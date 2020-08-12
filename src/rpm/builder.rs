use sha2::Digest;
use std::collections::{BTreeMap, BTreeSet};

use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use std::time::UNIX_EPOCH;
use std::path::{Path, PathBuf};

use crate::errors::*;
use crate::sequential_cursor::SeqCursor;

use super::compressor::Compressor;
use super::headers::*;
use super::Lead;
use crate::constants::*;

#[cfg(feature = "signature-meta")]
use crate::signature;

use crate::RPMPackage;
use crate::RPMPackageMetadata;

/// Builder pattern for a full rpm file.
///
/// Prefered method of creating a rpm file.
pub struct RPMBuilder {
    name: String,
    epoch: i32,
    version: String,
    license: String,
    arch: String,
    uid: Option<u32>,
    gid: Option<u32>,
    desc: String,
    release: String,

    // File entries need to be sorted. The entries need to be in the same order as they come
    // in the cpio payload. Otherwise rpm will not be able to resolve those paths.
    // key is the directory, values are complete paths
    files: BTreeMap<String, RPMFileEntry>,
    directories: BTreeSet<String>,

    policies: Vec<RPMPolicy>,

    requires: Vec<Dependency>,
    obsoletes: Vec<Dependency>,
    provides: Vec<Dependency>,
    conflicts: Vec<Dependency>,

    pre_inst_script: Option<String>,
    post_inst_script: Option<String>,
    pre_uninst_script: Option<String>,
    post_uninst_script: Option<String>,

    changelog_authors: Vec<String>,
    changelog_entries: Vec<String>,
    changelog_times: Vec<i32>,
    compressor: Compressor,
}

impl RPMBuilder {
    pub fn new(name: &str, version: &str, license: &str, arch: &str, desc: &str) -> Self {
        RPMBuilder {
            name: name.to_string(),
            epoch: 0,
            version: version.to_string(),
            license: license.to_string(),
            arch: arch.to_string(),
            desc: desc.to_string(),
            release: "1".to_string(),
            uid: None,
            gid: None,
            conflicts: Vec::new(),
            provides: Vec::new(),
            obsoletes: Vec::new(),
            requires: Vec::new(),
            pre_inst_script: None,
            post_inst_script: None,
            pre_uninst_script: None,
            post_uninst_script: None,
            files: BTreeMap::new(),
            changelog_authors: Vec::new(),
            changelog_entries: Vec::new(),
            changelog_times: Vec::new(),
            compressor: Compressor::None(Vec::new()),
            directories: BTreeSet::new(),
            policies: Vec::new(),
        }
    }

    pub fn epoch(mut self, epoch: i32) -> Self {
        self.epoch = epoch;
        self
    }

    pub fn compression(mut self, comp: Compressor) -> Self {
        self.compressor = comp;
        self
    }

    pub fn add_changelog_entry<E, F>(mut self, author: E, entry: F, time: i32) -> Self
    where
        E: Into<String>,
        F: Into<String>,
    {
        self.changelog_authors.push(author.into());
        self.changelog_entries.push(entry.into());
        self.changelog_times.push(time);
        self
    }

    pub fn with_file<T, P>(
        mut self,
        source: P,
        options: T,
    ) -> Result<Self, RPMError>
    where
        P: AsRef<Path>,
        T: Into<RPMFileOptions>,
    {
        let mut input = std::fs::File::open(source)?;
        let mut content = Vec::new();
        input.read_to_end(&mut content)?;
        let mut options = options.into();
        if options.inherit_permissions && cfg!(unix) {
            options.mode = input.metadata()?.permissions().mode() as i32;
        }
        self.add_data(
            content,
            input
                .metadata()?
                .modified()?
                .duration_since(UNIX_EPOCH)
                .expect("something really wrong with your time")
                .as_secs() as i32,
            options,
        )?;
        Ok(self)
    }

    fn add_data(
        &mut self,
        content: Vec<u8>,
        modified_at: i32,
        options: RPMFileOptions,
    ) -> Result<(), RPMError> {
        let dest = options.destination;
        if !dest.starts_with("./") && !dest.starts_with('/') {
            return Err(RPMError::new(&format!(
                "invalid path {} - needs to start with / or ./",
                dest
            )));
        }

        let pb = PathBuf::from(dest.clone());

        let parent = pb
            .parent()
            .ok_or_else(|| RPMError::new(&format!("invalid destination path {}", dest)))?;
        let (cpio_path, dir) = if dest.starts_with('.') {
            (
                dest.to_string(),
                format!("/{}/", parent.strip_prefix(".").unwrap().to_string_lossy()),
            )
        } else {
            (
                format!(".{}", dest),
                format!("{}/", parent.to_string_lossy()),
            )
        };

        let mut hasher = sha2::Sha256::default();
        hasher.update(&content);
        let hash_result = hasher.finalize();
        let sha_checksum = format!("{:x}", hash_result);
        let entry = RPMFileEntry {
            base_name: pb.file_name().unwrap().to_string_lossy().to_string(),
            size: content.len() as i32,
            content: Some(content),
            flag: options.flag,
            user: options.user,
            group: options.group,
            mode: options.mode as i16,
            link: options.symlink,
            modified_at,
            dir: dir.clone(),
            sha_checksum,
        };

        self.directories.insert(dir);
        self.files.entry(cpio_path).or_insert(entry);
        Ok(())
    }

    pub fn pre_install_script<T: Into<String>>(mut self, content: T) -> Self {
        self.pre_inst_script = Some(content.into());
        self
    }

    pub fn post_install_script<T: Into<String>>(mut self, content: T) -> Self {
        self.post_inst_script = Some(content.into());
        self
    }

    pub fn pre_uninstall_script<T: Into<String>>(mut self, content: T) -> Self {
        self.pre_uninst_script = Some(content.into());
        self
    }

    pub fn post_uninstall_script<T: Into<String>>(mut self, content: T) -> Self {
        self.post_uninst_script = Some(content.into());
        self
    }

    pub fn release(mut self, release: u16) -> Self {
        self.release = format!("{}", release);
        self
    }

    pub fn requires(mut self, dep: Dependency) -> Self {
        self.requires.push(dep);
        self
    }

    pub fn obsoletes(mut self, dep: Dependency) -> Self {
        self.obsoletes.push(dep);
        self
    }

    pub fn conflicts(mut self, dep: Dependency) -> Self {
        self.conflicts.push(dep);
        self
    }

    pub fn provides(mut self, dep: Dependency) -> Self {
        self.provides.push(dep);
        self
    }

    /// Include a SELinux policy file.
    ///
    /// Will not create a header entry, but rather
    pub fn with_policy_file<P: AsRef<Path>>(
        self,
        source: P,
        types: Vec<String>,
        flags: RPMPolicyFlags,
    ) -> Result<Self, RPMError> {
        let source = source.as_ref();
        let mut input = std::fs::File::open(source)?;
        let mut content = Vec::new();
        input.read_to_end(&mut content)?;
        let content = String::from_utf8(content).map_err(|e| RPMError::from(
            format!("Content is not valid utf-8: {}", e),
        ))?;

        let name = source.file_stem().map(std::ffi::OsStr::to_str).flatten()
            .ok_or_else(|| RPMError::new(
                "Failed to obtain file stem of policy file",
            ))?;

        self.with_policy(name.to_owned(), content, types, flags)
    }

    pub fn with_policy(
        mut self,
        name: String,
        content: String,
        types: Vec<String>,
        flags: RPMPolicyFlags,
    ) -> Result<Self, RPMError> {

        let policy = RPMPolicy {
            flags,
            content,
            name: name.clone(),
            types,
        };

        self.policies.push(policy);

        Ok(self)
    }

    /// build without a signature
    ///
    /// ignores a present key, if any
    pub fn build(self) -> Result<RPMPackage, RPMError> {
        let (lead, header_idx_tag, content) = self.prepare_data()?;

        let mut header = Vec::with_capacity(128);
        header_idx_tag.write(&mut header)?;
        let header = header;

        let (header_digest_sha1, header_and_content_digest_md5) =
            Self::derive_hashes(header.as_slice(), content.as_slice())?;

        let header_and_content_len = header.len() + content.len();

        let digest_header = Header::<IndexSignatureTag>::builder()
            .add_digest(
                header_digest_sha1.as_str(),
                header_and_content_digest_md5.as_slice(),
            )
            .build(header_and_content_len as i32);

        let metadata = RPMPackageMetadata {
            lead,
            signature: digest_header,
            header: header_idx_tag,
        };
        let pkg = RPMPackage { metadata, content };
        Ok(pkg)
    }

    /// use an external signer to sing and build
    ///
    /// See `signature::Signing` for more details.
    #[cfg(feature = "signature-meta")]
    pub fn build_and_sign<S>(self, signer: S) -> Result<RPMPackage, RPMError>
    where
        S: signature::Signing<crate::signature::algorithm::RSA>,
    {
        let (lead, header_idx_tag, content) = self.prepare_data()?;

        let mut header = Vec::with_capacity(128);
        header_idx_tag.write(&mut header)?;
        let header = header;

        let (header_digest_sha1, header_and_content_digest_md5) =
            Self::derive_hashes(header.as_slice(), content.as_slice())?;

        let header_and_content_len = header.len() + content.len();

        let builder = Header::<IndexSignatureTag>::builder().add_digest(
            header_digest_sha1.as_str(),
            header_and_content_digest_md5.as_slice(),
        );

        let signature_header = {
            let rsa_sig_header_only = signer
                .sign(header.as_slice())
                .map_err(|_e| RPMError::new("Failed to create signature for headers"))?;

            let cursor = SeqCursor::new(&[header.as_slice(), content.as_slice()]);
            let rsa_sig_header_and_archive = signer.sign(cursor).map_err(|_e| {
                RPMError::new("Failed to create signature based for headers and content")
            })?;

            builder
                .add_signature(
                    rsa_sig_header_only.as_ref(),
                    rsa_sig_header_and_archive.as_ref(),
                )
                .build(header_and_content_len as i32)
        };

        let metadata = RPMPackageMetadata {
            lead,
            signature: signature_header,
            header: header_idx_tag,
        };
        let pkg = RPMPackage { metadata, content };
        Ok(pkg)
    }

    /// use prepared data but make sure the signatures are
    fn derive_hashes(header: &[u8], content: &[u8]) -> Result<(String, Vec<u8>), RPMError> {
        // accross header index and content (compressed or uncompressed, depends on configuration)
        let mut hasher = md5::Md5::default();
        hasher.update(&header);
        hasher.update(&content);
        let digest_md5 = hasher.finalize();
        let digest_md5 = digest_md5.as_slice();

        // header only, not the lead, just the header index
        let digest_sha1 = sha1::Sha1::from(&header);
        let digest_sha1 = digest_sha1.digest();
        let digest_sha1 = digest_sha1.to_string();

        Ok((digest_sha1, digest_md5.to_vec()))
    }

    /// prepapre all rpm headers including content
    ///
    /// @todo split this into multiple `fn`s, one per `IndexTag`-group.
    fn prepare_data(mut self) -> Result<(Lead, Header<IndexTag>, Vec<u8>), RPMError> {
        // signature depends on header and payload. So we build these two first.
        // then the signature. Then we stitch all toghether.
        // Lead is not important. just build it here

        let lead = Lead::new(&self.name);

        let mut ino_index = 1;

        let mut file_sizes = Vec::new();
        let mut file_modes = Vec::new();
        let mut file_rdevs = Vec::new();
        let mut file_mtimes = Vec::new();
        let mut file_hashes = Vec::new();
        let mut file_linktos = Vec::new();
        let mut file_flags = Vec::new();
        let mut file_usernames = Vec::new();
        let mut file_groupnames = Vec::new();
        let mut file_devices = Vec::new();
        let mut file_inodes = Vec::new();
        let mut file_langs = Vec::new();
        let mut file_verify_flags = Vec::new();
        let mut dir_indixes = Vec::new();
        let mut base_names = Vec::new();

        let mut combined_file_sizes = 0;

        for (cpio_path, entry) in self.files.iter() {
            combined_file_sizes += entry.size;
            file_sizes.push(entry.size);
            file_modes.push(entry.mode);
            // I really do not know the difference. It seems like file_rdevice is always 0 and file_device number always 1.
            // Who knows, who cares.
            file_rdevs.push(0);
            file_devices.push(1);
            file_mtimes.push(entry.modified_at);
            file_hashes.push(entry.sha_checksum.to_owned());
            file_linktos.push(entry.link.to_owned());
            file_flags.push(entry.flag);
            file_usernames.push(entry.user.to_owned());
            file_groupnames.push(entry.group.to_owned());
            file_inodes.push(ino_index as i32);
            file_langs.push("".to_string());
            let index = self
                .directories
                .iter()
                .position(|d| d == &entry.dir)
                .unwrap();
            dir_indixes.push(index as i32);
            base_names.push(entry.base_name.to_owned());
            file_verify_flags.push(-1);
            let content = entry.content.to_owned().unwrap();
            let mut writer = cpio::newc::Builder::new(&cpio_path)
                .mode(entry.mode as u32)
                .ino(ino_index as u32)
                .uid(self.uid.unwrap_or(0))
                .gid(self.gid.unwrap_or(0))
                .write(&mut self.compressor, content.len() as u32);

            writer.write_all(&content)?;
            writer.finish()?;

            ino_index += 1;
        }

        self.requires.push(Dependency::any("/bin/sh".to_string()));

        self.provides
            .push(Dependency::eq(self.name.clone(), self.version.clone()));
        self.provides.push(Dependency::eq(
            format!("{}({})", self.name.clone(), self.arch.clone()),
            self.version.clone(),
        ));

        let mut provide_names = Vec::new();
        let mut provide_flags = Vec::new();
        let mut provide_versions = Vec::new();

        for d in self.provides.into_iter() {
            provide_names.push(d.dep_name);
            provide_flags.push(d.sense as i32);
            provide_versions.push(d.version);
        }

        let mut obsolete_names = Vec::new();
        let mut obsolete_flags = Vec::new();
        let mut obsolete_versions = Vec::new();

        for d in self.obsoletes.into_iter() {
            obsolete_names.push(d.dep_name);
            obsolete_flags.push(d.sense as i32);
            obsolete_versions.push(d.version);
        }

        let mut require_names = Vec::new();
        let mut require_flags = Vec::new();
        let mut require_versions = Vec::new();

        for d in self.requires.into_iter() {
            require_names.push(d.dep_name);
            require_flags.push(d.sense as i32);
            require_versions.push(d.version);
        }

        let mut conflicts_names = Vec::new();
        let mut conflicts_flags = Vec::new();
        let mut conflicts_versions = Vec::new();

        for d in self.conflicts.into_iter() {
            conflicts_names.push(d.dep_name);
            conflicts_flags.push(d.sense as i32);
            conflicts_versions.push(d.version);
        }

        let capa = self.policies.len();
        let mut policies = Vec::with_capacity(capa);
        let mut policy_names = Vec::with_capacity(capa);
        let mut policy_types = Vec::with_capacity(capa);
        let mut policy_typesindices = Vec::with_capacity(capa << 1);
        let mut policy_flags = Vec::with_capacity(capa);
        // Mapping is implicit by the index in the vector
        // see https://github.com/Richterrettich/rpm-rs/issues/18 for further details.
        for (idx, policy) in self.policies.into_iter().enumerate() {
            // direct mapping per index
            policies.push(base64::encode(policy.content.as_bytes()));
            policy_names.push(policy.name);
            policy_flags.push(policy.flags as i32);

            // indirect 1:N mapping
            policy_typesindices.extend(std::iter::repeat(idx as i32).take(policy.types.len()));
            policy_types.extend(policy.types);
        }

        let offset = 0;
        let mut actual_records = vec![
            IndexEntry::new(
                IndexTag::RPMTAG_HEADERI18NTABLE,
                offset,
                IndexData::StringTag("C".to_string()),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_NAME,
                offset,
                IndexData::StringTag(self.name),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_EPOCH,
                offset,
                IndexData::Int32(vec![self.epoch]),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_VERSION,
                offset,
                IndexData::StringTag(self.version),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_RELEASE,
                offset,
                IndexData::StringTag(self.release),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_DESCRIPTION,
                offset,
                IndexData::StringTag(self.desc.clone()),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_SUMMARY,
                offset,
                IndexData::StringTag(self.desc),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_SIZE,
                offset,
                IndexData::Int32(vec![combined_file_sizes]),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_LICENSE,
                offset,
                IndexData::StringTag(self.license),
            ),
            // https://fedoraproject.org/wiki/RPMGroups
            // IndexEntry::new(IndexTag::RPMTAG_GROUP, offset, IndexData::I18NString(group)),
            IndexEntry::new(
                IndexTag::RPMTAG_OS,
                offset,
                IndexData::StringTag("linux".to_string()),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_GROUP,
                offset,
                IndexData::I18NString(vec!["Unspecified".to_string()]),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_ARCH,
                offset,
                IndexData::StringTag(self.arch),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_PAYLOADFORMAT,
                offset,
                IndexData::StringTag("cpio".to_string()),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_FILESIZES,
                offset,
                IndexData::Int32(file_sizes),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_FILEMODES,
                offset,
                IndexData::Int16(file_modes),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_FILERDEVS,
                offset,
                IndexData::Int16(file_rdevs),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_FILEMTIMES,
                offset,
                IndexData::Int32(file_mtimes),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_FILEDIGESTS,
                offset,
                IndexData::StringArray(file_hashes),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_FILELINKTOS,
                offset,
                IndexData::StringArray(file_linktos),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_FILEFLAGS,
                offset,
                IndexData::Int32(file_flags),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_FILEUSERNAME,
                offset,
                IndexData::StringArray(file_usernames),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_FILEGROUPNAME,
                offset,
                IndexData::StringArray(file_groupnames),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_FILEDEVICES,
                offset,
                IndexData::Int32(file_devices),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_FILEINODES,
                offset,
                IndexData::Int32(file_inodes),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_DIRINDEXES,
                offset,
                IndexData::Int32(dir_indixes),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_FILELANGS,
                offset,
                IndexData::StringArray(file_langs),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_FILEDIGESTALGO,
                offset,
                IndexData::Int32(vec![8]),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_FILEVERIFYFLAGS,
                offset,
                IndexData::Int32(file_verify_flags),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_BASENAMES,
                offset,
                IndexData::StringArray(base_names),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_DIRNAMES,
                offset,
                IndexData::StringArray(self.directories.into_iter().collect()),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_PROVIDENAME,
                offset,
                IndexData::StringArray(provide_names),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_PROVIDEVERSION,
                offset,
                IndexData::StringArray(provide_versions),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_PROVIDEFLAGS,
                offset,
                IndexData::Int32(provide_flags),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_POLICIES,
                offset,
                IndexData::StringArray(policies)
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_POLICYNAMES,
                offset,
                IndexData::StringArray(policy_names)
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_POLICYFLAGS,
                offset,
                IndexData::Int32(policy_flags)
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_POLICYTYPES,
                offset,
                IndexData::StringArray(policy_types)
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_POLICYTYPESINDEXES,
                offset,
                IndexData::Int32(policy_typesindices)
            ),
        ];

        let possible_compression_details = self.compressor.get_details();

        if let Some(details) = possible_compression_details {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_PAYLOADCOMPRESSOR,
                offset,
                IndexData::StringTag(details.compression_name.to_string()),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_PAYLOADFLAGS,
                offset,
                IndexData::StringTag(details.compression_level.to_string()),
            ));
        }

        if !self.changelog_authors.is_empty() {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_CHANGELOGNAME,
                offset,
                IndexData::StringArray(self.changelog_authors),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_CHANGELOGTEXT,
                offset,
                IndexData::StringArray(self.changelog_entries),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_CHANGELOGTIME,
                offset,
                IndexData::Int32(self.changelog_times),
            ));
        }

        if !obsolete_flags.is_empty() {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_OBSOLETENAME,
                offset,
                IndexData::StringArray(obsolete_names),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_OBSOLETEVERSION,
                offset,
                IndexData::StringArray(obsolete_versions),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_OBSOLETEFLAGS,
                offset,
                IndexData::Int32(obsolete_flags),
            ));
        }

        if !require_flags.is_empty() {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_REQUIRENAME,
                offset,
                IndexData::StringArray(require_names),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_REQUIREVERSION,
                offset,
                IndexData::StringArray(require_versions),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_REQUIREFLAGS,
                offset,
                IndexData::Int32(require_flags),
            ));
        }

        if !conflicts_flags.is_empty() {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_CONFLICTNAME,
                offset,
                IndexData::StringArray(conflicts_names),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_CONFLICTVERSION,
                offset,
                IndexData::StringArray(conflicts_versions),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_CONFLICTFLAGS,
                offset,
                IndexData::Int32(conflicts_flags),
            ));
        }

        if self.pre_inst_script.is_some() {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_PREIN,
                offset,
                IndexData::StringTag(self.pre_inst_script.unwrap()),
            ));
        }
        if self.post_inst_script.is_some() {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_POSTIN,
                offset,
                IndexData::StringTag(self.post_inst_script.unwrap()),
            ));
        }

        if self.pre_uninst_script.is_some() {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_PREUN,
                offset,
                IndexData::StringTag(self.pre_uninst_script.unwrap()),
            ));
        }

        if self.post_uninst_script.is_some() {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_POSTUN,
                offset,
                IndexData::StringTag(self.post_uninst_script.unwrap()),
            ));
        }

        let header = Header::from_entries(actual_records, IndexTag::RPMTAG_HEADERIMMUTABLE);

        //those parts seem to break on fedora installations, but it does not seem to matter for centos.
        // if it turns out that those parts are not really required, we will delete the following comments

        // self.requires.push(Dependency::rpm_lib(
        //     "rpmlib(VersionedDependencies)".to_string(),
        //     "3.0.3-1".to_string(),
        // ));

        // self.requires.push(Dependency::rpm_lib(
        //     "rpmlib(PayloadFilesHavePrefix)".to_string(),
        //     "4.0-1".to_string(),
        // ));

        // self.requires.push(Dependency::rpm_lib(
        //     "rpmlib(CompressedFileNames)".to_string(),
        //     "3.0.4-1".to_string(),
        // ));

        // self.requires.push(Dependency::rpm_lib(
        //     "rpmlib(PayloadIsXz)".to_string(),
        //     "5.2-1".to_string(),
        // ));
        // self.requires.push(Dependency::rpm_lib(
        //     "rpmlib(FileDigests)".to_string(),
        //     "4.6.0-1".to_string(),
        // ));

        self.compressor = cpio::newc::trailer(self.compressor)?;
        let content = self.compressor.finish_compression()?;

        Ok((lead, header, content))
    }
}
