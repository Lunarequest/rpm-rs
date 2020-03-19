use super::*;
use crate::crypto::KeyLoader;
use std::io::prelude::*;

fn test_rpm_file_path() -> std::path::PathBuf {
    let mut rpm_path = cargo_manifest_dir();
    rpm_path.push("test_assets/389-ds-base-devel-1.3.8.4-15.el7.x86_64.rpm");
    rpm_path
}

fn cargo_manifest_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[cfg(feature = "signing-pgp")]
use crypto::{Signing, Verifying, RSA};

// [type] 0x00
// [now] [0x_, 0x_, 0x_, 0x_]
// [pk algo] 0x01 // RSA enc or sign
// [hash algorithm] 0x08 // sha2_256
// [two uppermost bytes of hash] [0x_ 0x_] // 2 uppermost values of hash
//

#[cfg(feature = "signing-ring")]
mod ring {
    use super::*;
    use crypto::ring::{Signer, Verifier};

    #[test]
    fn create_full_rpm() -> Result<(), Box<dyn std::error::Error>> {
        let (signing_key, _) = crate::signature::test::load_der_keys();
        super::create_full_rpm::<Signer>(&signing_key)
    }

    #[test]
    fn verify_signed_rpm() -> Result<(), Box<dyn std::error::Error>> {
        let (_, verification_key) = crate::signature::test::load_der_keys();
        super::verify_signed_rpm::<Verifier>(&verification_key)
    }
}

#[cfg(feature = "signing-pgp")]
mod pgp {
    use super::*;
    use crypto::pgp::{Signer, Verifier};

    #[test]
    fn create_full_rpm() -> Result<(), Box<dyn std::error::Error>> {
        let (signing_key, _) = crate::signature::test::load_asc_keys();
        super::create_full_rpm::<Signer>(&signing_key)
    }

    #[test]
    fn verify_signed_rpm() -> Result<(), Box<dyn std::error::Error>> {
        let (_, verification_key) = crate::signature::test::load_asc_keys();
        super::verify_signed_rpm::<Verifier>(&verification_key)
    }
}

use std::io::BufReader;
use std::process::Stdio;

fn create_full_rpm<S>(gpg_signing_key: &[u8]) -> Result<(), Box<dyn std::error::Error>>
where
    S: Signing<RSA, Signature = Vec<u8>> + KeyLoader,
{
	let cargo_file = cargo_manifest_dir().join("Cargo.toml");
	let out_file = cargo_manifest_dir().join("out").join("test.rpm");

    let mut f = std::fs::File::create(out_file)?;
    let pkg = RPMBuilder::new("test", "1.0.0", "MIT", "x86_64", "some package")
        .compression(Compressor::from_str("gzip")?)
        .with_file(
            cargo_file.to_str().unwrap(),
            RPMFileOptions::new("/etc/foobar/foo.toml"),
        )?
        .with_file(
            cargo_file.to_str().unwrap(),
            RPMFileOptions::new("/etc/foobar/zazz.toml"),
        )?
        .with_file(
            cargo_file.to_str().unwrap(),
            RPMFileOptions::new("/etc/foobar/hugo/bazz.toml")
                .mode(0o100777)
                .is_config(),
        )?
        .with_file(
            cargo_file.to_str().unwrap(),
            RPMFileOptions::new("/etc/foobar/bazz.toml"),
        )?
        .with_file(
            cargo_file.to_str().unwrap(),
            RPMFileOptions::new("/etc/foobar/hugo/aa.toml"),
        )?
        .with_file(
            cargo_file.to_str().unwrap(),
            RPMFileOptions::new("/var/honollulu/bazz.toml"),
        )?
        .with_file(
            cargo_file.to_str().unwrap(),
            RPMFileOptions::new("/etc/Cargo.toml"),
        )?
        .epoch(1)
        .pre_install_script("echo preinst")
        .add_changelog_entry("me", "was awesome, eh?", 123123123)
        .add_changelog_entry("you", "yeah, it was", 12312312)
        // .requires(Dependency::any("wget".to_string()))
        .build_and_sign::<S>(gpg_signing_key)?;

    pkg.write(&mut f)?;
    let epoch = pkg.metadata.header.get_epoch()?;
    assert_eq!(1, epoch);

    let yum_cmd = "yum --disablerepo=* install -y /out/test.rpm";
    let dnf_cmd = "dnf --disablerepo=* install -y /out/test.rpm";
    let rpm_sig_check = format!("rpm --verbose --checksig /out/test.rpm 2>&1");

    [
        ("fedora:31", rpm_sig_check.as_str()),
        ("fedora:30", yum_cmd),
        ("fedora:31", dnf_cmd),
        ("centos:8", yum_cmd),
        ("centos:7", yum_cmd),
    ]
    .iter()
    .try_for_each(|(image, cmd)| {
        podman_container_launcher(cmd, image, vec![])?;
        Ok(())
    })
}

fn verify_signed_rpm<V>(verification_key: &[u8]) -> Result<(), Box<dyn std::error::Error>>
where
    V: Verifying<RSA, Signature = Vec<u8>> + KeyLoader,
{
	let rpm_file_path = test_rpm_file_path();
	let out_file = cargo_manifest_dir().join("out").join(rpm_file_path.file_name().unwrap().to_str().unwrap());

	std::fs::copy(rpm_file_path.as_path(), out_file.as_path()).expect("Must be able to copy");

    let cmd = format!(
        r#"
echo ">>> sign"
rpm --verbose --addsign /out/{rpm_file} 2>&1

echo ">>> verify"
rpm --verbose --checksig /out/{rpm_file} 2>&1
"#,
        rpm_file = rpm_file_path.file_name().unwrap().to_str().unwrap()
    );

    podman_container_launcher(cmd.as_str(), "fedora:31", vec![])?;

	let out_file = std::fs::File::open(&rpm_file_path).expect("should be able to open rpm file");
	let mut buf_reader = std::io::BufReader::new(out_file);
    let package = RPMPackage::parse(&mut buf_reader)?;
    package
        .verify_signature::<V>(verification_key.as_ref())
        .expect("Key should verify rpm");

    Ok(())
}

fn wait_and_print_helper(mut child: std::process::Child, stdin_cmd: &str) -> std::io::Result<()> {
    if let Some(ref mut stdin) = child.stdin {
        write!(stdin, "{}", stdin_cmd).unwrap();
    } else {
        unreachable!("Must have stdin");
    }
    // not perfect, but gets it done
    if let Some(ref mut stdout) = child.stdout {
        if let Some(ref mut stderr) = child.stderr {
            let stdout_rdr = BufReader::new(stdout);
            let mut stdout_line = stdout_rdr.lines();

            let stderr_rdr = BufReader::new(stderr);
            let mut stderr_line = stderr_rdr.lines();

            let mut done: bool = false;
            while !done {
                done = true;
                while let Some(line) = stdout_line.next() {
                    done = false;
                    println!("[stdout] {}", line.unwrap().as_str());
                }
                while let Some(line) = stderr_line.next() {
                    done = false;
                    println!("[stderr] {}", line.unwrap().as_str());
                }
            }
        } else {
            unreachable!("Must have stderr");
        }
    } else {
        unreachable!("Must have stdout");
    }

    let status = child.wait()?;
    assert!(status.success());
    Ok(())
}

fn podman_container_launcher(cmd: &str, image: &str, mut mappings: Vec<String>) -> std::io::Result<()> {

	// always mount assets and out directory into container
	let out = format!("{}:/out:z", cargo_manifest_dir().join("out").display());
	let assets = format!("{}/test_assets:/assets:z", cargo_manifest_dir().display());
	mappings.extend(vec![
		out,
		assets,
	]);
    let mut args = mappings
        .iter()
        .fold(vec!["run", "-i", "--rm"], |mut acc, mapping| {
            acc.extend(vec!["-v", mapping]);
            acc
        });
    args.extend(vec![image, "sh"]);

    let mut podman_cmd = std::process::Command::new("podman");

    podman_cmd.args(dbg!(args));
    podman_cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    podman_cmd.stdin(Stdio::piped());

    podman_cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    podman_cmd.stdin(Stdio::piped());


	// partially following:
	//
    //  https://access.redhat.com/articles/3359321
    let cmd = format!(
        r#"
set -e
set -x

### either

#cat > gpgkeyspec <<EOF
#     %echo Generating a basic OpenPGP key
#     Key-Type: RSA
#     Key-Length: 2048
#     Subkey-Type: RSA
#     Subkey-Length: 2048
#     Name-Real: Package Manager
#     Name-Comment: unprotected
#     Name-Email: pmanager@example.com
#     Expire-Date: 0
#     %no-ask-passphrase
#     %no-protection
#     %commit
#     %echo done
#EOF
#gpg --batch --generate-key gpgkeyspec

### or (which has a couple of advantages regarding reproducability)

gpg --import /assets/id_rsa.asc

###

gpg --list-keys

gpg --export -a 'Package Manager' > /assets/RPM-GPG-KEY-pmanager

cat /assets/RPM-GPG-KEY-pmanager
cat /assets/id_rsa.pub.asc

yum install -y rpm-sign || dnf install -y rpm-sign

rpm --import /assets/RPM-GPG-KEY-pmanager 2>&1
rpm --import /assets/id_rsa.pub.asc 2>&1

cat > ~/.rpmmacros << EOF_Y
%_signature gpg
%_gpg_path /root/.gnupg
%_gpg_name Package Manager
%_gpgbin /usr/bin/gpg2
%__gpg_sign_cmd %{{__gpg}} gpg --batch --verbose --no-armor --passphrase-fd /dev/null --no-secmem-warning -u "%{{_gpg_name}}" -sbo %{{__signature_filename}} --digest-algo sha256 %{{__plaintext_filename}}'
EOF_Y

{}

exit 0
"#,
        cmd
    );

	// this is far from perfect, but at least pumps
	// stdio and stderr out
    wait_and_print_helper(podman_cmd.spawn()?, cmd.as_str())
}
