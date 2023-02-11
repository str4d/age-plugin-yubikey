use std::env;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

const PLUGIN_BIN: &str = env!("CARGO_BIN_EXE_age-plugin-yubikey");

#[test_with::env(YUBIKEY_SERIAL, YUBIKEY_SLOT)]
#[cfg_attr(all(unix, not(target_os = "macos")), test_with::executable(pcscd))]
#[test]
fn recipient_and_identity_match() {
    let recipient = Command::new(PLUGIN_BIN)
        .arg("--list")
        .arg("--serial")
        .arg(env::var("YUBIKEY_SERIAL").unwrap())
        .arg("--slot")
        .arg(env::var("YUBIKEY_SLOT").unwrap())
        .output()
        .unwrap();
    assert_eq!(recipient.status.code(), Some(0));

    let identity = Command::new(PLUGIN_BIN)
        .arg("--identity")
        .arg("--serial")
        .arg(env::var("YUBIKEY_SERIAL").unwrap())
        .arg("--slot")
        .arg(env::var("YUBIKEY_SLOT").unwrap())
        .output()
        .unwrap();
    assert_eq!(identity.status.code(), Some(0));

    let recipient_file = String::from_utf8_lossy(&recipient.stdout);
    let recipient = recipient_file.lines().last().unwrap();
    let identity = String::from_utf8_lossy(&identity.stdout);
    assert!(identity.contains(recipient));
}

#[test_with::executable(rage)]
#[test]
fn plugin_encrypt() {
    let enc_file = tempfile::NamedTempFile::new_in(env!("CARGO_TARGET_TMPDIR")).unwrap();

    let mut process = Command::new(which::which("rage").unwrap())
        .arg("-r")
        .arg("age1yubikey1q2w7u3vpya839jxxuq8g0sedh3d740d4xvn639sqhr95ejj8vu3hyfumptt")
        .arg("-o")
        .arg(enc_file.path())
        .stdin(Stdio::piped())
        .env("PATH", Path::new(PLUGIN_BIN).parent().unwrap())
        .spawn()
        .unwrap();

    // Scope to ensure stdin is closed.
    {
        let mut stdin = process.stdin.take().unwrap();
        stdin.write_all(b"Testing YubiKey encryption").unwrap();
        stdin.flush().unwrap();
    }

    let status = process.wait().unwrap();
    assert_eq!(status.code(), Some(0));
}

#[test_with::env(YUBIKEY_SERIAL, YUBIKEY_SLOT)]
#[test_with::executable(rage)]
#[cfg_attr(all(unix, not(target_os = "macos")), test_with::executable(pcscd))]
#[test]
fn plugin_decrypt() {
    let mut identity_file = tempfile::NamedTempFile::new_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let enc_file = tempfile::NamedTempFile::new_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let plaintext = "Testing YubiKey encryption";

    // Write an identity file corresponding to this YubiKey slot.
    let identity = Command::new(PLUGIN_BIN)
        .arg("--identity")
        .arg("--serial")
        .arg(env::var("YUBIKEY_SERIAL").unwrap())
        .arg("--slot")
        .arg(env::var("YUBIKEY_SLOT").unwrap())
        .output()
        .unwrap();
    assert_eq!(identity.status.code(), Some(0));
    identity_file.write_all(&identity.stdout).unwrap();
    identity_file.flush().unwrap();

    // Encrypt to the YubiKey slot.
    let mut enc_process = Command::new(which::which("rage").unwrap())
        .arg("-e")
        .arg("-i")
        .arg(identity_file.path())
        .arg("-o")
        .arg(enc_file.path())
        .stdin(Stdio::piped())
        .env("PATH", Path::new(PLUGIN_BIN).parent().unwrap())
        .spawn()
        .unwrap();

    // Scope to ensure stdin is closed.
    {
        let mut stdin = enc_process.stdin.take().unwrap();
        stdin.write_all(plaintext.as_bytes()).unwrap();
        stdin.flush().unwrap();
    }

    let enc_status = enc_process.wait().unwrap();
    assert_eq!(enc_status.code(), Some(0));

    // Decrypt with the YubiKey.
    let dec_process = Command::new(which::which("rage").unwrap())
        .arg("-d")
        .arg("-i")
        .arg(identity_file.path())
        .arg(enc_file.path())
        .stdin(Stdio::piped())
        .env("PATH", Path::new(PLUGIN_BIN).parent().unwrap())
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&dec_process.stderr);
    if !stderr.is_empty() {
        assert!(stderr.contains("age-plugin-yubikey"));
        assert!(stderr.ends_with("...\n"));
    }
    assert_eq!(String::from_utf8_lossy(&dec_process.stdout), plaintext);
}
