use std::env;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

const PLUGIN_BIN: &str = env!("CARGO_BIN_EXE_age-plugin-yubikey");

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
