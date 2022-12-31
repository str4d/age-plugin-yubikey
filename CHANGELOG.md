# Changelog
All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). All versions prior
to 0.3.0 are beta releases.

## [Unreleased]
### Changed
- The "sharing violation" logic now also sends SIGHUP to any `yubikey-agent`
  that is running, to have them release any YubiKey locks they are holding.

## [0.3.1] - 2022-12-30
### Changed
- If a "sharing violation" error is encountered while opening a connection to a
  YubiKey, and `scdaemon` is running (which can hold exclusive access to a
  YubiKey indefinitely), `age-plugin-yubikey` now attempts to stop `scdaemon` by
  interrupting it (or killing it on Windows), and then tries again to open the
  connection.
- Several error messages were enhanced with guidance on how to resolve their
  respective issue.

## [0.3.0] - 2022-05-02
First non-beta release!

### Changed
- MSRV is now 1.56.0.
- During decryption, when asked to insert a YubiKey, you can now choose to skip
  it, allowing the client to move on to the next identity instead of returning
  an error.
- Certain kinds of PIN invalidity will now cause the plugin to re-request the
  PIN instead of aborting: if the PIN is too short or too long, or if the user
  touched the YubiKey early and "typed" an OTP.

### Fixed
- The "default" identity (provided by clients that invoke `age-plugin-yubikey`
  using `-j yubikey`) previously caused a panic. It is now correctly treated as
  an invalid identity (because this plugin does not support default identities).

## [0.2.0] - 2021-11-22
### Fixed
- Attempts-before-blocked counter is now returned as part of the invalid PIN
  error string.
- PIN is no longer requested when fetching the recipient for a slot, or when
  decrypting with a slot that has a PIN policy of Never.
- Migrated to `yubikey 0.5` to fix `cargo install age-plugin-yubikey` error
  (caused by the `yubikey-piv` crate being yanked after it was renamed).

## [0.1.0] - 2021-05-02

Initial beta release.
