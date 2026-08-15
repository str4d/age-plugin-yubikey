//! Structs for handling YubiKeys.

use age_core::primitives::bech32_encode;
use age_core::secrecy::{ExposeSecret, SecretString};
use age_plugin::{identity, Callbacks};
use dialoguer::Password;
use log::{debug, error, warn};
use std::convert::Infallible;
use std::env;
use std::fmt;
use std::io::{self, Read, Write};
use std::iter;
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime};
use x509_parser::der_parser::oid::Oid;
use yubikey::{
    certificate::Certificate,
    piv::{decrypt_data, metadata as piv_metadata, AlgorithmId, RetiredSlotId, SlotId},
    reader::{Context, Reader},
    MgmKey, ObjectId, PinPolicy, Serial, TouchPolicy, YubiKey,
};

use crate::{
    error::Error,
    fl,
    native::p256tag,
    recipient::TAG_BYTES,
    util::{otp_serial_prefix, Metadata, POLICY_EXTENSION_OID},
    Recipient, IDENTITY_PREFIX, USABLE_SLOTS,
};

const ONE_SECOND: Duration = Duration::from_secs(1);
const FIFTEEN_SECONDS: Duration = Duration::from_secs(15);

/// The set of OIDs that we understand and use when parsing YubiKey slot certificates.
const KNOWN_OIDS: &[&[u64]] = &[POLICY_EXTENSION_OID];

pub(crate) fn is_connected(reader: Reader) -> bool {
    filter_connected(&reader)
}

pub(crate) fn filter_connected(reader: &Reader) -> bool {
    match reader.open() {
        Err(yubikey::Error::PcscError {
            inner: Some(pcsc::Error::NoSmartcard | pcsc::Error::RemovedCard),
        }) => {
            warn!(
                "{}",
                fl!("warn-yk-not-connected", yubikey_name = reader.name())
            );
            false
        }
        Err(yubikey::Error::AppletNotFound { applet_name }) => {
            warn!(
                "{}",
                fl!(
                    "warn-yk-missing-applet",
                    yubikey_name = reader.name(),
                    applet_name = applet_name,
                ),
            );
            false
        }
        Err(_) => true,
        Ok(yubikey) => {
            // We only connected as a side-effect of confirming that we can connect, so
            // avoid resetting the YubiKey.
            disconnect_without_reset(yubikey);
            true
        }
    }
}

pub(crate) fn wait_for_readers() -> Result<Context, Error> {
    // Start a 15-second timer waiting for a YubiKey to be inserted (if necessary).
    let start = SystemTime::now();
    loop {
        let mut readers = Context::open()?;
        if readers.iter()?.any(is_connected) {
            break Ok(readers);
        }

        match SystemTime::now().duration_since(start) {
            Ok(end) if end >= FIFTEEN_SECONDS => return Err(Error::TimedOut),
            _ => sleep(ONE_SECOND),
        }
    }
}

/// Looks for agent processes that might be holding exclusive access to a YubiKey, and
/// asks them as nicely as possible to release it.
///
/// Returns `true` if any known agent was running and was successfully interrupted (or
/// killed if the platform doesn't support interrupts).
fn hunt_agents() -> bool {
    debug!("Sharing violation encountered, looking for agent processes");

    use sysinfo::{ProcessExt, ProcessRefreshKind, RefreshKind, Signal, System, SystemExt};

    let mut interrupted = false;

    let sys =
        System::new_with_specifics(RefreshKind::new().with_processes(ProcessRefreshKind::new()));

    for process in sys.processes().values() {
        match process.name() {
            "scdaemon" | "scdaemon.exe" => {
                // gpg-agent runs scdaemon to interact with smart cards. The canonical way
                // to reload it is `gpgconf --reload scdaemon`, which kills and restarts
                // the process. We emulate that here with SIGINT (which it listens to).
                if process
                    .kill_with(Signal::Interrupt)
                    .unwrap_or_else(|| process.kill())
                {
                    debug!("Stopped scdaemon (PID {})", process.pid());
                    interrupted = true;
                }
            }
            "yubikey-agent" | "yubikey-agent.exe" => {
                // yubikey-agent releases all YubiKey locks when it receives a SIGHUP.
                match process.kill_with(Signal::Hangup) {
                    Some(true) => {
                        debug!("Sent SIGHUP to yubikey-agent (PID {})", process.pid());
                        interrupted = true;
                    }
                    Some(false) => (),
                    None => debug!(
                        "Found yubikey-agent (PID {}) but platform doesn't support SIGHUP",
                        process.pid(),
                    ),
                }
            }
            _ => (),
        }
    }

    // If we did interrupt an agent, pause briefly to allow it to finish up.
    if interrupted {
        sleep(Duration::from_millis(100));
    }

    interrupted
}

fn open_sesame(
    op: impl Fn() -> Result<YubiKey, yubikey::Error>,
) -> Result<YubiKey, yubikey::Error> {
    op().or_else(|e| match e {
        yubikey::Error::PcscError {
            inner: Some(pcsc::Error::SharingViolation),
        } if hunt_agents() => op(),
        _ => Err(e),
    })
}

/// Opens a connection to this reader, returning a `YubiKey` if successful.
///
/// This is equivalent to [`Reader::open`], but additionally handles the presence of
/// agents (which can indefinitely hold exclusive access to a YubiKey).
pub(crate) fn open_connection(reader: &Reader) -> Result<YubiKey, yubikey::Error> {
    open_sesame(|| reader.open())
}

/// Opens a YubiKey with a specific serial number.
///
/// This is equivalent to [`YubiKey::open_by_serial`], but additionally handles the
/// presence of agents (which can indefinitely hold exclusive access to a YubiKey).
fn open_by_serial(serial: Serial) -> Result<YubiKey, yubikey::Error> {
    // `YubiKey::open_by_serial` has a bug where it ignores all opening errors, even if
    // it potentially could have found a matching YubiKey if not for an error, and thus
    // returns `Error::NotFound` if another agent is holding exclusive access to the
    // required YubiKey. This gives misleading UX behaviour where age-plugin-yubikey asks
    // the user to insert a YubiKey they have already inserted.
    //
    // For now, we instead implement the correct behaviour manually. Once MSRV has been
    // raised to 1.60, we can upstream this into the `yubikey` crate.
    open_sesame(|| {
        let mut readers = Context::open()?;

        let mut open_error = None;

        for reader in readers.iter()? {
            let yubikey = match reader.open() {
                Ok(yk) => yk,
                Err(e) => {
                    // Save the first error we see that indicates we might have been able
                    // to find a matching YubiKey.
                    if open_error.is_none() {
                        if let yubikey::Error::PcscError {
                            inner: Some(pcsc::Error::SharingViolation),
                        } = e
                        {
                            open_error = Some(e);
                        }
                    }
                    continue;
                }
            };

            if serial == yubikey.serial() {
                return Ok(yubikey);
            } else {
                // We didn't want this YubiKey; don't reset it.
                disconnect_without_reset(yubikey);
            }
        }

        Err(if let Some(e) = open_error {
            e
        } else {
            error!("no YubiKey detected with serial: {}", serial);
            yubikey::Error::NotFound
        })
    })
}

pub(crate) fn open(serial: Option<Serial>) -> Result<YubiKey, Error> {
    if !Context::open()?.iter()?.any(is_connected) {
        if let Some(serial) = serial {
            eprintln!(
                "{}",
                fl!("open-yk-with-serial", yubikey_serial = serial.to_string())
            );
        } else {
            eprintln!("{}", fl!("open-yk-without-serial"));
        }
    }
    let mut readers = wait_for_readers()?;
    let mut readers_iter = readers.iter()?.filter(filter_connected);

    // --serial selects the YubiKey to use. If not provided, and more than one YubiKey is
    // connected, an error is returned.
    let yubikey = match (readers_iter.next(), readers_iter.next(), serial) {
        (None, _, _) => unreachable!(),
        (Some(reader), None, None) => open_connection(&reader)?,
        (Some(reader), None, Some(serial)) => {
            let yubikey = open_connection(&reader)?;
            if yubikey.serial() != serial {
                return Err(Error::NoMatchingSerial(serial));
            }
            yubikey
        }
        (Some(a), Some(b), Some(serial)) => {
            let reader = iter::empty()
                .chain(Some(a))
                .chain(Some(b))
                .chain(readers_iter)
                .find(|reader| match open_connection(reader) {
                    Ok(yk) => yk.serial() == serial,
                    _ => false,
                })
                .ok_or(Error::NoMatchingSerial(serial))?;
            open_connection(&reader)?
        }
        (Some(_), Some(_), None) => return Err(Error::MultipleYubiKeys),
    };

    Ok(yubikey)
}

/// Sends a request to the SSH agent to trigger reconnection to the YubiKey.
///
/// This function sends an `SSH_AGENTC_REQUEST_IDENTITIES` (opcode 11) message to the
/// SSH agent socket specified by the `SSH_AUTH_SOCK` environment variable. This triggers
/// agents like `yubikey-agent` to reconnect to the YubiKey on-demand, preserving PIN
/// cache state.
///
/// All errors are silently ignored to avoid affecting the main encryption/decryption
/// workflow.
#[cfg(unix)]
fn poke_ssh_agent() {
    // Get SSH_AUTH_SOCK; silently return if not set
    let socket_path = match env::var("SSH_AUTH_SOCK") {
        Ok(path) if !path.is_empty() => path,
        _ => return,
    };

    // Connect to the SSH agent socket
    let mut stream = match UnixStream::connect(&socket_path) {
        Ok(s) => s,
        Err(e) => {
            debug!("Failed to connect to SSH agent socket: {}", e);
            return;
        }
    };

    // Set a short timeout to avoid blocking
    let timeout = Some(Duration::from_secs(1));
    let _ = stream.set_read_timeout(timeout);
    let _ = stream.set_write_timeout(timeout);

    // SSH_AGENTC_REQUEST_IDENTITIES message:
    // - 4 bytes: message length (big-endian) = 1
    // - 1 byte: message type = 11 (SSH_AGENTC_REQUEST_IDENTITIES)
    const SSH_AGENTC_REQUEST_IDENTITIES: [u8; 5] = [0, 0, 0, 1, 11];

    if let Err(e) = stream.write_all(&SSH_AGENTC_REQUEST_IDENTITIES) {
        debug!("Failed to send request to SSH agent: {}", e);
        return;
    }

    // Read and discard the response (we don't need the identities list)
    // Response format: 4-byte length + message body
    let mut length_buf = [0u8; 4];
    if stream.read_exact(&mut length_buf).is_ok() {
        let length = u32::from_be_bytes(length_buf) as usize;
        // Limit read to prevent memory issues with malformed responses
        if length <= 64 * 1024 {
            let mut response = vec![0u8; length];
            let _ = stream.read_exact(&mut response);
        }
    }

    debug!("Sent reconnection trigger to SSH agent at {}", socket_path);
}

#[cfg(not(unix))]
fn poke_ssh_agent() {
    // SSH agent socket communication is Unix-specific
}

/// Disconnect from the YubiKey without resetting it.
///
/// This can be used to preserve the YubiKey's PIN and touch caches. There are two cases
/// where we want to do this:
///
/// - We connected to this YubiKey in a read-only context, so we have not made any changes
///   to the YubiKey's state. However, we might have asked an agent to release the YubiKey
///   in `key::open_connection`, and we want to allow any state it may have left behind
///   (such as cached PINs or touches) to persist beyond our execution, for usability.
/// - We opened this connection in a decryption context, so the only changes to the
///   YubiKey's state were to potentially cache the PIN and/or touch (depending on the
///   policies of the slot). We want to allow these to persist beyond our execution, for
///   usability.
///
/// After releasing the YubiKey, this function also sends a request to the SSH agent
/// (if available) to trigger reconnection, allowing agents like `yubikey-agent` to
/// reclaim the device and preserve PIN cache state.
pub(crate) fn disconnect_without_reset(yubikey: YubiKey) {
    let _ = yubikey.disconnect(pcsc::Disposition::LeaveCard);
    poke_ssh_agent();
}

fn request_pin<E, E2>(
    mut prompt: impl FnMut(Option<String>) -> Result<Result<SecretString, E>, E2>,
    serial: Serial,
) -> Result<Result<SecretString, E>, E2> {
    let mut prev_error = None;
    loop {
        prev_error = Some(match prompt(prev_error)? {
            Ok(pin) => match pin.expose_secret().len() {
                // A PIN must be between 6 and 8 characters.
                6..=8 => break Ok(Ok(pin)),
                // If the string is 44 bytes and starts with the YubiKey's serial
                // encoded as 12-byte modhex, the user probably touched the YubiKey
                // early and "typed" an OTP.
                44 if pin.expose_secret().starts_with(&otp_serial_prefix(serial)) => {
                    fl!("plugin-err-accidental-touch")
                }
                // Otherwise, the PIN is either too short or too long.
                0..=5 => fl!("plugin-err-pin-too-short"),
                _ => fl!("plugin-err-pin-too-long"),
            },
            Err(e) => break Ok(Err(e)),
        });
    }
}

pub(crate) fn manage(yubikey: &mut YubiKey) -> Result<(), Error> {
    const DEFAULT_PIN: &str = "123456";
    const DEFAULT_PUK: &str = "12345678";

    eprintln!();
    let pin = Password::new()
        .with_prompt(fl!(
            "mgr-enter-pin",
            yubikey_serial = yubikey.serial().to_string(),
            default_pin = DEFAULT_PIN,
        ))
        .report(true)
        .interact()?;
    yubikey.verify_pin(pin.as_bytes())?;

    // If the user is using the default PIN, help them to change it.
    if pin == DEFAULT_PIN {
        eprintln!();
        eprintln!("{}", fl!("mgr-change-default-pin"));
        eprintln!();
        let current_puk = Password::new()
            .with_prompt(fl!("mgr-enter-current-puk", default_puk = DEFAULT_PUK))
            .interact()?;
        let new_pin = loop {
            let pin = request_pin(
                |prev_error| {
                    if let Some(err) = prev_error {
                        eprintln!("{err}");
                    }
                    Password::new()
                        .with_prompt(fl!("mgr-choose-new-pin"))
                        .with_confirmation(fl!("mgr-repeat-new-pin"), fl!("mgr-pin-mismatch"))
                        .interact()
                        .map(|pin| Result::<_, Infallible>::Ok(SecretString::from(pin)))
                },
                yubikey.serial(),
            )?
            .unwrap();
            if pin.expose_secret() == DEFAULT_PIN {
                eprintln!("{}", fl!("mgr-nope-default-pin"));
            } else {
                break pin;
            }
        };
        let new_pin = new_pin.expose_secret();
        yubikey
            .change_puk(current_puk.as_bytes(), new_pin.as_bytes())
            .map_err(|e| match e {
                yubikey::Error::PinLocked => Error::PukLocked,
                yubikey::Error::WrongPin { tries } => Error::WrongPuk(tries),
                _ => Error::YubiKey(e),
            })?;
        yubikey.change_pin(pin.as_bytes(), new_pin.as_bytes())?;
    }

    match MgmKey::get_protected(yubikey) {
        Ok(mgm_key) => yubikey.authenticate(mgm_key).map_err(|e| match e {
            yubikey::Error::AuthenticationError => Error::ManagementKeyAuth,
            _ => e.into(),
        })?,
        Err(yubikey::Error::AuthenticationError) => Err(Error::ManagementKeyAuth)?,
        _ => {
            // Try to authenticate with the default management key.
            yubikey
                .authenticate(MgmKey::default())
                .map_err(|_| Error::CustomManagementKey)?;

            // Migrate to a PIN-protected management key.
            let mgm_key = MgmKey::generate();
            eprintln!();
            eprintln!("{}", fl!("mgr-changing-mgmt-key"));
            eprint!("... ");
            mgm_key.set_protected(yubikey).map_err(|e| {
                eprintln!(
                    "{}",
                    fl!(
                        "mgr-changing-mgmt-key-error",
                        management_key = hex::encode(mgm_key.as_ref()),
                    )
                );
                e
            })?;
            eprintln!("{}", fl!("mgr-changing-mgmt-key-success"));
        }
    }

    Ok(())
}

/// Parses the certificate to identify the preferred recipient type it corresponds to.
pub(crate) fn identify_recipient(cert: &Certificate) -> Option<Recipient> {
    let known_oids = KNOWN_OIDS
        .iter()
        .map(|oid| Oid::from(oid).unwrap())
        .collect::<Vec<_>>();

    // If the certificate contains any unrecognised critical extensions, reject it: we
    // don't know how to correctly use the identity. In particular, some identities store
    // parts of their private key material in certificate extensions to work around
    // hardware limitations. Not understanding these extensions could lead to encrypting
    // with the wrong protocol and violating security assumptions.
    let (_, c) = x509_parser::parse_x509_certificate(cert.as_ref()).ok()?;
    if c.tbs_certificate
        .extensions()
        .iter()
        .any(|ext| ext.critical && !known_oids.contains(&ext.oid))
    {
        return None;
    }

    p256tag::Recipient::from_certificate(cert).map(Recipient::P256Tag)
}

/// What one of the plugin-compatible slots contains.
///
/// The certificate is carried directly rather than as a `yubikey::piv::Key`, because
/// `Key` has private fields and no public constructor: the only way to obtain one is
/// `Key::list`, which is precisely what we are replacing. `Key` is a `(SlotId,
/// Certificate)` pair, and every caller only ever used its `certificate()`.
// `Usable` is much larger than the other variants, but we build at most one per usable
// slot (of which there are 20), so boxing the certificate would cost more in legibility
// than it saves.
#[allow(clippy::large_enum_variant)]
pub(crate) enum SlotState {
    /// The slot contains no certificate, so it is free for us to write to.
    Empty,
    /// The slot is occupied by a certificate that we cannot parse, so we have no idea
    /// what it is being used for.
    ///
    /// This must never be conflated with [`SlotState::Empty`]: callers treat an empty
    /// slot as safe to overwrite, and doing that here would destroy whatever key the
    /// user has stored in the slot.
    Unusable,
    /// The slot contains a certificate that we can parse. The recipient is `Some` if the
    /// key is compatible with this plugin.
    Usable(Certificate, Option<Recipient>),
}

/// The PIV data object ID of the first retired slot.
///
/// The retired slots are numbered contiguously from `0x82` (`RetiredSlotId::R1`), and
/// their data objects are contiguous to match. `RetiredSlotId::object_id` in the
/// `yubikey` crate is `pub(crate)`, so we derive the ID the same way it does.
const RETIRED_SLOT_OBJECT_ID_BASE: ObjectId = 0x005f_c10d;

/// Returns the PIV data object ID in which the given retired slot stores its certificate.
fn slot_object_id(slot: RetiredSlotId) -> ObjectId {
    RETIRED_SLOT_OBJECT_ID_BASE + (u8::from(slot) as ObjectId - 0x82)
}

/// Returns whether the given retired slot has anything stored in it.
///
/// A slot only counts as empty if it holds neither a certificate nor a private key. Both
/// have to be checked: a slot can hold a key with no certificate (as left behind by
/// `ykman piv keys import`, or by deleting just the certificate), and generating over one
/// would destroy it. `Key::list` looked at certificates alone and so never saw these.
///
/// Neither check can produce a false "empty", which is the answer that costs a user their
/// key:
///
/// - We ask for the raw certificate object rather than going through `Certificate::read`,
///   because the latter cannot tell an empty slot apart from one holding a certificate it
///   fails to parse: it reports `InvalidObject` for both. `fetch_object` answers
///   `NotFound` only for status word 6A82; a communication failure surfaces as
///   `PcscError`, and we treat anything we cannot positively establish as absent as
///   "occupied".
/// - Key metadata requires firmware 5.2.3 or newer, and its failures do not distinguish
///   "no key in this slot" from "could not ask", so it is only ever used to say
///   "occupied", never to conclude that a slot is free.
pub(crate) fn slot_is_occupied(yubikey: &mut YubiKey, slot: RetiredSlotId) -> bool {
    match yubikey.fetch_object(slot_object_id(slot)) {
        Err(yubikey::Error::NotFound) => (),
        Ok(buf) if buf.is_empty() => (),
        // A certificate is stored here, or we could not tell.
        _ => return true,
    }

    // No certificate, but the slot may still hold a private key.
    piv_metadata(yubikey, SlotId::Retired(slot)).is_ok()
}

/// Returns the first slot that this plugin can use that has nothing stored in it.
///
/// This only checks occupancy, and stops at the first empty slot, so it usually costs a
/// single round trip rather than reading and parsing all 20 slots.
pub(crate) fn first_empty_slot(yubikey: &mut YubiKey) -> Option<RetiredSlotId> {
    USABLE_SLOTS
        .iter()
        .copied()
        .find(|&slot| !slot_is_occupied(yubikey, slot))
}

/// Returns the state of a single plugin-compatible slot.
pub(crate) fn slot_state(yubikey: &mut YubiKey, slot: RetiredSlotId) -> Result<SlotState, Error> {
    // Check occupancy first. Most slots are empty on a typical YubiKey, and ruling an
    // empty slot out costs a single round trip this way, where going via
    // `Certificate::read` would cost two (it can't distinguish empty from unparseable,
    // so we'd end up asking for the raw object anyway).
    if !slot_is_occupied(yubikey, slot) {
        return Ok(SlotState::Empty);
    }

    match Certificate::read(yubikey, SlotId::Retired(slot)) {
        Ok(cert) => {
            let recipient = identify_recipient(&cert);
            Ok(SlotState::Usable(cert, recipient))
        }
        // Something is stored in this slot, but we can't make sense of it. An unsupported
        // key algorithm reports one of two ways: RSA-4096 gives `AlgorithmError`, while
        // Ed25519 and X25519 fall through the catch-all arm of `PublicKeyInfo::parse` and
        // give `InvalidObject`, as does malformed DER. The slot is occupied either way,
        // and must never be offered up as empty.
        Err(yubikey::Error::AlgorithmError | yubikey::Error::InvalidObject) => {
            Ok(SlotState::Unusable)
        }
        // `yubikey::Error` is `#[non_exhaustive]`. Anything else is a genuine failure to
        // talk to the YubiKey, which we surface rather than guess about.
        Err(e) => Err(e.into()),
    }
}

/// Returns the state of every slot that this plugin can use, in [`USABLE_SLOTS`] order.
///
/// We enumerate the retired slots ourselves instead of calling `yubikey::piv::Key::list`.
/// That walks all 27 PIV objects, and while it tolerates read failures, a single
/// certificate it cannot parse aborts the entire loop and discards every slot found so
/// far. One unrelated key elsewhere on the YubiKey - including in the 9a/9c/9d/9e slots
/// that this plugin never uses - would therefore hide every slot from us.
///
/// See https://github.com/str4d/age-plugin-yubikey/issues/241.
pub(crate) fn list_slots(yubikey: &mut YubiKey) -> Result<Vec<(RetiredSlotId, SlotState)>, Error> {
    USABLE_SLOTS
        .iter()
        .map(|&slot| slot_state(yubikey, slot).map(|state| (slot, state)))
        .collect()
}

/// Returns an iterator of certificates in plugin-compatible slots that are compatible
/// with this plugin, along with their slot and recipient.
pub(crate) fn list_compatible(
    yubikey: &mut YubiKey,
) -> Result<impl Iterator<Item = (Certificate, RetiredSlotId, Recipient)>, Error> {
    list_slots(yubikey).map(|slots| {
        slots.into_iter().filter_map(|(slot, state)| match state {
            SlotState::Usable(cert, Some(recipient)) => Some((cert, slot, recipient)),
            _ => None,
        })
    })
}

/// A reference to an age key stored in a YubiKey.
#[derive(Debug)]
pub struct Stub {
    pub(crate) serial: Serial,
    pub(crate) slot: RetiredSlotId,
    pub(crate) tag: [u8; TAG_BYTES],
    pub(crate) identity_index: usize,
}

impl fmt::Display for Stub {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            bech32_encode(IDENTITY_PREFIX, &self.to_bytes())
                .to_uppercase()
                .as_str(),
        )
    }
}

impl PartialEq for Stub {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes().eq(&other.to_bytes())
    }
}

impl Stub {
    /// Returns a key stub and recipient for this `(Serial, SlotId, PublicKey)` tuple.
    ///
    /// Does not check that the `PublicKey` matches the given `(Serial, SlotId)` tuple;
    /// this is checked at decryption time.
    pub(crate) fn new(serial: Serial, slot: RetiredSlotId, recipient: &Recipient) -> Self {
        Stub {
            serial,
            slot,
            tag: recipient.static_tag(),
            identity_index: 0,
        }
    }

    pub(crate) fn from_bytes(bytes: &[u8], identity_index: usize) -> Option<Self> {
        if bytes.len() < 9 {
            return None;
        }
        let serial = Serial::from(u32::from_le_bytes(bytes[0..4].try_into().unwrap()));
        let slot: RetiredSlotId = bytes[4].try_into().ok()?;
        Some(Stub {
            serial,
            slot,
            tag: bytes[5..9].try_into().unwrap(),
            identity_index,
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(9);
        bytes.extend_from_slice(&self.serial.0.to_le_bytes());
        bytes.push(self.slot.into());
        bytes.extend_from_slice(&self.tag);
        bytes
    }

    /// Returns:
    /// - `Ok(Ok(Some(connection)))` if we successfully connected to this YubiKey.
    /// - `Ok(Ok(None))` if the user told us to skip this YubiKey.
    /// - `Ok(Err(_))` if we encountered an error while trying to connect to the YubiKey.
    /// - `Err(_)` on communication errors with the age client.
    pub(crate) fn connect<E>(
        &self,
        callbacks: &mut dyn Callbacks<E>,
    ) -> io::Result<Result<Option<Connection>, identity::Error>> {
        let mut yubikey = match open_by_serial(self.serial) {
            Ok(yk) => yk,
            Err(yubikey::Error::NotFound) => {
                let mut message = fl!("plugin-insert-yk", yubikey_serial = self.serial.to_string());

                // If the `confirm` command is available, we loop until either the YubiKey
                // we want is inserted, or the used explicitly skips.
                let yubikey = loop {
                    match callbacks.confirm(
                        &message,
                        &fl!("plugin-yk-is-plugged-in"),
                        Some(&fl!("plugin-skip-this-yk")),
                    )? {
                        // `confirm` command is not available.
                        Err(age_core::plugin::Error::Unsupported) => break None,
                        // User told us to skip this key.
                        Ok(false) => return Ok(Ok(None)),
                        // User said they plugged it in; try it.
                        Ok(true) => match open_by_serial(self.serial) {
                            Ok(yubikey) => break Some(yubikey),
                            Err(yubikey::Error::NotFound) => (),
                            Err(_) => {
                                return Ok(Err(identity::Error::Identity {
                                    index: self.identity_index,
                                    message: fl!(
                                        "plugin-err-yk-opening",
                                        yubikey_serial = self.serial.to_string(),
                                    ),
                                }));
                            }
                        },
                        // We can't communicate with the user.
                        Err(age_core::plugin::Error::Fail) => {
                            return Ok(Err(identity::Error::Identity {
                                index: self.identity_index,
                                message: fl!(
                                    "plugin-err-yk-opening",
                                    yubikey_serial = self.serial.to_string(),
                                ),
                            }))
                        }
                    }

                    // We're going to loop around, meaning that the first attempt failed.
                    // Change the message to indicate this to the user.
                    message = fl!(
                        "plugin-insert-yk-retry",
                        yubikey_serial = self.serial.to_string(),
                    );
                };

                if let Some(yk) = yubikey {
                    yk
                } else {
                    // `confirm` is not available; fall back to `message` with a timeout.
                    if callbacks.message(&message)?.is_err() {
                        return Ok(Err(identity::Error::Identity {
                            index: self.identity_index,
                            message: fl!(
                                "plugin-err-yk-not-found",
                                yubikey_serial = self.serial.to_string(),
                            ),
                        }));
                    }

                    // Start a 15-second timer waiting for the YubiKey to be inserted
                    let start = SystemTime::now();
                    loop {
                        match open_by_serial(self.serial) {
                            Ok(yubikey) => break yubikey,
                            Err(yubikey::Error::NotFound) => (),
                            Err(_) => {
                                return Ok(Err(identity::Error::Identity {
                                    index: self.identity_index,
                                    message: fl!(
                                        "plugin-err-yk-opening",
                                        yubikey_serial = self.serial.to_string(),
                                    ),
                                }));
                            }
                        }

                        match SystemTime::now().duration_since(start) {
                            Ok(end) if end >= FIFTEEN_SECONDS => {
                                return Ok(Err(identity::Error::Identity {
                                    index: self.identity_index,
                                    message: fl!(
                                        "plugin-err-yk-timed-out",
                                        yubikey_serial = self.serial.to_string(),
                                    ),
                                }))
                            }
                            _ => sleep(ONE_SECOND),
                        }
                    }
                }
            }
            Err(_) => {
                return Ok(Err(identity::Error::Identity {
                    index: self.identity_index,
                    message: fl!(
                        "plugin-err-yk-opening",
                        yubikey_serial = self.serial.to_string(),
                    ),
                }))
            }
        };

        // Read the pubkey from the YubiKey slot and check it still matches.
        let (cert, pk) = match Certificate::read(&mut yubikey, SlotId::Retired(self.slot))
            .ok()
            .and_then(|cert| {
                // Parse as the preferred recipient for each identity type.
                identify_recipient(&cert)
                    .filter(|recipient| recipient.static_tag() == self.tag)
                    .map(|r| (cert, r))
            }) {
            Some(pk) => pk,
            None => {
                return Ok(Err(identity::Error::Identity {
                    index: self.identity_index,
                    message: fl!("plugin-err-yk-stub-mismatch"),
                }))
            }
        };

        Ok(Ok(Some(Connection {
            yubikey,
            cert,
            pk,
            slot: self.slot,
            identity_index: self.identity_index,
            cached_metadata: None,
            last_touch: None,
        })))
    }
}

pub(crate) struct Connection {
    yubikey: YubiKey,
    cert: Certificate,
    pk: Recipient,
    slot: RetiredSlotId,
    identity_index: usize,
    cached_metadata: Option<Metadata>,
    last_touch: Option<Instant>,
}

impl Connection {
    /// Returns the preferred recipient for encrypting to this identity.
    pub(crate) fn recipient(&self) -> &Recipient {
        &self.pk
    }

    pub(crate) fn stub(&self) -> Stub {
        Stub::new(self.yubikey.serial(), self.slot, &self.pk)
    }

    pub(crate) fn request_pin_if_necessary<E>(
        &mut self,
        callbacks: &mut dyn Callbacks<E>,
    ) -> io::Result<Result<(), identity::Error>> {
        // Check if we can skip requesting a PIN.
        if self.cached_metadata.is_none() {
            self.cached_metadata =
                match Metadata::extract(&mut self.yubikey, self.slot, &self.cert, true) {
                    None => {
                        return Ok(Err(identity::Error::Identity {
                            index: self.identity_index,
                            message: fl!("plugin-err-yk-invalid-pin-policy"),
                        }))
                    }
                    metadata => metadata,
                };
        }
        match self.cached_metadata.as_ref().and_then(|m| m.pin_policy) {
            Some(PinPolicy::Never) => return Ok(Ok(())),
            Some(PinPolicy::Once) if self.yubikey.verify_pin(&[]).is_ok() => return Ok(Ok(())),
            _ => (),
        }

        // The policy requires a PIN, so request it.
        let pin = match request_pin(
            |prev_error| {
                callbacks.request_secret(&format!(
                    "{}{}{}",
                    prev_error.as_deref().unwrap_or(""),
                    prev_error.as_deref().map(|_| " ").unwrap_or(""),
                    fl!(
                        "plugin-enter-pin",
                        yubikey_serial = self.yubikey.serial().to_string(),
                    )
                ))
            },
            self.yubikey.serial(),
        )? {
            Ok(pin) => pin,
            Err(_) => {
                return Ok(Err(identity::Error::Identity {
                    index: self.identity_index,
                    message: fl!(
                        "plugin-err-pin-required",
                        yubikey_serial = self.yubikey.serial().to_string(),
                    ),
                }))
            }
        };
        if let Err(e) = self.yubikey.verify_pin(pin.expose_secret().as_bytes()) {
            return Ok(Err(identity::Error::Identity {
                index: self.identity_index,
                message: format!("{:?}", Error::YubiKey(e)),
            }));
        }
        Ok(Ok(()))
    }

    pub(crate) fn p256_ecdh(&mut self, epk_bytes: &[u8]) -> Result<yubikey::Buffer, ()> {
        // The YubiKey API for performing scalar multiplication takes the point in its
        // uncompressed SEC-1 encoding.
        assert_eq!(epk_bytes.len(), 65);

        // Check if the touch policy requires a touch.
        let needs_touch = match (
            self.cached_metadata.as_ref().and_then(|m| m.touch_policy),
            self.last_touch,
        ) {
            (Some(TouchPolicy::Always), _) | (Some(TouchPolicy::Cached), None) => true,
            (Some(TouchPolicy::Cached), Some(last)) if last.elapsed() >= FIFTEEN_SECONDS => true,
            _ => false,
        };

        let shared_secret = match decrypt_data(
            &mut self.yubikey,
            epk_bytes,
            AlgorithmId::EccP256,
            SlotId::Retired(self.slot),
        ) {
            Ok(res) => res,
            Err(_) => return Err(()),
        };

        // If we requested a touch and reached here, the user touched the YubiKey.
        if needs_touch {
            if let Some(TouchPolicy::Cached) =
                self.cached_metadata.as_ref().and_then(|m| m.touch_policy)
            {
                self.last_touch = Some(Instant::now());
            }
        }

        Ok(shared_secret)
    }

    /// Close this connection without resetting the YubiKey.
    ///
    /// This can be used to preserve the YubiKey's PIN and touch caches.
    pub(crate) fn disconnect_without_reset(self) {
        disconnect_without_reset(self.yubikey);
    }
}

#[cfg(test)]
mod tests {
    use yubikey::{piv::RetiredSlotId, Serial};

    use super::Stub;

    #[test]
    fn stub_round_trip() {
        let stub = Stub {
            serial: Serial::from(42),
            slot: RetiredSlotId::R1,
            tag: [7; 4],
            identity_index: 0,
        };

        let encoded = stub.to_bytes();
        assert_eq!(Stub::from_bytes(&[], 0), None);
        assert_eq!(Stub::from_bytes(&encoded, 0), Some(stub));
        assert_eq!(Stub::from_bytes(&encoded[..encoded.len() - 1], 0), None);
    }
}
