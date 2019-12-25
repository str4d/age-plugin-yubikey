use age_plugin::run_state_machine;
use dialoguer::{Confirm, Password, Select};
use gumdrop::Options;
use rand::{rngs::OsRng, RngCore};
use std::convert::TryFrom;
use std::fmt;
use std::io;
use yubikey_piv::{
    certificate::{Certificate, PublicKeyInfo},
    key::{generate as yubikey_generate, AlgorithmId, Key, RetiredSlotId, SlotId},
    policy::{PinPolicy, TouchPolicy},
    MgmKey, Readers,
};

mod format;
mod p256;
mod plugin;
mod yubikey;

const IDENTITY_PREFIX: &str = "age-plugin-yubikey-";
const RECIPIENT_PREFIX: &str = "age1yubikey";
const STANZA_TAG: &str = "piv-p256";

const USABLE_SLOTS: [RetiredSlotId; 20] = [
    RetiredSlotId::R1,
    RetiredSlotId::R2,
    RetiredSlotId::R3,
    RetiredSlotId::R4,
    RetiredSlotId::R5,
    RetiredSlotId::R6,
    RetiredSlotId::R7,
    RetiredSlotId::R8,
    RetiredSlotId::R9,
    RetiredSlotId::R10,
    RetiredSlotId::R11,
    RetiredSlotId::R12,
    RetiredSlotId::R13,
    RetiredSlotId::R14,
    RetiredSlotId::R15,
    RetiredSlotId::R16,
    RetiredSlotId::R17,
    RetiredSlotId::R18,
    RetiredSlotId::R19,
    RetiredSlotId::R20,
];

enum Error {
    Io(io::Error),
    YubiKey(yubikey_piv::Error),
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<yubikey_piv::error::Error> for Error {
    fn from(e: yubikey_piv::error::Error) -> Self {
        Error::YubiKey(e)
    }
}

// Rust only supports `fn main() -> Result<(), E: Debug>`, so we implement `Debug`
// manually to provide the error output we want.
impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => writeln!(f, "Failed to set up YubiKey: {}", e)?,
            Error::YubiKey(e) => match e {
                yubikey_piv::error::Error::NotFound => {
                    writeln!(f, "Please insert the YubiKey you want to set up")?
                }
                e => {
                    writeln!(f, "Error while communicating with YubiKey: {}", e)?;
                    use std::error::Error;
                    if let Some(inner) = e.source() {
                        writeln!(f, "Cause: {}", inner)?;
                    }
                }
            },
        }
        writeln!(f)?;
        writeln!(
            f,
            "[ Did this not do what you expected? Could an error be more useful? ]"
        )?;
        write!(
            f,
            "[ Tell us: https://str4d.xyz/rage/report                            ]"
        )
    }
}

#[derive(Debug, Options)]
struct PluginOptions {
    #[options(help = "print help message")]
    help: bool,

    #[options(help = "run the given age plugin state machine", no_short)]
    age_plugin: Option<String>,
}

fn main() -> Result<(), Error> {
    let opts = PluginOptions::parse_args_default_or_exit();

    if let Some(state_machine) = opts.age_plugin {
        run_state_machine(
            &state_machine,
            || plugin::RecipientPlugin::default(),
            || plugin::IdentityPlugin::default(),
        )?;
        return Ok(());
    }

    eprintln!("✨ Let's get your YubiKey set up for age! ✨");
    eprintln!("");
    eprintln!("This tool can create a new age identity in a free slot of your YubiKey.");
    eprintln!("It will generate an identity file that you can use with an age client,");
    eprintln!("along with the corresponding recipient.");
    eprintln!("");
    eprintln!("If you are already using a YubiKey with age, you can select an existing");
    eprintln!("slot to recreate its corresponding identity file and recipient.");
    eprintln!("");
    eprintln!("When asked below to select an option, use the up/down arrow keys to");
    eprintln!("make your choice, or press [Esc] or [q] to quit.");
    eprintln!("");

    let mut readers = Readers::open()?;
    let readers_list: Vec<_> = readers.iter()?.collect();
    let reader_names: Vec<_> = readers_list.iter().map(|reader| reader.name()).collect();

    let mut yubikey = match Select::new()
        .with_prompt("🔑 Select a YubiKey")
        .items(&reader_names)
        .default(0)
        .interact_opt()?
    {
        Some(yk) => readers_list[yk].open()?,
        None => return Ok(()),
    };

    let keys = Key::list(&mut yubikey)?;

    let slots: Vec<_> = USABLE_SLOTS
        .iter()
        .enumerate()
        .map(|(i, slot)| {
            // Use 1-indexing in the UI for niceness
            let i = i + 1;

            let occupied = keys.iter().find(|key| key.slot() == SlotId::Retired(*slot));
            if let Some(key) = occupied {
                format!("Slot {} ({})", i, key.certificate().subject())
            } else {
                format!("Slot {} (Empty)", i)
            }
        })
        .collect();

    let (created, (stub, recipient)) = {
        let (slot_index, slot) = match Select::new()
            .with_prompt("🕳️  Select a slot for your age identity")
            .items(&slots)
            .default(0)
            .interact_opt()?
        {
            Some(slot) => (slot + 1, USABLE_SLOTS[slot]),
            None => return Ok(()),
        };

        if let Some(key) = keys.iter().find(|key| key.slot() == SlotId::Retired(slot)) {
            match key.certificate().subject_pki() {
                PublicKeyInfo::EcP256(pubkey) => {
                    if Confirm::new()
                        .with_prompt(&format!("Use existing identity in slot {}?", slot_index))
                        .interact()?
                    {
                        (
                            // TODO: enable replacing this with
                            // key.certificate().created(),
                            chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                            yubikey::Stub::new(yubikey.serial(), slot, *pubkey)
                                .expect("YubiKey only stores valid pubkeys"),
                        )
                    } else {
                        return Ok(());
                    }
                }
                PublicKeyInfo::Rsa { .. } | PublicKeyInfo::EcP384(_) => {
                    // TODO: Don't allow this to be selected, by detecting existing keys correctly
                    eprintln!("Error: age requires P-256 for YubiKeys.");
                    return Ok(());
                }
            }
        } else {
            let pin_policy = match Select::new()
                .with_prompt("🔤 Select a PIN policy")
                .items(&[
                    "Always (A PIN is required for every decryption, if set)",
                    "Once   (A PIN is required once per session, if set)",
                    "Never  (A PIN is NOT required to decrypt)",
                ])
                .default(1)
                .interact_opt()?
            {
                Some(0) => PinPolicy::Always,
                Some(1) => PinPolicy::Once,
                Some(2) => PinPolicy::Never,
                Some(_) => unreachable!(),
                None => return Ok(()),
            };

            let touch_policy = match Select::new()
                .with_prompt("👆 Select a touch policy")
                .items(&[
                    "Always (A physical touch is required for every decryption)",
                    "Cached (A physical touch is required for decryption, and is cached for 15 seconds)",
                    "Never  (A physical touch is NOT required to decrypt)",
                ])
                .default(0)
                .interact_opt()?
            {
                Some(0) => TouchPolicy::Always,
                Some(1) => TouchPolicy::Cached,
                Some(2) => TouchPolicy::Never,
                Some(_) => unreachable!(),
                None => return Ok(()),
            };

            if Confirm::new()
                .with_prompt(&format!("Generate new identity in slot {}?", slot_index))
                .interact()?
            {
                eprintln!();

                // Try to authenticate with the default management key.
                if yubikey.authenticate(MgmKey::default()).is_err() {
                    // Management key has been changed; ask the user to provide it.
                    let mgm_input = Password::new()
                        .with_prompt("🔐 Enter the management key as a hex string")
                        .interact()?;

                    let mgm_key = match hex::decode(mgm_input) {
                        Ok(mgm_bytes) => match MgmKey::try_from(&mgm_bytes[..]) {
                            Ok(mgm_key) => mgm_key,
                            Err(_) => {
                                eprintln!("Incorrect management key size");
                                return Ok(());
                            }
                        },
                        Err(_) => {
                            eprintln!("Management key must be a hex string");
                            return Ok(());
                        }
                    };

                    yubikey.authenticate(mgm_key)?;
                }

                if let PinPolicy::Never = pin_policy {
                    // No need to enter PIN
                } else {
                    let pin = Password::new()
                        .with_prompt(&format!(
                            "🔤 Enter PIN for YubiKey with serial {}",
                            yubikey.serial()
                        ))
                        .interact()?;
                    yubikey.verify_pin(pin.as_bytes())?;
                }

                if let TouchPolicy::Never = touch_policy {
                    // No need to touch YubiKey
                } else {
                    eprintln!("👆 Please touch the YubiKey");
                }

                // Generate a new key in the selected slot.
                let generated = yubikey_generate(
                    &mut yubikey,
                    SlotId::Retired(slot),
                    AlgorithmId::EccP256,
                    pin_policy,
                    touch_policy,
                )?;

                let mut serial = [0; 20];
                OsRng.fill_bytes(&mut serial);

                let cert = Certificate::generate_self_signed(
                    &mut yubikey,
                    SlotId::Retired(slot),
                    serial,
                    None,
                    "age-plugin-yubikey".to_owned(),
                    generated,
                )?;

                match cert.subject_pki() {
                    PublicKeyInfo::EcP256(pubkey) => (
                        chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                        yubikey::Stub::new(yubikey.serial(), slot, *pubkey)
                            .expect("YubiKey generates a valid pubkey"),
                    ),
                    _ => unreachable!(),
                }
            } else {
                return Ok(());
            }
        }
    };

    if !console::user_attended() {
        eprintln!("Recipient: {}", format::yubikey_to_str(&recipient));
    }

    println!("# created: {}", created);
    println!("# recipient: {}", format::yubikey_to_str(&recipient));
    println!("{}", stub.to_str());

    Ok(())
}
