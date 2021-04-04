use age_plugin::run_state_machine;
use dialoguer::{Confirm, Select};
use gumdrop::Options;
use log::warn;
use yubikey_piv::{
    certificate::PublicKeyInfo,
    key::{RetiredSlotId, SlotId},
    policy::{PinPolicy, TouchPolicy},
    Key, Readers,
};

mod builder;
mod error;
mod p256;
mod plugin;
mod util;
mod yubikey;

use error::Error;

const PLUGIN_NAME: &str = "age-plugin-yubikey";
const RECIPIENT_PREFIX: &str = "age1yubikey";
const IDENTITY_PREFIX: &str = "age-plugin-yubikey-";

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

#[derive(Debug, Options)]
struct PluginOptions {
    #[options(help = "Print this help message and exit.")]
    help: bool,

    #[options(
        help = "Run the given age plugin state machine. Internal use only.",
        meta = "STATE-MACHINE",
        no_short
    )]
    age_plugin: Option<String>,

    #[options(help = "Force --generate to overwrite a filled slot.")]
    force: bool,

    #[options(help = "Generate a new YubiKey identity.")]
    generate: bool,

    #[options(help = "Print the identity stored in a YubiKey slot.")]
    identity: bool,

    #[options(help = "List all age identities in connected YubiKeys.")]
    list: bool,

    #[options(help = "List all YubiKey keys that are compatible with age.", no_short)]
    list_all: bool,

    #[options(
        help = "Name for the generated identity. Defaults to 'age identity HEX_TAG'.",
        no_short
    )]
    name: Option<String>,

    #[options(help = "One of [always, once, never]. Defaults to 'once'.", no_short)]
    pin_policy: Option<String>,

    #[options(
        help = "Specify which YubiKey to use, if more than one is plugged in.",
        no_short
    )]
    serial: Option<u32>,

    #[options(
        help = "Specify which slot to use. Defaults to first usable slot.",
        no_short
    )]
    slot: Option<u8>,

    #[options(
        help = "One of [always, cached, never]. Defaults to 'always'.",
        no_short
    )]
    touch_policy: Option<String>,
}

fn generate(opts: PluginOptions) -> Result<(), Error> {
    let serial = opts.serial.map(|s| s.into());
    let slot = opts.slot.map(util::ui_to_slot).transpose()?;
    let pin_policy = opts
        .pin_policy
        .map(util::pin_policy_from_string)
        .transpose()?;
    let touch_policy = opts
        .touch_policy
        .map(util::touch_policy_from_string)
        .transpose()?;

    let mut yubikey = yubikey::open(serial)?;

    let (stub, recipient, created) = builder::IdentityBuilder::new(slot)
        .with_name(opts.name)
        .with_pin_policy(pin_policy)
        .with_touch_policy(touch_policy)
        .force(opts.force)
        .build(&mut yubikey)?;

    util::print_identity(stub, recipient, &created);

    Ok(())
}

fn identity(opts: PluginOptions) -> Result<(), Error> {
    let serial = opts.serial.map(|s| s.into());
    let slot = opts.slot.map(util::ui_to_slot).transpose()?;

    let mut yubikey = yubikey::open(serial)?;

    let mut keys = Key::list(&mut yubikey)?.into_iter().filter_map(|key| {
        // - We only use the retired slots.
        // - Only P-256 keys are compatible with us.
        match (key.slot(), key.certificate().subject_pki()) {
            (SlotId::Retired(slot), PublicKeyInfo::EcP256(pubkey)) => {
                p256::Recipient::from_encoded(pubkey).map(|r| (key, slot, r))
            }
            _ => None,
        }
    });

    let (key, slot, recipient) = if let Some(slot) = slot {
        keys.find(|(_, s, _)| s == &slot)
            .ok_or(Error::SlotHasNoIdentity(slot))
    } else {
        let mut keys = keys.filter(|(key, _, _)| {
            let cert = x509_parser::parse_x509_certificate(key.certificate().as_ref())
                .map(|(_, cert)| cert)
                .ok();
            match cert
                .as_ref()
                .and_then(|cert| cert.subject().iter_organization().next())
            {
                Some(org) => org.as_str() == Ok(PLUGIN_NAME),
                _ => false,
            }
        });
        match (keys.next(), keys.next()) {
            (None, None) => Err(Error::NoIdentities),
            (Some(key), None) => Ok(key),
            (Some(_), Some(_)) => Err(Error::MultipleIdentities),
            (None, Some(_)) => unreachable!(),
        }
    }?;

    let stub = yubikey::Stub::new(yubikey.serial(), slot, &recipient);
    let created = x509_parser::parse_x509_certificate(key.certificate().as_ref())
        .ok()
        .map(|(_, cert)| cert.validity().not_before.to_rfc2822())
        .unwrap_or_else(|| "Unknown".to_owned());

    util::print_identity(stub, recipient, &created);

    Ok(())
}

fn list(all: bool) -> Result<(), Error> {
    let mut readers = Readers::open()?;

    for reader in readers.iter()? {
        let mut yubikey = match reader.open() {
            Ok(yk) => yk,
            Err(e) => {
                use std::error::Error;
                let reason = if let Some(inner) = e.source() {
                    format!("{}: {}", e, inner)
                } else {
                    e.to_string()
                };
                warn!("Ignoring {}: {}", reader.name(), reason);
                continue;
            }
        };

        for key in Key::list(&mut yubikey)? {
            // We only use the retired slots.
            let slot = match key.slot() {
                SlotId::Retired(slot) => slot,
                _ => continue,
            };

            // Only P-256 keys are compatible with us.
            let recipient = match key.certificate().subject_pki() {
                PublicKeyInfo::EcP256(pubkey) => match p256::Recipient::from_encoded(pubkey) {
                    Some(recipient) => recipient,
                    None => continue,
                },
                _ => continue,
            };

            let ((name, pin_policy, touch_policy), created) =
                match x509_parser::parse_x509_certificate(key.certificate().as_ref())
                    .ok()
                    .and_then(|(_, cert)| {
                        util::extract_name_and_policies(&mut yubikey, &key, &cert, all)
                            .map(|res| (res, cert.validity().not_before.to_rfc2822()))
                    }) {
                    Some(res) => res,
                    None => continue,
                };

            println!(
                "#       Serial: {}, Slot: {}",
                yubikey.serial(),
                util::slot_to_ui(&slot),
            );
            println!("#         Name: {}", name);
            println!("#      Created: {}", created);
            println!("#   PIN policy: {}", util::pin_policy_to_str(pin_policy));
            println!(
                "# Touch policy: {}",
                util::touch_policy_to_str(touch_policy)
            );
            println!("{}", recipient.to_string());
            println!();
        }
        println!();
    }

    Ok(())
}

fn main() -> Result<(), Error> {
    env_logger::builder()
        .format_timestamp(None)
        .filter_level(log::LevelFilter::Off)
        .parse_default_env()
        .init();

    let opts = PluginOptions::parse_args_default_or_exit();

    if [opts.generate, opts.identity, opts.list, opts.list_all]
        .iter()
        .filter(|&&b| b)
        .count()
        > 1
    {
        return Err(Error::MultipleCommands);
    }

    if let Some(state_machine) = opts.age_plugin {
        run_state_machine(
            &state_machine,
            || plugin::RecipientPlugin::default(),
            || plugin::IdentityPlugin::default(),
        )?;
        Ok(())
    } else if opts.generate {
        generate(opts)
    } else if opts.identity {
        identity(opts)
    } else if opts.list {
        list(false)
    } else if opts.list_all {
        list(true)
    } else {
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

        if Readers::open()?.iter()?.len() == 0 {
            eprintln!("⏳ Please insert the YubiKey you want to set up.");
        };
        let mut readers = yubikey::wait_for_readers()?;

        // Filter out readers we can't connect to.
        let readers_list: Vec<_> = readers
            .iter()?
            .filter_map(|reader| match reader.open() {
                Ok(_) => Some(reader),
                Err(e) => {
                    use std::error::Error;
                    let reason = if let Some(inner) = e.source() {
                        format!("{}: {}", e, inner)
                    } else {
                        e.to_string()
                    };
                    warn!("Ignoring {}: {}", reader.name(), reason);
                    None
                }
            })
            .collect();

        let reader_names = readers_list
            .iter()
            .map(|reader| {
                reader
                    .open()
                    .map(|yk| format!("{} (Serial: {})", reader.name(), yk.serial()))
            })
            .collect::<Result<Vec<_>, _>>()?;
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

        // Identify slots that we can't allow the user to select.
        let slot_details: Vec<_> = USABLE_SLOTS
            .iter()
            .map(|&slot| {
                keys.iter()
                    .find(|key| key.slot() == SlotId::Retired(slot))
                    .map(|key| match key.certificate().subject_pki() {
                        PublicKeyInfo::EcP256(pubkey) => {
                            p256::Recipient::from_encoded(pubkey).map(|_| {
                                // Cache the details we need to display to the user.
                                let (_, cert) =
                                    x509_parser::parse_x509_certificate(key.certificate().as_ref())
                                        .unwrap();
                                let (name, _) = util::extract_name(&cert, true).unwrap();
                                let created = cert.validity().not_before.to_rfc2822();

                                format!("{}, created: {}", name, created)
                            })
                        }
                        _ => None,
                    })
            })
            .collect();

        let slots: Vec<_> = slot_details
            .iter()
            .enumerate()
            .map(|(i, occupied)| {
                // Use 1-indexing in the UI for niceness
                let i = i + 1;

                match occupied {
                    Some(Some(name)) => format!("Slot {} ({})", i, name),
                    Some(None) => format!("Slot {} (Unusable)", i),
                    None => format!("Slot {} (Empty)", i),
                }
            })
            .collect();

        let (stub, recipient, created) = {
            let (slot_index, slot) = loop {
                match Select::new()
                    .with_prompt("🕳️  Select a slot for your age identity")
                    .items(&slots)
                    .default(0)
                    .interact_opt()?
                {
                    Some(slot) => {
                        if let Some(None) = slot_details[slot] {
                        } else {
                            break (slot + 1, USABLE_SLOTS[slot]);
                        }
                    }
                    None => return Ok(()),
                }
            };

            if let Some(key) = keys.iter().find(|key| key.slot() == SlotId::Retired(slot)) {
                let recipient = match key.certificate().subject_pki() {
                    PublicKeyInfo::EcP256(pubkey) => {
                        p256::Recipient::from_encoded(pubkey).expect("We checked this above")
                    }
                    _ => unreachable!(),
                };

                if Confirm::new()
                    .with_prompt(&format!("Use existing identity in slot {}?", slot_index))
                    .interact()?
                {
                    let stub = yubikey::Stub::new(yubikey.serial(), slot, &recipient);
                    let (_, cert) =
                        x509_parser::parse_x509_certificate(key.certificate().as_ref()).unwrap();
                    let created = cert.validity().not_before.to_rfc2822();

                    (stub, recipient, created)
                } else {
                    return Ok(());
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
                    builder::IdentityBuilder::new(Some(slot))
                        .with_name(opts.name)
                        .with_pin_policy(Some(pin_policy))
                        .with_touch_policy(Some(touch_policy))
                        .force(opts.force)
                        .build(&mut yubikey)?
                } else {
                    return Ok(());
                }
            }
        };

        util::print_identity(stub, recipient, &created);

        Ok(())
    }
}
