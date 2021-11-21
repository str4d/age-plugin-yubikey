use std::convert::{TryFrom, TryInto};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};

use age_plugin::run_state_machine;
use dialoguer::{Confirm, Input, Select};
use gumdrop::Options;
use yubikey::{
    certificate::PublicKeyInfo,
    piv::{RetiredSlotId, SlotId},
    reader::Context,
    Key, PinPolicy, Serial, TouchPolicy,
};

mod builder;
mod error;
mod format;
mod key;
mod p256;
mod plugin;
mod util;

use error::Error;

const PLUGIN_NAME: &str = "yubikey";
const BINARY_NAME: &str = "age-plugin-yubikey";
const RECIPIENT_PREFIX: &str = "age1yubikey";
const IDENTITY_PREFIX: &str = "age-plugin-yubikey-";
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

#[derive(Debug, Options)]
struct PluginOptions {
    #[options(help = "Print this help message and exit.")]
    help: bool,

    #[options(help = "Print version info and exit.", short = "V")]
    version: bool,

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

    #[options(help = "Print identities stored in connected YubiKeys.")]
    identity: bool,

    #[options(help = "List recipients for age identities in connected YubiKeys.")]
    list: bool,

    #[options(
        help = "List recipients for all YubiKey keys that are compatible with age.",
        no_short
    )]
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

struct PluginFlags {
    serial: Option<Serial>,
    slot: Option<RetiredSlotId>,
    name: Option<String>,
    pin_policy: Option<PinPolicy>,
    touch_policy: Option<TouchPolicy>,
    force: bool,
}

impl TryFrom<PluginOptions> for PluginFlags {
    type Error = Error;

    fn try_from(opts: PluginOptions) -> Result<Self, Self::Error> {
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

        Ok(PluginFlags {
            serial,
            slot,
            name: opts.name,
            pin_policy,
            touch_policy,
            force: opts.force,
        })
    }
}

fn generate(flags: PluginFlags) -> Result<(), Error> {
    let mut yubikey = key::open(flags.serial)?;

    let (stub, recipient, metadata) = builder::IdentityBuilder::new(flags.slot)
        .with_name(flags.name)
        .with_pin_policy(flags.pin_policy)
        .with_touch_policy(flags.touch_policy)
        .force(flags.force)
        .build(&mut yubikey)?;

    util::print_identity(stub, recipient, metadata);

    Ok(())
}

fn print_single(
    serial: Option<Serial>,
    slot: RetiredSlotId,
    printer: impl Fn(key::Stub, p256::Recipient, util::Metadata),
) -> Result<(), Error> {
    let mut yubikey = key::open(serial)?;

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

    let (key, slot, recipient) = keys
        .find(|(_, s, _)| s == &slot)
        .ok_or(Error::SlotHasNoIdentity(slot))?;

    let stub = key::Stub::new(yubikey.serial(), slot, &recipient);
    let metadata = x509_parser::parse_x509_certificate(key.certificate().as_ref())
        .ok()
        .and_then(|(_, cert)| util::Metadata::extract(&mut yubikey, slot, &cert, true))
        .unwrap();

    printer(stub, recipient, metadata);

    Ok(())
}

fn print_multiple(
    kind: &str,
    serial: Option<Serial>,
    all: bool,
    printer: impl Fn(key::Stub, p256::Recipient, util::Metadata),
) -> Result<(), Error> {
    let mut readers = Context::open()?;

    let mut printed = 0;
    for reader in readers.iter()?.filter(key::filter_connected) {
        let mut yubikey = reader.open()?;
        if let Some(serial) = serial {
            if yubikey.serial() != serial {
                continue;
            }
        }

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

            let stub = key::Stub::new(yubikey.serial(), slot, &recipient);
            let metadata = match x509_parser::parse_x509_certificate(key.certificate().as_ref())
                .ok()
                .and_then(|(_, cert)| util::Metadata::extract(&mut yubikey, slot, &cert, all))
            {
                Some(res) => res,
                None => continue,
            };

            printer(stub, recipient, metadata);
            printed += 1;
            println!();
        }
        println!();
    }
    if printed > 1 {
        eprintln!(
            "Generated {} for {} slots. If you intended to select a slot, use --slot.",
            kind, printed,
        );
    }

    Ok(())
}

fn print_details(
    kind: &str,
    flags: PluginFlags,
    all: bool,
    printer: impl Fn(key::Stub, p256::Recipient, util::Metadata),
) -> Result<(), Error> {
    if let Some(slot) = flags.slot {
        print_single(flags.serial, slot, printer)
    } else {
        print_multiple(kind, flags.serial, all, printer)
    }
}

fn identity(flags: PluginFlags) -> Result<(), Error> {
    if flags.force {
        return Err(Error::InvalidFlagCommand(
            "--force".into(),
            "--identity".into(),
        ));
    }
    print_details("identities", flags, false, util::print_identity)
}

fn list(flags: PluginFlags, all: bool) -> Result<(), Error> {
    if all && flags.slot.is_some() {
        return Err(Error::UseListForSingleSlot);
    }
    if flags.force {
        return Err(Error::InvalidFlagCommand(
            "--force".into(),
            format!("--list{}", if all { "-all" } else { "" }),
        ));
    }

    print_details("recipients", flags, all, |_, recipient, metadata| {
        println!("{}", metadata);
        println!("{}", recipient.to_string());
    })
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
            plugin::RecipientPlugin::default,
            plugin::IdentityPlugin::default,
        )?;
        Ok(())
    } else if opts.version {
        println!("age-plugin-yubikey {}", env!("CARGO_PKG_VERSION"));
        Ok(())
    } else if opts.generate {
        generate(opts.try_into()?)
    } else if opts.identity {
        identity(opts.try_into()?)
    } else if opts.list {
        list(opts.try_into()?, false)
    } else if opts.list_all {
        list(opts.try_into()?, true)
    } else {
        if opts.force {
            return Err(Error::InvalidFlagTui("--force".into()));
        }
        let flags: PluginFlags = opts.try_into()?;

        eprintln!("✨ Let's get your YubiKey set up for age! ✨");
        eprintln!();
        eprintln!("This tool can create a new age identity in a free slot of your YubiKey.");
        eprintln!("It will generate an identity file that you can use with an age client,");
        eprintln!("along with the corresponding recipient. You can also do this directly");
        eprintln!("with:");
        eprintln!("    age-plugin-yubikey --generate");
        eprintln!();
        eprintln!("If you are already using a YubiKey with age, you can select an existing");
        eprintln!("slot to recreate its corresponding identity file and recipient.");
        eprintln!();
        eprintln!("When asked below to select an option, use the up/down arrow keys to");
        eprintln!("make your choice, or press [Esc] or [q] to quit.");
        eprintln!();

        if !Context::open()?.iter()?.any(key::is_connected) {
            eprintln!("⏳ Please insert the YubiKey you want to set up.");
        };
        let mut readers = key::wait_for_readers()?;

        // Filter out readers we can't connect to.
        let readers_list: Vec<_> = readers.iter()?.filter(key::filter_connected).collect();

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

        let ((stub, recipient, metadata), is_new) = {
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
                    let stub = key::Stub::new(yubikey.serial(), slot, &recipient);
                    let (_, cert) =
                        x509_parser::parse_x509_certificate(key.certificate().as_ref()).unwrap();
                    let metadata =
                        util::Metadata::extract(&mut yubikey, slot, &cert, true).unwrap();

                    ((stub, recipient, metadata), false)
                } else {
                    return Ok(());
                }
            } else {
                let name = Input::<String>::new()
                    .with_prompt(format!(
                        "📛 Name this identity [{}]",
                        flags.name.as_deref().unwrap_or("age identity TAG_HEX")
                    ))
                    .allow_empty(true)
                    .interact_text()?;

                let pin_policy = match Select::new()
                    .with_prompt("🔤 Select a PIN policy")
                    .items(&[
                        "Always (A PIN is required for every decryption, if set)",
                        "Once   (A PIN is required once per session, if set)",
                        "Never  (A PIN is NOT required to decrypt)",
                    ])
                    .default(
                        [PinPolicy::Always, PinPolicy::Once, PinPolicy::Never]
                            .iter()
                            .position(|p| {
                                p == &flags.pin_policy.unwrap_or(builder::DEFAULT_PIN_POLICY)
                            })
                            .unwrap(),
                    )
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
                        .default(
                            [TouchPolicy::Always, TouchPolicy::Cached, TouchPolicy::Never]
                                .iter()
                                .position(|p| p == &flags
                                    .touch_policy.unwrap_or(builder::DEFAULT_TOUCH_POLICY))
                                .unwrap(),
                        )
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
                    (
                        builder::IdentityBuilder::new(Some(slot))
                            .with_name(match name {
                                s if s.is_empty() => flags.name,
                                s => Some(s),
                            })
                            .with_pin_policy(Some(pin_policy))
                            .with_touch_policy(Some(touch_policy))
                            .build(&mut yubikey)?,
                        true,
                    )
                } else {
                    return Ok(());
                }
            }
        };

        eprintln!();
        let file_name = Input::<String>::new()
            .with_prompt("📝 File name to write this identity to")
            .default(format!(
                "age-yubikey-identity-{}.txt",
                hex::encode(stub.tag)
            ))
            .interact_text()?;

        let mut file = match OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&file_name)
        {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                if Confirm::new()
                    .with_prompt("File exists. Overwrite it?")
                    .interact()?
                {
                    File::create(&file_name)?
                } else {
                    return Ok(());
                }
            }
            Err(e) => return Err(e.into()),
        };

        writeln!(file, "{}", metadata)?;
        writeln!(file, "#    Recipient: {}", recipient)?;
        writeln!(file, "{}", stub.to_string())?;
        file.sync_data()?;

        // If `rage` binary is installed, use it in examples. Otherwise default to `age`.
        let age_binary = which::which("rage").map(|_| "rage").unwrap_or("age");

        eprintln!();
        eprintln!("✅ Done! This YubiKey identity is ready to go.");
        eprintln!();
        if is_new {
            eprintln!("🔑 Here's your shiny new YubiKey recipient:");
        } else {
            eprintln!("🔑 Here's the corresponding YubiKey recipient:");
        }
        eprintln!("  {}", recipient);
        eprintln!();
        eprintln!("Here are some example things you can do with it:");
        eprintln!();
        eprintln!("- Encrypt a file to this identity:");
        eprintln!(
            "  $ cat foo.txt | {} -r {} -o foo.txt.age",
            age_binary, recipient
        );
        eprintln!();
        eprintln!("- Decrypt a file with this identity:");
        eprintln!(
            "  $ cat foo.txt.age | {} -d -i {} > foo.txt",
            age_binary, file_name
        );
        eprintln!();
        eprintln!("- Recreate the identity file:");
        eprintln!(
            "  $ age-plugin-yubikey -i --serial {} --slot {} > {}",
            stub.serial,
            util::slot_to_ui(&stub.slot),
            file_name,
        );
        eprintln!();
        eprintln!("- Recreate the recipient:");
        eprintln!(
            "  $ age-plugin-yubikey -l --serial {} --slot {}",
            stub.serial,
            util::slot_to_ui(&stub.slot),
        );
        eprintln!();
        eprintln!("💭 Remember: everything breaks, have a backup plan for when this YubiKey does.");

        Ok(())
    }
}
