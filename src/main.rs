use age_plugin::run_state_machine;
use gumdrop::Options;

mod error;
mod plugin;

use error::Error;

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

    #[options(help = "Generate a new YubiKey identity.")]
    generate: bool,

    #[options(help = "Print the identity stored in a YubiKey slot.")]
    identity: bool,

    #[options(help = "List all age identities in connected YubiKeys.")]
    list: bool,

    #[options(help = "List all YubiKey keys that are compatible with age.", no_short)]
    list_all: bool,
}

fn main() -> Result<(), Error> {
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
        todo!()
    } else if opts.identity {
        todo!()
    } else if opts.list {
        todo!()
    } else if opts.list_all {
        todo!()
    } else {
        // TODO: CLI identity generation
        Ok(())
    }
}
