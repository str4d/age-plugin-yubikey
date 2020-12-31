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
}

fn main() -> Result<(), Error> {
    let opts = PluginOptions::parse_args_default_or_exit();

    if let Some(state_machine) = opts.age_plugin {
        run_state_machine(
            &state_machine,
            || plugin::RecipientPlugin::default(),
            || plugin::IdentityPlugin::default(),
        )?;
        Ok(())
    } else {
        // TODO: CLI identity generation
        Ok(())
    }
}
