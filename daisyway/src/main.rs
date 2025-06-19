use std::{io::stdout, path::PathBuf};

use anyhow::{bail, ensure, Context, Result};
use clap::{CommandFactory, Parser};
use daisyway::{Daisyway, DaisywayConfig};
use log::{debug, info};
use shadow_rs::shadow;
use tokio::{self, io::AsyncWriteExt};

shadow!(build);

// TODO: PossibleValue inference is somehow broken if we use log::Level directly. Can we fix this?
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
enum LogLevel {
    Nothing,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl From<LogLevel> for log::LevelFilter {
    fn from(value: LogLevel) -> Self {
        use log::LevelFilter as T;
        use LogLevel as F;
        match value {
            F::Nothing => T::Off,
            F::Error => T::Error,
            F::Warn => T::Warn,
            F::Info => T::Info,
            F::Debug => T::Debug,
            F::Trace => T::Trace,
        }
    }
}

#[derive(Debug, Parser)]
#[command(author, about, version = build::CLAP_LONG_VERSION, long_about, arg_required_else_help = true)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Lowest log level to show
    #[arg(long = "log-level", value_name = "LOG_LEVEL", group = "log-level")]
    log_level: Option<LogLevel>,

    /// Show verbose log output – sets log level to "debug"
    #[arg(short, long, group = "log-level")]
    verbose: bool,

    /// Show no log output – sets log level to "error"
    #[arg(short, long, group = "log-level")]
    quiet: bool,
}

impl Cli {
    async fn init_logging(&self) -> Result<()> {
        let mut log_builder = env_logger::Builder::from_default_env(); // sets log level filter from environment (or defaults)

        // Use warn as the default level
        if std::env::var("RUST_LOG").is_err() {
            log_builder.filter_level(log::Level::Warn.to_level_filter());
        }

        // Read log level from command line if specified
        if let Some(filter) = self.log_level_filter() {
            log_builder.filter_level(filter); // set log level filter from CLI args if available
        }

        log_builder.try_init()?;

        Ok(())
    }

    async fn run(&self) -> Result<()> {
        match &self.command {
            Some(cmd) => cmd.run(self).await,
            None => {
                // Caught automatically by clap; should not happen
                bail!("No command specified");
            }
        }
    }

    /// returns the log level filter set by CLI args
    /// returns `None` if the user did not specify any log level filter via CLI
    ///
    /// NOTE: the clap feature of ["argument groups"](https://docs.rs/clap/latest/clap/_derive/_tutorial/chapter_3/index.html#argument-relations)
    /// ensures that the user can not specify more than one of the possible log level arguments.
    /// Note the `#[arg("group")]` in the [`CliArgs`] struct.
    pub fn log_level_filter(&self) -> Option<log::LevelFilter> {
        if self.verbose {
            return Some(log::LevelFilter::Info);
        }
        if self.quiet {
            return Some(log::LevelFilter::Warn);
        }
        if let Some(level) = self.log_level {
            return Some(level.into());
        }
        None
    }
}

#[derive(Debug, clap::Subcommand)]
enum Commands {
    Exchange(ExchangeCommand),
    Manpage(ManpageCommand),
    ExportManpages(ExportManpagesCommand),
    ShellCompletion(ShellCompletion),
}

impl Commands {
    async fn run(&self, cli: &Cli) -> Result<()> {
        use Commands as C;
        match self {
            C::Exchange(cmd) => cmd.run(cli).await,
            C::Manpage(cmd) => cmd.run(cli).await,
            C::ExportManpages(cmd) => cmd.run(cli).await,
            C::ShellCompletion(cmd) => cmd.run(cli).await,
        }
    }
}

/// Show the Daisyway manual page
#[derive(Debug, Clone, clap::Args)]
struct ManpageCommand {
    // Which manpage to display
    selection: ManpageSelection,
    // Whether to pipe the output through the man command.
    //
    // If this option is set to false, then this command will output raw groff output.
    #[clap(long, default_value_t = false)]
    dont_invoke_man: bool,
}

// TODO: We should be able to autogenerate this
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
enum ManpageSelection {
    #[clap(alias = "daisyway(1)")]
    Daisyway,
    #[clap(alias = "daisyway-exchange(1)", alias = "daisyway-exchange")]
    Exchange,
    #[clap(alias = "daisyway-manpage(1)", alias = "daisyway-manpage")]
    Manpage,
    #[clap(
        alias = "daisyway-export-manpages(1)",
        alias = "daisyway-export-manpages"
    )]
    ExportManpages,

    #[clap(
        alias = "daisyway-shell-completion(1)",
        alias = "daisyway-shell-completion"
    )]
    ShellCompletion,
    #[clap(alias = "daisyway-help(1)", alias = "daisyway-help")]
    Help,
}

impl ManpageCommand {
    async fn run(&self, cli: &Cli) -> Result<()> {
        let mut cmd = Cli::command();
        cmd.build();

        let cmd = self
            .selected_command(cli, &cmd)
            .context("Could not retrieve command for manpage – this is a bug.")
            .unwrap();

        if self.dont_invoke_man {
            clap_mangen::Man::new(cmd.clone()).render(&mut stdout().lock())?;
        } else {
            let mut proc = tokio::process::Command::new("man")
                .args(["--local-file", "-"])
                .kill_on_drop(true)
                .stdin(std::process::Stdio::piped())
                .spawn()
                .context("Failed to start `man` command.")?;

            let mut buf = Vec::new();
            clap_mangen::Man::new(cmd.clone()).render(&mut buf)?;

            let stdin = proc
                .stdin
                .as_mut()
                .context("Stdout missin from manpage command. This is a bug")
                .unwrap();
            stdin.write_all(&buf).await?;

            let status = proc.wait().await?;
            ensure!(
                status.success(),
                "`man` command exited unsuccessfully, with exit code {:?}",
                status.code()
            );
        }

        Ok(())
    }

    fn selected_command<'a>(
        &self,
        _cli: &Cli,
        cmd: &'a clap::Command,
    ) -> Option<&'a clap::Command> {
        use ManpageSelection as S;
        match self.selection {
            S::Daisyway => Some(cmd),
            S::Exchange => cmd.find_subcommand("exchange"),
            S::Manpage => cmd.find_subcommand("manpage"),
            S::ExportManpages => cmd.find_subcommand("export-manpages"),
            S::ShellCompletion => cmd.find_subcommand("shell-comletion"),
            S::Help => cmd.find_subcommand("help"),
        }
    }
}

/// Export all the manpages into a directory
#[derive(Debug, Clone, clap::Args)]
struct ExportManpagesCommand {
    /// The directory to write the man pages into
    destination: PathBuf,
}

impl ExportManpagesCommand {
    async fn run(&self, _cli: &Cli) -> Result<()> {
        let mut cmd = Cli::command();
        cmd.build();

        clap_mangen::generate_to(cmd.clone(), &self.destination)?;

        Ok(())
    }
}

/// Produce shell completion files
#[derive(Debug, Clone, clap::Args)]
struct ShellCompletion {
    shell: clap_complete::Shell,
}

impl ShellCompletion {
    async fn run(&self, _cli: &Cli) -> Result<()> {
        let mut cmd = Cli::command();
        cmd.build();

        let bin_name = std::env::current_exe()
            .unwrap()
            .to_str()
            .context("Could not convert command binary name to string? UTF-8 woes?")
            .unwrap()
            .to_string();

        clap_complete::generate(
            self.shell,
            &mut cmd,
            bin_name,
            &mut std::io::stdout().lock(),
        );

        Ok(())
    }
}

/// Run the Daisyway QKD & WireGuard VPN using the given configuration file
#[derive(Debug, clap::Args)]
struct ExchangeCommand {
    #[arg(long, short)]
    config: PathBuf,
}

impl ExchangeCommand {
    async fn run(&self, _cli: &Cli) -> Result<()> {
        info!(
            "Starting DaisyWay ({}{}/{}) with config {:?}...",
            build::SHORT_COMMIT,                          // The short commit hash
            if build::GIT_CLEAN { "" } else { "-dirty" }, // Append "-dirty" if the repo is dirty
            build::BRANCH,                                // The branch name
            &self.config
        );

        let config = DaisywayConfig::load_from_file(&self.config).await?;
        debug!("Loaded config: {:#?}", config);

        Daisyway::from_config(&config).await?.event_loop().await
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    cli.init_logging().await?;
    cli.run().await
}
