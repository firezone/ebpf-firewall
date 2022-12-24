mod codegen;
mod run_on;

use std::process::exit;

use clap::Parser;

#[derive(Debug, Parser)]
pub struct Options {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Parser)]
enum Command {
    Codegen,
    RunOn(RunOn),
}

#[derive(Debug, Parser)]
pub struct RunOn {
    version: String,
    #[arg(long)]
    release: bool,
}

fn main() {
    let opts = Options::parse();

    use Command::*;
    let ret = match opts.command {
        Codegen => codegen::generate(),
        RunOn(params) => run_on::run_on(params),
    };

    if let Err(e) = ret {
        eprintln!("{e:#}");
        exit(1);
    }
}
