mod codegen;

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
}

fn main() {
    let opts = Options::parse();

    use Command::*;
    let ret = match opts.command {
        Codegen => codegen::generate(),
    };

    if let Err(e) = ret {
        eprintln!("{:#}", e);
        exit(1);
    }
}
