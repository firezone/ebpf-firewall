use anyhow::Result;
use std::fs::{self, File};
use std::io::Write;
use std::process::Command;

use crate::RunOn;
use phf::phf_map;
use tempfile::{tempdir, TempDir};

const VAGRANT_FILE: &str = r#"
# -*- mode: ruby -*-
# vi: set ft=ruby :
Vagrant.configure("2") do |config|
  config.vm.box = "{box}"
  config.vm.synced_folder "{target}/x86_64-unknown-linux-musl/{target_source}/examples", "/bin/", type: "rsync",
    rsync__args: ["-r", "--include=ci-run", "--exclude=*"]
end
"#;

const KERNEL_VERSION: phf::Map<&'static str, &'static str> = phf_map! {
    "5.15" => "generic/alpine317",
    "5.10" => "generic/alpine313",
    "5.4" => "generic/alpine312",
    "4.18" => "generic/centos8",
};

fn get_file(version: &str, target_dir: &str, target_source: &str) -> Result<String> {
    Ok(VAGRANT_FILE
        .replace(
            "{box}",
            KERNEL_VERSION
                .get(version)
                .ok_or_else(|| anyhow::format_err!("Kernel version {} not supported", version))?,
        )
        .replace("{target}", target_dir)
        .replace("{target_source}", target_source))
}

pub fn run_on(params: RunOn) -> Result<()> {
    let target_source = if params.release { "release" } else { "debug" };
    let target_dir = fs::canonicalize("./target")?;
    let version = params.version;
    let mut vagrant = Vagrant::new(get_file(
        &version,
        &target_dir.to_string_lossy(),
        target_source,
    )?)?;
    println!("Running kernel version:");
    vagrant.kernel_version()?;
    vagrant.run_on("sudo /bin/ci-run")?;
    Ok(())
}

struct Vagrant {
    temp_dir: TempDir,
}

impl Vagrant {
    fn new(contents: String) -> Result<Self> {
        let temp_dir = tempdir()?;
        let file_path = temp_dir.path().join("Vagrantfile");
        let mut file = File::create(file_path)?;
        writeln!(file, "{}", contents)?;

        let mut this = Self { temp_dir };
        this.run(&["up"])?;
        Ok(this)
    }

    fn run(&mut self, args: &[&str]) -> Result<(), anyhow::Error> {
        Command::new("vagrant")
            .args(args)
            .current_dir(&self.temp_dir)
            .status()?;
        Ok(())
    }

    fn run_on(&mut self, cmd: &str) -> Result<(), anyhow::Error> {
        self.run(&["ssh", "-c", cmd])
    }

    fn kernel_version(&mut self) -> Result<(), anyhow::Error> {
        self.run_on("uname -r")
    }
}

impl Drop for Vagrant {
    fn drop(&mut self) {
        // Ignoring result in destructor is fineee
        let _ = self.run(&["destroy", "-f"]);
    }
}
