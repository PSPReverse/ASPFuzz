use chrono::Local;
use clap::{command, Parser};

use libasp::config::{borrow_global_conf, init_global_conf};

use std::{
    env, fs, io,
    path::{Path, PathBuf},
    process::exit,
};

/// Fuzzing the on-chip-bootloader from different AMD Zen generations.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)] // Read from Cargo.toml
struct Args {
    /// YAML config file path
    #[arg(short, long)]
    yaml_path: PathBuf,

    /// Run directory name
    #[arg(short, long)]
    run_dir_name: Option<String>,

    /// Number of cores
    #[arg(short, long)]
    num_cores: Option<u32>,
}

pub fn setup_directory_structure(
    run_dir: &PathBuf,
    original_path: &Path,
) -> Result<(PathBuf, PathBuf, PathBuf), io::Error> {
    if run_dir.exists() {
        fs::remove_dir_all(run_dir)?;
    }
    fs::create_dir_all(run_dir)?;
    let mut input_dir = run_dir.clone();
    input_dir.push("inputs");
    fs::create_dir_all(&input_dir)?;
    let mut log_dir = run_dir.clone();
    log_dir.push("logs");
    fs::create_dir_all(&log_dir)?;
    let mut solutions_dir = run_dir.clone();
    solutions_dir.push("solutions");
    fs::create_dir_all(&solutions_dir)?;
    let mut config_path = run_dir.clone();
    config_path.push("config.yaml");

    fs::copy(original_path, &config_path)?;

    Ok((input_dir, log_dir, solutions_dir))
}

pub fn parse_args() -> Vec<String> {
    let cli_args = Args::parse();
    // Parse YAML config
    if !cli_args.yaml_path.exists() {
        log::error!(
            "YAML file path does not exist: {}",
            cli_args.yaml_path.display()
        );
        exit(2);
    }
    let date = Local::now();
    let run_dir = if let Some(run_dir_name) = cli_args.run_dir_name {
        PathBuf::from(format!("runs/{run_dir_name}"))
    } else {
        PathBuf::from(format!("runs/{}", date.format("%Y-%m-%d_%H:%M")))
    };
    let num_cores = if let Some(num_cores) = cli_args.num_cores {
        num_cores
    } else {
        log::error!(
            "For multicore fuzzing a core number must be provided (`cargo make run_fast -h`)"
        );
        exit(3);
    };
    init_global_conf(&cli_args.yaml_path, num_cores, run_dir.clone());
    let conf = borrow_global_conf().unwrap();

    //Check if pathes exist
    if !conf.qemu.on_chip_bl_path.exists() {
        log::error!(
            "On-chip-bl file path does not exist: {}",
            conf.qemu.on_chip_bl_path.display()
        );
        exit(4);
    }
    if !conf.flash.base.exists() {
        log::error!(
            "UEFI file path does not exist: {}",
            &conf.flash.base.display()
        );
        exit(5);
    }

    // Create arguments to start QEMU with
    let mut qemu_args: String = env::args().next().unwrap();
    log::debug!("QEMU arguments: {qemu_args:?}");
    if conf.debug {
        qemu_args += " -d trace:ccp_*,trace:psp_*,guest_errors,unimp,trace:psp_x86_misc_write";
        qemu_args += &format![" -D {}/logs/qemu.log", run_dir.display()];
        if num_cores == 0 {
            qemu_args += " -chardev socket,id=mon0,host=127.0.0.1,port=4444,server=on,wait=off -monitor chardev:mon0";
        }
        log::info!("Debug mode enabled");
    }
    if num_cores != 0 || !conf.debug {
        qemu_args += " -monitor none";
    }
    let project_dir = env::var("PROJECT_DIR").expect("PROJECT_DIR not set");
    qemu_args += &format![" --machine {}", conf.qemu.zen.get_qemu_machine_name(),];
    qemu_args += " --nographic";
    qemu_args += &format!(
        " -device loader,file={}/{},addr=0xffff0000,force-raw=on",
        project_dir,
        &conf.qemu.on_chip_bl_path.display()
    );
    qemu_args += &format!(
        " -global driver=amd_psp.smnflash,property=flash_img,value={}/{}",
        project_dir,
        &conf.flash.base.display()
    );
    qemu_args += &format![" -bios {}/{}", project_dir, &conf.flash.base.display()];
    // As the access observer degrades emulation acccuracy and performance, only enable it if required
    if conf.crashes.x86.is_some() {
        qemu_args += " -global driver=amd_psp.x86.mapper,property=use_access_observer,value=true";
    }
    log::debug!("Full QEMU arguments: {qemu_args:?}");
    shlex::Shlex::new(&qemu_args).collect::<Vec<String>>()
}
