mod crypto;
use anyhow::{anyhow, Context};
use clap::Parser;
use crypto::{decrypt, encrypt, Key};
use rand::{thread_rng, Rng};
use std::{
    fs,
    io::{stdout, Write},
    path::PathBuf,
};

const DEFAULT_KEYFILE: &str = ".config/rhinopuffin/keyfile";

#[derive(Debug, Parser)]
#[clap(name = "rhinopuffin")]
#[clap(about = "A simple cli tool for encrypting and decrypting files with symmetric encryption.")]
#[clap(author = "https://ariel.ninja")]
#[clap(version)]
struct Args {
    /// Input file
    #[arg()]
    file: PathBuf,
    /// Decrypt (encrypt by default)
    #[arg(short, long)]
    decrypt: bool,
    /// Output file
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Encryption/decryption key file
    #[arg(short, long)]
    key_file: Option<String>,
    /// Use encryption/decryption key string instead of key file
    #[arg(short, long)]
    raw_key: Option<String>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    // get key
    let key = if let Some(key) = args.raw_key {
        Key::new(key)?
    } else {
        let file = if let Some(keyfile) = args.key_file {
            PathBuf::from(keyfile)
        } else {
            let mut keyfile =
                homedir::get_my_home()?.ok_or_else(|| anyhow!("get home directory"))?;
            keyfile.push(DEFAULT_KEYFILE);
            if !keyfile.exists() {
                let config_dir = keyfile
                    .parent()
                    .ok_or_else(|| anyhow!("internal config dir error"))?;
                fs::create_dir_all(config_dir).context("create config directory")?;
                let key_data: [u8; 32] = thread_rng().gen();
                fs::write(&keyfile, key_data).context("create new default key file")?;
            }
            keyfile
        };
        let key_data = fs::read(file).context("read key file")?;
        Key::new(key_data)?
    };
    // get data
    let input_data = fs::read(args.file).context("read input file")?;
    // perform encryption/decryption
    let output_data = if args.decrypt {
        decrypt(&input_data, key)?
    } else {
        encrypt(&input_data, key)?
    };
    // output
    if let Some(path) = args.output {
        fs::write(path, &output_data).context("write output file")?;
    } else {
        stdout()
            .write_all(&output_data)
            .context("write to stdout")?;
        stdout().flush().context("flush stdout")?;
    }
    Ok(())
}
