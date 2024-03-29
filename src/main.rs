mod crypto;
use anyhow::Context;
use clap::Parser;
use console::Key;
use std::{
    fs,
    io::{stderr, stdout, Read, Write},
    path::PathBuf,
};

#[derive(Debug, Parser)]
#[clap(name = "rhinopuffin")]
#[clap(about = "A simple cli tool for encrypting and decrypting files with symmetric encryption.")]
#[clap(author = "https://ariel.ninja")]
#[clap(version)]
struct Args {
    /// Input file (omit to read from stdin)
    #[arg()]
    file: Option<PathBuf>,
    /// Decrypt (encrypt by default)
    #[arg(short, long)]
    decrypt: bool,
    /// Output file
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Use a file as encryption/decryption key
    #[arg(short, long)]
    key_file: Option<PathBuf>,
    /// Use encryption/decryption key string instead of prompting
    #[arg(short, long)]
    raw_key: Option<String>,
    /// Remove input file
    #[arg(short = 'D', long)]
    delete: bool,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // get data
    let input_data = if let Some(file) = &args.file {
        fs::read(file).context("read input file")?
    } else {
        let mut data = Vec::new();
        let mut stdin = std::io::stdin().lock();
        stdin.read_to_end(&mut data).context("read stdin")?;
        data
    };

    // get key
    let key = if let Some(raw_key) = args.raw_key {
        crypto::Key::new(raw_key)?
    } else if let Some(key_file) = args.key_file {
        let key_data = fs::read(key_file).context("read key file")?;
        crypto::Key::new(key_data)?
    } else {
        let raw_key = prompt("Encryption password: ")?;
        crypto::Key::new(raw_key)?
    };

    // perform encryption/decryption
    let output_data = if args.decrypt {
        crypto::decrypt(&input_data, key)?
    } else {
        crypto::encrypt(&input_data, key)?
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

    if args.delete {
        if let Some(file) = &args.file {
            std::fs::remove_file(file).context("remove input file")?;
        }
    }
    Ok(())
}

fn prompt(prompt_text: &str) -> anyhow::Result<String> {
    let mut input = String::new();
    eprint!("{prompt_text}");
    stderr().flush().context("flush stdout")?;
    loop {
        let term = console::Term::stderr();
        let character = term.read_key().context("read key from terminal")?;
        match character {
            Key::Enter => {
                eprintln!();
                break;
            }
            Key::Char(c) => {
                input.push(c);
                eprint!("*");
                stderr().flush().context("flush stdout")?;
            }
            Key::Backspace => {
                if !input.is_empty() {
                    term.clear_chars(1).context("clear character")?;
                }
                input.pop();
            }
            _other_key => continue,
        };
    }
    Ok(input)
}
