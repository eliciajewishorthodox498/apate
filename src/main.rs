use std::path::PathBuf;
use std::process;

use clap::{Parser, Subcommand};
use colored::Colorize;

use apate::error::ApateError;
use apate::key;
use apate::manifest;
use apate::passes::{self, ObfuscationLevel};
use apate::pipeline::Pipeline;

const BANNER: &str = r#" ▄▄▄       ██▓███   ▄▄▄     ▄▄▄█████▓▓█████
▒████▄    ▓██░  ██▒▒████▄   ▓  ██▒ ▓▒▓█   ▀
▒██  ▀█▄  ▓██░ ██▓▒▒██  ▀█▄ ▒ ▓██░ ▒░▒███
░██▄▄▄▄██ ▒██▄█▓▒ ▒░██▄▄▄▄██░ ▓██▓ ░ ▒▓█  ▄
 ▓█   ▓██▒▒██▒ ░  ░ ▓█   ▓██▒ ▒██▒ ░ ░▒████▒
 ▒▒   ▓▒█░▒▓▒░ ░  ░ ▒▒   ▓▒█░ ▒ ░░   ░░ ▒░ ░
  ▒   ▒▒ ░░▒ ░       ▒   ▒▒ ░   ░     ░ ░  ░
  ░   ▒   ░░         ░   ▒    ░         ░
      ░  ░               ░  ░           ░  ░"#;

#[derive(Parser)]
#[command(
    name = "apate",
    about = "Keyed reversible source code obfuscator",
    long_version = concat!(env!("CARGO_PKG_VERSION"), " — Goddess of deceit"),
    before_help = BANNER,
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Obfuscate a Rust source file or crate directory
    Encrypt {
        /// Input file or directory
        #[arg(short, long)]
        input: PathBuf,

        /// Output file or directory
        #[arg(short, long)]
        output: PathBuf,

        /// Path to 256-bit key file
        #[arg(short, long)]
        key: PathBuf,

        /// Comma-separated list of passes (overrides --level)
        #[arg(long, value_delimiter = ',')]
        passes: Option<Vec<String>>,

        /// Obfuscation level: 1 (mild), 2 (spicy), 3 (diabolical)
        #[arg(long, default_value = "1")]
        level: u8,

        /// Preserve bare `pub` items (external API boundary)
        #[arg(long)]
        preserve_public: bool,
    },

    /// Restore obfuscated source to its original form
    Decrypt {
        /// Input obfuscated file or directory
        #[arg(short, long)]
        input: PathBuf,

        /// Output restored file or directory
        #[arg(short, long)]
        output: PathBuf,

        /// Path to 256-bit key file
        #[arg(short, long)]
        key: PathBuf,
    },

    /// Generate a new 256-bit random key
    Keygen {
        /// Output key file path
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Verify that obfuscated code roundtrips to the original
    Verify {
        /// Path to original source file or directory
        #[arg(long)]
        original: PathBuf,

        /// Path to obfuscated source file or directory
        #[arg(long)]
        obfuscated: PathBuf,

        /// Path to 256-bit key file
        #[arg(short, long)]
        key: PathBuf,
    },
}

fn print_banner() {
    println!("{}", BANNER.magenta());
    println!(
        "  {} {}\n",
        format!("v{}", env!("CARGO_PKG_VERSION")).bright_magenta(),
        "— goddess of deceit".dimmed()
    );
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    print_banner();

    match cli.command {
        Commands::Keygen { output } => {
            let k = key::generate_key();
            key::save_key(&k, &output)?;
            println!(
                "  {} Generated 256-bit key → {}",
                "✓".green().bold(),
                output.display().to_string().bright_white()
            );
        }

        Commands::Encrypt {
            input,
            output,
            key: key_path,
            passes: explicit_passes,
            level,
            preserve_public,
        } => {
            let master_key = key::load_key(&key_path)?;
            let obfuscation_level = ObfuscationLevel::from_u8(level).ok_or_else(|| {
                ApateError::PassFailed {
                    pass: "cli".into(),
                    reason: format!("invalid level {level} (must be 1-3)"),
                }
            })?;

            let pass_names =
                passes::resolve_passes(Some(obfuscation_level), explicit_passes.as_deref());

            let mut pipeline = Pipeline::new(master_key, pass_names.clone());
            pipeline.preserve_public = preserve_public;

            let is_dir = input.is_dir();
            let m = if is_dir {
                pipeline.encrypt_crate(&input, &output)?
            } else {
                pipeline.encrypt_single(&input, &output)?
            };

            // Save manifest
            let manifest_path = if is_dir {
                output.join("manifest.apate")
            } else {
                output.with_extension("apate")
            };
            let encrypted = manifest::encrypt_manifest(&m, &master_key)?;
            manifest::save_manifest(&encrypted, &manifest_path)?;

            let level_name = match obfuscation_level {
                ObfuscationLevel::Mild => "Mild",
                ObfuscationLevel::Spicy => "Spicy",
                ObfuscationLevel::Diabolical => "Diabolical",
            };

            println!(
                "  {} Encrypted ({}) → {}",
                "✓".green().bold(),
                level_name.yellow(),
                output.display().to_string().bright_white()
            );
            println!(
                "  {} Manifest → {}",
                "✓".green().bold(),
                manifest_path.display().to_string().bright_white()
            );
            println!(
                "  {} Passes: {}{}",
                "·".dimmed(),
                pass_names.join(", ").dimmed(),
                if preserve_public {
                    " (preserving pub)".dimmed().to_string()
                } else {
                    String::new()
                }
            );
            if is_dir {
                println!(
                    "  {} {} files processed",
                    "·".dimmed(),
                    m.files.len().to_string().bright_white()
                );
            }
        }

        Commands::Decrypt {
            input,
            output,
            key: key_path,
        } => {
            let master_key = key::load_key(&key_path)?;
            let pipeline = Pipeline::new(master_key, Vec::new());

            if input.is_dir() {
                let manifest_path = input.join("manifest.apate");
                let encrypted = manifest::load_manifest(&manifest_path)?;
                let m = manifest::decrypt_manifest(&encrypted, &master_key)?;
                let file_count = m.files.len();
                pipeline.decrypt_crate(&input, &output, &m)?;
                println!(
                    "  {} Decrypted {} files → {}",
                    "✓".green().bold(),
                    file_count,
                    output.display().to_string().bright_white()
                );
            } else {
                let manifest_path = input.with_extension("apate");
                pipeline.decrypt_single(&input, &output, &manifest_path)?;
                println!(
                    "  {} Decrypted → {}",
                    "✓".green().bold(),
                    output.display().to_string().bright_white()
                );
            }
        }

        Commands::Verify {
            original,
            obfuscated,
            key: key_path,
        } => {
            let master_key = key::load_key(&key_path)?;
            let pipeline = Pipeline::new(master_key, Vec::new());

            if original.is_dir() {
                let manifest_path = obfuscated.join("manifest.apate");
                let results = pipeline.verify_crate(&original, &obfuscated, &manifest_path)?;
                let all_pass = results.iter().all(|(_, ok)| *ok);
                for (path, ok) in &results {
                    if *ok {
                        println!(
                            "  {} {}",
                            "✓".green().bold(),
                            path.display()
                        );
                    } else {
                        println!(
                            "  {} {} — hash mismatch",
                            "✗".red().bold(),
                            path.display()
                        );
                    }
                }
                if all_pass {
                    println!("\n  {} All files verified", "✓".green().bold());
                } else {
                    println!("\n  {} Verification failed", "✗".red().bold());
                    process::exit(1);
                }
            } else {
                let manifest_path = obfuscated.with_extension("apate");
                let ok = pipeline.verify_file(&original, &obfuscated, &manifest_path)?;
                if ok {
                    println!("  {} Roundtrip verified", "✓".green().bold());
                } else {
                    println!("  {} Roundtrip verification failed — hash mismatch", "✗".red().bold());
                    process::exit(1);
                }
            }
        }
    }

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        print_banner();
        eprintln!("  {} {}", "✗".red().bold(), format!("{e}").red());
        process::exit(1);
    }
}
