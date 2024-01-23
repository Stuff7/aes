use aes::*;
use std::{
  env,
  error::Error,
  fs,
  io::{self, Write},
  str::FromStr,
};

fn main() -> Result<(), Box<dyn Error>> {
  let cli = Cli::read()?;
  let mut buf = read_as_block(&cli.input)?;
  let mut aes = AESContext::new(&cli.password);

  if let Some(path) = cli.encrypted {
    aes.encrypt_with_iv(&mut buf);
    fs::write(path, &buf)?;
  }

  if let Some(path) = cli.decrypted {
    aes.decrypt_with_iv(&mut buf);
    fs::write(path, &buf)?;
  }

  Ok(())
}

pub struct Cli {
  input: String,
  password: String,
  encrypted: Option<String>,
  decrypted: Option<String>,
}

impl Cli {
  pub fn read() -> Result<Self, String> {
    let mut args = env::args();
    let exe = args.next().ok_or("Missing executable")?;
    let input = args
      .next()
      .ok_or_else(|| format!("Usage {exe} <input_file> -e <encrypt_to> -d <decrypt_to>"))?;
    let encrypted = Self::find_arg("-e");
    let decrypted = Self::find_arg("-d");

    if encrypted.is_none() && decrypted.is_none() {
      return Err("Nothing to be done, at least one of these is needed: -e <encrypt_to> -d <decrypt_to>".to_owned());
    }

    Ok(Self {
      input,
      encrypted,
      decrypted,
      password: Self::password_prompt().map_err(|err| err.to_string())?,
    })
  }

  fn password_prompt() -> io::Result<String> {
    print!("Password: ");
    io::stdout().flush()?;
    let mut password = String::new();
    io::stdin().read_line(&mut password)?;
    password.pop();
    Ok(password)
  }

  fn find_arg<F: FromStr + Default>(arg_name: &str) -> Option<F> {
    let mut args = env::args();
    args
      .position(|arg| arg == arg_name)
      .and_then(|_| args.next())
      .and_then(|n| n.parse::<F>().ok())
  }
}
