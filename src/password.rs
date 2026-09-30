use std::io::BufRead;

use anyhow::{Context, Result, bail};
use zeroize::Zeroizing;

/// Reads one password line from any buffered input, so the GUI can pass it in safely through a
/// pipe.
pub fn read_password_line(mut input: impl BufRead) -> Result<Zeroizing<String>> {
    let mut password = Zeroizing::new(String::new());
    input
        .read_line(&mut password)
        .context("failed to read the VPN password")?;
    while password.ends_with(['\n', '\r']) {
        password.pop();
    }
    if password.is_empty() {
        bail!("the VPN password must not be empty");
    }
    Ok(password)
}

/// Reads the password from the controlling terminal without echoing it.
pub fn prompt_password(prompt: &str) -> Result<Zeroizing<String>> {
    let password = rpassword::prompt_password(prompt)
        .context("cannot read the password from the controlling terminal; set the password environment variable and try again")?;
    if password.is_empty() {
        bail!("the VPN password must not be empty");
    }
    Ok(Zeroizing::new(password))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_password_and_strips_newline() {
        let password = read_password_line("secret\r\n".as_bytes()).unwrap();
        assert_eq!(password.as_str(), "secret");
    }

    #[test]
    fn rejects_empty_password() {
        assert!(read_password_line("\n".as_bytes()).is_err());
    }
}
