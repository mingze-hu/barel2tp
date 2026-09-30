use std::{env, fs, net::Ipv4Addr, path::Path, time::Duration};

use anyhow::{Context, Result, bail};
use ipnet::Ipv4Net;
use serde::Deserialize;
use zeroize::Zeroizing;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: String,

    #[serde(default = "default_port")]
    pub port: u16,

    pub username: String,

    #[serde(default)]
    password: Option<String>,

    #[serde(default)]
    password_env: Option<String>,

    /// Required, with no built-in default; `routes = []` means no subnet routes are added.
    pub routes: Vec<Ipv4Net>,

    #[serde(default = "default_mtu")]
    pub mtu: u16,

    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u64,

    #[serde(default = "default_retries")]
    pub retries: u32,

    #[serde(default = "default_hello_interval_seconds")]
    pub hello_interval_seconds: u64,

    #[serde(default)]
    pub request_dns: bool,

    #[serde(default)]
    pub local_bind: Option<Ipv4Addr>,

    #[serde(default)]
    pub local_port: u16,

    #[serde(default)]
    pub hostname: Option<String>,
}

fn default_port() -> u16 {
    1701
}

fn default_mtu() -> u16 {
    1400
}

fn default_timeout_seconds() -> u64 {
    3
}

fn default_retries() -> u32 {
    5
}

fn default_hello_interval_seconds() -> u64 {
    30
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let source = fs::read_to_string(path)
            .with_context(|| format!("failed to read config file {}", path.display()))?;
        let config: Self = toml::from_str(&source)
            .with_context(|| format!("invalid config file {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.server.trim().is_empty() {
            bail!("server must not be empty");
        }
        if self.username.is_empty() {
            bail!("username must not be empty");
        }
        if self.mtu < 576 || self.mtu > 1500 {
            bail!("mtu must be between 576 and 1500");
        }
        if self.timeout_seconds == 0 {
            bail!("timeout_seconds must be greater than 0");
        }
        if self.retries == 0 {
            bail!("retries must be greater than 0");
        }
        if self.hello_interval_seconds == 0 {
            bail!("hello_interval_seconds must be greater than 0");
        }
        if self.password.is_some() && self.password_env.is_some() {
            bail!("only one of password and password_env may be set");
        }
        Ok(())
    }

    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_seconds)
    }

    pub fn hello_interval(&self) -> Duration {
        Duration::from_secs(self.hello_interval_seconds)
    }

    pub fn client_hostname(&self) -> String {
        self.hostname.clone().unwrap_or_else(|| {
            env::var("HOSTNAME")
                .ok()
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "barel2tp".to_owned())
        })
    }

    pub fn take_password(&mut self) -> Result<Option<Zeroizing<String>>> {
        if let Some(password) = self.password.take() {
            if password.is_empty() {
                bail!("password must not be empty");
            }
            return Ok(Some(Zeroizing::new(password)));
        }

        let variable = self.password_env.as_deref().unwrap_or("BAREL2TP_PASSWORD");
        match env::var(variable) {
            Ok(password) if password.is_empty() => {
                bail!("password environment variable {variable} must not be empty");
            }
            Ok(password) => Ok(Some(Zeroizing::new(password))),
            Err(env::VarError::NotPresent) => Ok(None),
            Err(env::VarError::NotUnicode(_)) => {
                bail!("password environment variable {variable} is not valid UTF-8")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_out_of_range_mtu() {
        let config: Config = toml::from_str(
            r#"
            server = "vpn.example.com"
            username = "user"
            routes = []
            password = "secret"
            mtu = 1600
            "#,
        )
        .unwrap();

        assert!(config.validate().is_err());
    }

    #[test]
    fn reads_defaults() {
        let config: Config = toml::from_str(
            r#"
            server = "vpn.example.com"
            username = "user"
            routes = []
            password = "secret"
            "#,
        )
        .unwrap();

        assert_eq!(config.port, 1701);
        assert_eq!(config.mtu, 1400);
        assert_eq!(config.hello_interval_seconds, 30);
    }

    #[test]
    fn routes_must_be_configured_explicitly() {
        let error = toml::from_str::<Config>(
            r#"
            server = "vpn.example.com"
            username = "user"
            password = "secret"
            "#,
        )
        .unwrap_err();

        assert!(error.to_string().contains("routes"));
    }

    #[test]
    fn missing_env_var_allows_interactive_input() {
        let mut config: Config = toml::from_str(
            r#"
            server = "vpn.example.com"
            username = "user"
            routes = []
            password_env = "BAREL2TP_TEST_PASSWORD_THAT_MUST_NOT_EXIST"
            "#,
        )
        .unwrap();

        assert!(config.take_password().unwrap().is_none());
    }

    #[test]
    fn rejects_disabling_l2tp_keepalive() {
        let config: Config = toml::from_str(
            r#"
            server = "vpn.example.com"
            username = "user"
            routes = []
            hello_interval_seconds = 0
            "#,
        )
        .unwrap();

        assert!(config.validate().is_err());
    }
}
