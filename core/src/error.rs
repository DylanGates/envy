use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("vault database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("vault config error: {0}")]
    Config(#[from] toml::de::Error),

    #[error("failed to serialize vault config: {0}")]
    ConfigSerialize(#[from] toml::ser::Error),

    #[error("keychain error: {0}")]
    Keychain(#[from] keyring::Error),

    #[error("decryption failed: ciphertext is invalid or has been tampered with")]
    DecryptionFailed,

    #[error(
        "vault at {0} is partially initialized (corrupted or interrupted init) — remove it and re-run `envy init`"
    )]
    PartialVault(PathBuf),

    #[error("no envy vault found at {0} — run `envy init` first")]
    VaultNotFound(PathBuf),

    #[error("vault at {0} has insecure permissions (readable/writable by group or others)")]
    InsecurePermissions(PathBuf),

    #[error("a secret named '{0}' already exists in the vault")]
    SecretAlreadyExists(String),

    #[error(
        "bundled provider descriptor '{name}' failed to parse (this is a bug in envy itself): {message}"
    )]
    BundledProviderDescriptor { name: &'static str, message: String },

    #[error("no secret named '{0}' in the vault")]
    SecretNotFound(String),

    #[error("no provider named '{0}' in the registry")]
    ProviderNotFound(String),

    #[error("request blocked: {0}")]
    RequestBlocked(String),

    #[error("this operation requires explicit consent, which isn't supported yet: {0}")]
    ConsentRequired(String),

    #[error("policy denied this operation: {0}")]
    PolicyDenied(String),

    #[error("request to provider failed: {0}")]
    Http(String),

    #[error("invalid request: {0}")]
    InvalidRequest(String),
}
