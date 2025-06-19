use std::{path::PathBuf, sync::Arc};

use anyhow::{ensure, Context, Result};
use base64ct::{Base64, Encoding};
use log::{debug, info, warn};
use reqwest::Client;
use rustls::{
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        WebPkiServerVerifier,
    },
    pki_types::{CertificateDer, ServerName, UnixTime},
    ClientConfig, DigitallySignedStruct, RootCertStore,
};
use rustls_pki_types::{pem::PemObject, PrivateKeyDer};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zerocopy::FromZeros;

use crate::internal::{daisyway::crypto::Key, util::ConstLenExt};

#[derive(Debug)]
pub struct NoServerNameVerification {
    inner: Arc<WebPkiServerVerifier>,
}

// TODO add test cases for this
impl NoServerNameVerification {
    pub fn new(inner: Arc<WebPkiServerVerifier>) -> Self {
        Self { inner }
    }

    pub fn from_roots(roots: Arc<RootCertStore>) -> Result<NoServerNameVerification> {
        let inner = rustls::client::WebPkiServerVerifier::builder(roots).build()?;
        Ok(Self::new(inner))
    }
}

impl ServerCertVerifier for NoServerNameVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        match self
            .inner
            .verify_server_cert(_end_entity, _intermediates, _server_name, _ocsp, _now)
        {
            Ok(scv) => {
                debug!("Server certificate verified successfully.");
                Ok(scv)
            }
            Err(rustls::Error::InvalidCertificate(cert_error)) => match cert_error {
                rustls::CertificateError::NotValidForName => {
                    debug!("Server certificate verification failed: NotValidForName");
                    Ok(ServerCertVerified::assertion())
                }
                rustls::CertificateError::NotValidForNameContext {
                    expected: _,
                    presented: _,
                } => {
                    debug!("Server certificate verification failed: NotValidForNameContext");
                    Ok(ServerCertVerified::assertion())
                }
                _ => {
                    debug!("Server certificate verification failed: {:?}", cert_error);
                    Err(rustls::Error::InvalidCertificate(cert_error))
                }
            },
            Err(e) => Err(e),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ClientAuth {
    tls_cert: PathBuf,
    tls_key: PathBuf,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Etsi014Config {
    url: String,
    remote_sae_id: String,
    pub interval_secs: Option<u64>,
    tls_cacert: Option<PathBuf>,
    #[serde(flatten)]
    client_auth: Option<ClientAuth>,
    #[serde(default)]
    danger_allow_insecure_no_server_name_certificates: bool,
}

#[derive(Debug, Clone)]
pub struct Etsi014Key {
    pub id: Uuid,
    pub key: Key,
}

impl Etsi014Key {
    pub fn empty() -> Self {
        Self {
            id: Uuid::nil(),
            key: Key::new_zeroed(),
        }
    }
}

impl TryFrom<ResponseKey> for Etsi014Key {
    type Error = anyhow::Error;

    fn try_from(value: ResponseKey) -> Result<Self, Self::Error> {
        let ResponseKey { id, key } = value;
        assert!(Base64::encoded_len(key.as_bytes()) != Key::LEN);
        let mut dec_buf = Key::new_zeroed();
        let decoded = Base64::decode(key.as_bytes(), &mut dec_buf).unwrap();
        Ok(Self {
            id,
            key: decoded.try_into()?,
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ResponseKey {
    #[serde(rename = "key_ID")]
    pub id: Uuid,
    pub key: String,
}

#[derive(Deserialize, Serialize)]
struct ResponseKeys {
    keys: Vec<ResponseKey>,
}

impl TryFrom<ResponseKeys> for Etsi014Key {
    type Error = anyhow::Error;

    fn try_from(value: ResponseKeys) -> Result<Self, Self::Error> {
        ensure!(
            value.keys.len() == 1,
            "Expected exactly one key, but got {} keys",
            value.keys.len()
        );
        value.keys.into_iter().next().unwrap().try_into()
    }
}

#[derive(Debug)]
pub struct Etsi014Connection {
    url: String,
    remote_sae_id: String,
    client: Client,
}

impl Etsi014Connection {
    pub fn new(url: String, remote_sae_id: String, client: Client) -> Self {
        Self {
            url,
            remote_sae_id,
            client,
        }
    }

    pub fn from_config(config: &Etsi014Config) -> Result<Self> {
        let client_builder = Client::builder().use_rustls_tls();
        let client_builder = match Self::configure_rustls(config)? {
            Some(rustls_config) => client_builder.use_preconfigured_tls(rustls_config),
            None => client_builder,
        };

        Ok(Self::new(
            config.url.clone(),
            config.remote_sae_id.clone(),
            client_builder.build()?,
        ))
    }

    fn configure_rustls(config: &Etsi014Config) -> Result<Option<rustls::ClientConfig>> {
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("Failed to install rustls crypto provider");

        let mut roots = RootCertStore::empty();

        // Load CA certificate if provided
        if let Some(cacert_path) = &config.tls_cacert {
            let cacert = CertificateDer::from_pem_file(cacert_path).with_context(|| {
                format!(
                    "Failed to read TLS CA certificate from file {:?}",
                    cacert_path
                )
            })?;
            roots
                .add(cacert)
                .context("Failed to add TLS CA certificate to RootCertStore")?;
        }

        let tls_roots = Arc::new(roots);

        let mut rustls_config: ClientConfig;

        // Handle client authentication if configured
        if let Some(client_auth) = &config.client_auth {
            let (cert_path, key_path) = match client_auth {
                ClientAuth { tls_cert, tls_key } => (tls_cert, tls_key),
            };

            info!(
                "Using client authentification with certificate {:?} and key {:?}",
                cert_path, key_path
            );

            let cert = CertificateDer::from_pem_file(cert_path).with_context(|| {
                format!(
                    "Failed to read TLS client certificate from file {:?}",
                    cert_path
                )
            })?;
            let key = PrivateKeyDer::from_pem_file(key_path).with_context(|| {
                format!("Failed to read TLS client key from file {:?}", key_path)
            })?;

            rustls_config = ClientConfig::builder()
                .with_root_certificates(tls_roots.clone())
                .with_client_auth_cert(vec![cert], key)?;
        } else {
            // Start with a base client config using root certificates
            rustls_config = ClientConfig::builder()
                .with_root_certificates(tls_roots.clone())
                .with_no_client_auth();
        }

        // Allow insecure certificates if configured
        if config.danger_allow_insecure_no_server_name_certificates {
            warn!("Allowing insecure server name verification for ETSI014 certificates");

            ClientConfig::dangerous(&mut rustls_config).set_certificate_verifier(Arc::new(
                NoServerNameVerification::from_roots(tls_roots)?,
            ));
        }

        Ok(Some(rustls_config))
    }

    pub async fn fetch_any_key(&self) -> Result<Etsi014Key> {
        self.fetch_key_internal(&format!(
            "{}/api/v1/keys/{}/enc_keys?number=1&key_length=256",
            self.url, self.remote_sae_id
        ))
        .await
        .context("Error Fetching unspecific key from ETSI014 URL.")
    }

    pub async fn fetch_specific_key(&self, id: Uuid) -> Result<Etsi014Key> {
        self.fetch_key_internal(&format!(
            "{}/api/v1/keys/{}/dec_keys?key_ID={}",
            self.url, self.remote_sae_id, id
        ))
        .await
        .context("Error Fetching specific key from ETSI014 URL. (key id={id})")
    }

    async fn fetch_key_internal(&self, uri: &str) -> Result<Etsi014Key> {
        let response = self.client.get(uri).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await?;
            return Err(anyhow::anyhow!(
                "ETSI 014 URL {} returned status code {}: {}",
                &uri,
                status,
                text
            ));
        }

        let response: ResponseKeys = response.json().await?;
        response.try_into()
    }
}
