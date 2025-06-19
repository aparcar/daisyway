use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use anyhow::{Error, Result};
use base64ct::{Base64, Encoding};
use clap::Parser;
use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::{Request, Response, StatusCode, body::Bytes, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use log::{debug, error, info};
use rustls::{RootCertStore, ServerConfig, server::WebPkiClientVerifier};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use serde_json::json;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Address to bind the server
    #[arg(short, long, default_value = "0.0.0.0:12345")]
    addr: SocketAddr,

    /// Path to TLS certificate
    #[arg(long, short)]
    cert_path: Option<String>,

    /// Path to TLS private key
    #[arg(long, short)]
    key_path: Option<String>,

    /// Path to the CA certificate file
    #[arg(long)]
    ca_path: Option<String>,

    #[arg(long)]
    danger_allow_insecure_no_server_name_certificates: bool,
}

async fn handle_request(
    req: Request<impl hyper::body::Body>,
    counter: Arc<AtomicU64>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let path = req.uri().path();
    let query = req.uri().query();

    info!("Received request: {}", path);
    debug!("Query parameters: {:?}", query);

    if path.starts_with("/api/v1/keys/") {
        return handle_keys(path, query, counter);
    }

    info!("Request not found: {}", path);

    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(empty())
        .unwrap())
}

fn empty() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

fn handle_keys(
    path: &str,
    query: Option<&str>,
    counter: Arc<AtomicU64>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    info!("Handling key request: {}", path);

    if !path.contains("dec_keys") && !path.contains("enc_keys") {
        error!("Invalid request path: {}", path);
        return Ok(bad_request("Only one of /dec_keys or /enc_keys is allowed"));
    }

    let key_id = if path.contains("dec_keys") {
        match query {
            Some(q) => {
                if let Some(pos) = q.find("key_ID=") {
                    match Uuid::parse_str(&q[(pos + 7)..]) {
                        Ok(id) => id,
                        Err(_) => {
                            error!("Invalid key_ID format in query: {}", q);
                            return Ok(bad_request("Invalid key_ID format"));
                        }
                    }
                } else {
                    error!("Missing key_ID parameter in query: {}", q);
                    return Ok(bad_request("Invalid key_ID format"));
                }
            }
            None => {
                error!("key_ID parameter is required but missing");
                return Ok(bad_request("key_ID parameter is required"));
            }
        }
    } else {
        let count = counter.fetch_add(1, Ordering::SeqCst);
        debug!("Incremented counter to: {}", count);

        Uuid::from_u128(count as u128)
    };

    let mut key_input = [0u8; 32];
    let key_id_bytes = key_id.as_bytes();
    key_input[..16].copy_from_slice(key_id_bytes);
    key_input[16..].copy_from_slice(key_id_bytes);

    let mut enc_buf = [0u8; 128];
    let encoded_key: &str = Base64::encode(&key_input, &mut enc_buf).unwrap();
    debug!("Encoded key: {}", encoded_key);

    let response_body = json!({
        "keys": [{ "key": encoded_key, "key_ID": key_id.to_string() }]
    })
    .to_string();

    let response = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .header("Content-Length", response_body.len().to_string())
        .body(full(response_body))
        .unwrap();

    info!("Key response generated for key_ID: {}", key_id);
    Ok(response)
}

fn bad_request(msg: &str) -> Response<BoxBody<Bytes, hyper::Error>> {
    error!("Bad request: {}", msg);

    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(full(msg.to_string()))
        .unwrap()
}

fn load_tls_config(
    cert_path: &str,
    key_path: &str,
    ca_path: Option<String>,
) -> Result<ServerConfig, Error> {
    let cert = CertificateDer::from_pem_file(cert_path).expect("Failed to read certificate file");
    let key = PrivateKeyDer::from_pem_file(key_path).expect("Failed to read private key file");

    let config: ServerConfig;

    if let Some(ca_path) = ca_path {
        let ca_cert =
            CertificateDer::from_pem_file(ca_path).expect("Failed to read CA certificate file");

        let mut roots = RootCertStore::empty();
        roots.add(ca_cert)?;

        let verifier = WebPkiClientVerifier::builder(roots.into())
            .build()
            .expect("Failed to create client certificate verifier");

        config = ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![cert], key)
            .expect("Failed to create server config");
    } else {
        config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();
    }

    Ok(config)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init(); // Initialize logging
    let args = Args::parse();

    if args.cert_path.is_some() != args.key_path.is_some() {
        return Err(anyhow::anyhow!(
            "Both --cert-path and --key-path must be provided"
        ));
    }

    let addr = args.addr;
    let counter = Arc::new(AtomicU64::new(1));

    let tls_acceptor: Option<TlsAcceptor>;
    if args.cert_path.is_some() && args.key_path.is_some() {
        let tls_config = load_tls_config(
            &args.cert_path.unwrap(),
            &args.key_path.unwrap(),
            args.ca_path,
        )?;
        tls_acceptor = Some(TlsAcceptor::from(Arc::new(tls_config)));
    } else {
        tls_acceptor = None;
    }
    let listener = TcpListener::bind(&addr).await?;
    info!("Starting TLS server on https://{}", addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let tls_acceptor = tls_acceptor.clone();
        let counter_clone = counter.clone();

        tokio::spawn(async move {
            if let Some(tls_acceptor) = tls_acceptor {
                match tls_acceptor.accept(stream).await {
                    Ok(tls_stream) => {
                        let io = TokioIo::new(tls_stream);

                        if let Err(e) = http1::Builder::new()
                            .serve_connection(
                                io,
                                service_fn(|req| handle_request(req, counter_clone.clone())),
                            )
                            .await
                        {
                            error!("Server error: {}", e);
                        }
                    }
                    Err(e) => error!("TLS handshake error: {}", e),
                }
            } else {
                let io = TokioIo::new(stream);

                if let Err(e) = http1::Builder::new()
                    .serve_connection(
                        io,
                        service_fn(|req| handle_request(req, counter_clone.clone())),
                    )
                    .await
                {
                    error!("Server error: {}", e);
                }
            }
        });
    }
}
