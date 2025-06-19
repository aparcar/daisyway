# Daisyway

Enhancing the security of a WireGuard tunnel by using Quantum-Key-Distribution (QKD) as additional pre-shared keys.

Dual-licensed under [Apache 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT).

## Usage

Start the simulator if you have no real QKD device:

```bash
cargo run --bin simulator -- --addr 127.0.0.1:12345
```

Now start both Daisyway daemons:

```bash
# terminal 1
cd example/ada/
cargo run --bin daisyway -- exchange --config config.toml

# terminal 2
cd example/bob/
cargo run --bin daisyway -- exchange --config config.toml
```

## Configuration

The configuration file is a TOML file and is passed via `--config` to the binary. The following options are available:

```toml
[peer]
listen = "127.0.0.1:5555"     # Address:Port for Daisyway binding
endpoint = "127.0.0.1:5556"   # Address/Domain:Port for Daisyway peer binding
psk_file = "../psk.key"       # (optional) Path to file containing the pre-shared key
state_file = "./daisyway.state" # Path to file containing the state of the Daisyway

[etsi014]
url = "http://localhost:12345" # ETSI014 API address

# To allow forward secrecy, the key is rotated every 120 seconds per default.
# If the key generation rate is below 1 key per 120 seconds (i.e. bad fiber cable
# connection between QKD devices), increase this to an appropriate value.
# interval_secs = 120

# The Secure Application Entity (SAE) is part of the ETSI014 standard. In production
# setups the QKD devices should be configured to use a dedicated SAE for the Daisyway
# instances. When using the included simulator, the SAE can be left as is.
remote_sae_id = "SAE_002"      # Identifier for the "SAE" intended for communication

# If the ETSI014 API uses a self-signed certificate, the CA certificate can be provided
#tls_cacert = "ca.crt"

# The following two options allow to configure a TLS based client authentification
#tls_cert = "client.crt"
#tls_key = "client.key"

# If the ETSI014 API uses a self-signed certificate without a server name, the following
# option can be used to disable the server name check - this is insecure!
#danger_allow_insecure_no_server_name_certificates = true

# The following two sections define how exchanged keys are used. They can be
# stored in a file using the `outfile` secton or used directly in the WireGuard
# configuration using the `wireguard` section. The `outfile` section is optional
# and is recommended only for testing. If `outfile` is defined, it's used,
# otherwise the `wireguard` section is used.
[wireguard]
interface = "wg0"                                                # Interface name
peer_public_key = "GOJt/mfPuwoUiKD+hARpxuDtnzJOWkcK0Tq+sxxw4UQ=" # Public key of the peer
self_public_key = "5+l6TWvUJr2jCCqqyeSwExPriW74khDQvompp+xHe4Q=" # Public key of the self

#[outfile]
#path = "/tmp/outfile.ada" # Path to file where the exchanged key is stored
```

## Development

### Testing

We are using nix-based tests. Run the nix checks to execute the tests:

```bash
nix flake check . --print-build-logs
```

### TLS and mTLS setup

The Daisyway sotware supports also ETSI 014 APIs over HTTPS and even mTLS. To
simulate and test such a setup, we provide a simple TLS setup using `openssl`.
The following steps are required to set up the TLS environment:

```bash
# Generate a self-signed CA
openssl req -x509 -newkey rsa:4096 -keyout ca.key -out ca.crt -days 365 -nodes -subj "/CN=QKD_CA"

# Generate the server key and certificate signing request (CSR)
openssl req -newkey rsa:4096 -keyout server.key -out server.csr -nodes -subj "/CN=localhost"

# Sign the server certificate with the CA
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365

# Generate client certificates (for mTLS)
openssl req -newkey rsa:4096 -keyout client.key -out client.csr -nodes -subj "/CN=client"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365
```

The QKD simulator and Daisypass can load those certificates. The first example uses only a self-signed certificate, the second example uses mTLS.

#### Self-signed certificate

* Start the ETSI014 API with a self-signed certificate:

```bash
cargo run --bin simulator -- --addr 127.0.0.1:12345 --cert-path server.crt --key-path server.key
```

The `etsi014` part of the Daisyway configuration should look like this:

```toml
# example/ada/config.toml
...
[etsi014]
url = "https://localhost:12345"
remote_sae_id = "SAE_002"
tls_cacert = "ca.crt"
danger_allow_insecure_no_server_name_certificates = true
```

> [!CAUTION]
> The `danger_allow_insecure_no_server_name_certificates` is only required when
> the server URL does not match the certificate.

* Start the Daisyway daemons:

```bash
cp ca.crt example/ada/
cd example/ada/
cargo run --bin daisyway -- exchange --config config.toml
```

#### Self-signed certificate with mTLS

* Start the ETSI014 API with mTLS:

```bash
cargo run -- --addr 0.0.0.0:1234 --cert-path server.crt --key-path server.key --ca-path ca.crt
```

The `etsi014` part of the Daisyway configuration should look like this:

```toml
# example/ada/config.toml
...
[etsi014]
url = "https://localhost:12345"
remote_sae_id = "SAE_002"
tls_cacert = "ca.crt"
tls_cert = "client.crt"
tls_key = "client.key"
danger_allow_insecure_no_server_name_certificates = true
```

> [!CAUTION]
> The `danger_allow_insecure_no_server_name_certificates` is only required when
> the server URL does not match the certificate.

* Start the Daisyway daemons:

```bash
cp ca.crt client.crt client.key example/ada/
cd example/ada/
cargo run --bin daisyway -- exchange --config config.toml
```

## Acknowledgments

This project was developed by [Karolin Varner](https://github.com/koraa)
([Rosenpass e.V.](https://rosenpass.eu)) and [Paul
Spooren](https://github.com/aparcar) ([Hochschule
Nordhausen](http://hs-nordhausen.de)), partly funded by the European
Commission and the BMFTR (Bundesministerium für Forschung, Technologie und
Raumfahrt) - formally BMWF.
