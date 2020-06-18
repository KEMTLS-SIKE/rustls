#![allow(unused)]
use std::sync::Arc;

use std::net::{TcpListener, TcpStream, SocketAddr};
use std::io::{Read, Write, BufReader, stdout};
use std::fs;
use std::net;

#[macro_use]
extern crate serde_derive;

use docopt::Docopt;

use rustls;

use env_logger;

const USAGE: &'static str = "
Runs a TLS server on :PORT.  The default PORT is 443.

`--certs' names the full certificate chain, `--key' provides the
RSA private key.

Usage:
  tlsserver --certs CERTFILE --key KEYFILE [options]
  tlsserver (--version | -v)
  tlsserver (--help | -h)

Options:
    -p, --port PORT     Listen on PORT [default: 443].
    --certs CERTFILE    Read server certificates from CERTFILE.
                        This should contain PEM-format certificates
                        in the right order (the first certificate should
                        certify KEYFILE, the last should be a root CA).
    --key KEYFILE       Read private key from KEYFILE.  This should be a RSA
                        private key or PKCS8-encoded private key, in PEM format.
    --verbose           Emit log output.
    --version, -v       Show tool version.
    --help, -h          Show this screen.
";


#[derive(Debug, Deserialize)]
struct Args {
    flag_port: Option<u16>,
    flag_verbose: bool,
    flag_certs: Option<String>,
    flag_key: Option<String>,
    arg_fport: Option<u16>,
}

fn load_certs(filename: &str) -> Vec<rustls::Certificate> {
    let certfile = fs::File::open(filename).expect("cannot open certificate file");
    let mut reader = BufReader::new(certfile);
    rustls::internal::pemfile::certs(&mut reader).unwrap()
}

fn load_private_key(filename: &str) -> rustls::PrivateKey {
    let rsa_keys = {
        let keyfile = fs::File::open(filename)
            .expect("cannot open private key file");
        let mut reader = BufReader::new(keyfile);
        rustls::internal::pemfile::rsa_private_keys(&mut reader)
            .expect("file contains invalid rsa private key")
    };

    let pkcs8_keys = {
        let keyfile = fs::File::open(filename)
            .expect("cannot open private key file");
        let mut reader = BufReader::new(keyfile);
        rustls::internal::pemfile::pkcs8_private_keys(&mut reader)
            .expect("file contains invalid pkcs8 private key (encrypted keys not supported)")
    };

    // prefer to load pkcs8 keys
    if !pkcs8_keys.is_empty() {
        pkcs8_keys[0].clone()
    } else {
        assert!(!rsa_keys.is_empty());
        rsa_keys[0].clone()
    }
}

fn main() {
    let version = env!("CARGO_PKG_NAME").to_string() +", version: " + env!("CARGO_PKG_VERSION");
    let args: Args = Docopt::new(USAGE)
        .and_then(|d| Ok(d.help(true)))
        .and_then(|d| Ok(d.version(Some(version))))
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    if args.flag_verbose {
        env_logger::Builder::new().parse_filters("trace").init();
    }

    let port = args.flag_port.unwrap_or(443);

    let mut config = rustls::ServerConfig::new(rustls::NoClientAuth::new());
    config.key_log = Arc::new(rustls::KeyLogFile::new());
    let certs = load_certs(args.flag_certs.as_ref().expect("--certs option missing"));
    let key = load_private_key(args.flag_key.as_ref().expect("--key option missing"));
    config.set_single_cert(certs, key).unwrap();
    let mut addr: net::SocketAddr = "0.0.0.0:443".parse().unwrap();
    addr.set_port(args.flag_port.unwrap_or(443));


    let config = Arc::new(config);


    let listener = TcpListener::bind(addr).unwrap();

    let mut input = Vec::new();
    for stream in listener.incoming() {
        {
            let sess = rustls::ServerSession::new(&config);
            let mut tlsstream = rustls::StreamOwned::new(sess, stream.unwrap());
            let _ = tlsstream.read(&mut input).unwrap();
            tlsstream.write(b"Hello!").unwrap();
        }
        println!("Connection completed");
    }
}
