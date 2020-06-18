use std::sync::Arc;

use std::net::{TcpStream, SocketAddr};
use std::io::{Read, Write, BufReader, stdout};
use std::fs;

#[macro_use]
extern crate serde_derive;

use docopt::Docopt;

use rustls;
use webpki;
use webpki_roots;

use env_logger;

use rustls::Session;

const USAGE: &'static str ="
Connects to TLS server at hostname:Port and sends HTTP request

Not all options are actually implemented

Usage:
    client [options] <hostname>
    client --help

Options:
    -l, --loops LOOPS   Number of loops
    -p, --port PORT     Connect to PORT [default: 443].
    --http              Send a basic HTTP GET request for /.
    --cafile CAFILE     Read root certificates from CAFILE.
    --auth-key KEY      Read client authentication key from KEY.
    --auth-certs CERTS  Read client authentication certificates from CERTS.
                        CERTS must match up with KEY.
    --protover VERSION  Disable default TLS version list, and use
                        VERSION instead.  May be used multiple times.
    --suite SUITE       Disable default cipher suite list, and use
                        SUITE instead.  May be used multiple times.
    --proto PROTOCOL    Send ALPN extension containing PROTOCOL.
                        May be used multiple times to offer several protocols.
    --cache CACHE       Save session cache to file CACHE.
    --no-tickets        Disable session ticket support.
    --no-sni            Disable server name indication support.
    --insecure          Disable certificate verification.
    --verbose           Emit log output.
    --mtu MTU           Limit outgoing messages to MTU bytes.
    --version, -v       Show tool version.
    --help, -h          Show this screen.
";

fn lookup_ipv4(host: &str, port: u16) -> SocketAddr {
    use std::net::ToSocketAddrs;

    let addrs = (host, port).to_socket_addrs().unwrap();
    for addr in addrs {
        if let SocketAddr::V4(_) = addr {
            return addr;
        }
    }

    unreachable!("Cannot lookup address");
}

#[derive(Debug, Deserialize)]
struct Args {
    flag_loops: Option<u16>,
    flag_port: Option<u16>,
    flag_http: bool,
    flag_verbose: bool,
    flag_protover: Vec<String>,
    flag_suite: Vec<String>,
    flag_proto: Vec<String>,
    flag_mtu: Option<usize>,
    flag_cafile: Option<String>,
    flag_cache: Option<String>,
    flag_no_tickets: bool,
    flag_no_sni: bool,
    flag_insecure: bool,
    flag_auth_key: Option<String>,
    flag_auth_certs: Option<String>,
    arg_hostname: String,
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

    let num_loops = args.flag_loops.unwrap_or(1);
    let port = args.flag_port.unwrap_or(443);
    let addr = lookup_ipv4(args.arg_hostname.as_str(), port);

    let mut config = rustls::ClientConfig::new();

    if args.flag_cafile.is_some() {
        let cafile = args.flag_cafile.as_ref().unwrap();

        let certfile = fs::File::open(&cafile).expect("Cannot open CA file");
        let mut reader = BufReader::new(certfile);
        config.root_store
            .add_pem_file(&mut reader)
            .unwrap();
    } else {
        config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        config.ct_logs = None;
    }

    if args.flag_no_tickets {
        config.enable_tickets = false;
    }

    let dns_name = webpki::DNSNameRef::try_from_ascii_str(&args.arg_hostname).unwrap();

    let config = &Arc::new(config);
    let mut plaintext = Vec::with_capacity(1024);
    for i in 0..num_loops {
        println!("Iteration {} of {}", i, num_loops);
        let sess = rustls::ClientSession::new(&config, dns_name);
        let sock = TcpStream::connect(addr).unwrap();
        let mut tls = rustls::StreamOwned::new(sess, sock);
        tls.write_all(concat!("GET / HTTP/1.1\r\n",
                          "Connection: close\r\n",
                          "Accept-Encoding: identity\r\n",
                          "\r\n")
                  .as_bytes())
            .unwrap();
        tls.read_to_end(&mut plaintext).unwrap();
        println!("Read to end");
        //stdout().write_all(&plaintext).unwrap();
        plaintext.clear();
    }
}
