fn main() {
    if let Err(err) = devctl::run() {
        eprintln!("devctl: {err}");
        std::process::exit(2);
    }
}
