fn main() {
    if cfg!(feature = "hd") {
        println!("hd_usage example. Try `--features hd` to run HD wallet APIs.");
    } else {
        println!("Enable with: cargo run --example hd_usage --features hd");
    }
}
