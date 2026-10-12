// Verify a Tauri/minisign signature using the EXACT crate the updater itself
// uses (minisign-verify 0.2.5, already in BlackRose's Cargo.lock).
//
//   cargo run --release -- <public-key-line> <artifact> <signature-text>
//
// The two inputs are deliberately in DIFFERENT shapes, which is the whole
// source of confusion here:
//
//   * PublicKey::from_base64 takes the BARE base64 line (56 chars -> 42 bytes).
//   * Signature::decode    takes the DECODED 4-line minisign TEXT, because it
//     reads untrusted-comment / sig / trusted-comment / global-sig in order and
//     asserts 74 and 64 bytes at fixed offsets.
//
// Tauri writes both as base64(base64(text)); unwrap the outer layer first.
//
// PublicKey::verify(&self, bin, &Signature, allow_legacy):
//   bin          the signed bytes (the artifact itself)
//   allow_legacy true accepts pre-0.6 "Ed" keys, which Tauri's are.
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("usage: msigcheck <public-key-line> <artifact> <signature-text>");
        std::process::exit(2);
    }

    let pk_line = std::fs::read_to_string(&args[1]).expect("read pubkey line");
    let sig_text = std::fs::read_to_string(&args[3]).expect("read signature text");

    let pk = minisign_verify::PublicKey::from_base64(pk_line.trim())
        .expect("parse public key from base64");
    let sig = minisign_verify::Signature::decode(sig_text.trim())
        .expect("parse signature");

    println!("trusted comment : {}", sig.trusted_comment());

    let bin = std::fs::read(&args[2]).expect("read artifact");
    println!("artifact bytes  : {}", bin.len());

    match pk.verify(&bin, &sig, true) {
        Ok(()) => println!("SIGNATURE VALID"),
        Err(e) => {
            println!("SIGNATURE INVALID: {e}");
            std::process::exit(1);
        }
    }
}
