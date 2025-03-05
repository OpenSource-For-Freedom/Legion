// Legion High-Performance Scanner (in Rust)
// Uses SHA-256 

use std::fs::File;
use std::io::{BufReader, Read};
use sha2::{Sha256, Digest};
use rayon::prelude::*;
use std::path::Path;

fn compute_sha256(filepath: &str) -> String {
    let file = File::open(filepath).expect("Failed to open file");
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0; 4096];

    while let Ok(n) = reader.read(&mut buffer) {
        if n == 0 { break; }
       hasher.update(&buffer[..n]);
    }

    format!("{:x}", hasher.finalize())
}

fn main() {
    let files = vec!["/path/to/scan/file1", "/path/to/scan/file2"];
    files.par_iter().for_each(|file| {
        let hash = compute_sha256(file);
        println!("Scanned {} -> Hash: {}", file, hash);
    });
}
