//! Measures unlock cost across candidate Argon2id parameters.
//!
//! ```bash
//! cargo run --profile measure --example kdf_timing --manifest-path src-tauri/Cargo.toml
//! ```
//!
//! The `measure` profile matters: under the dev profile the scratch-buffer allocation and
//! zeroization in `derive_key` are unoptimised and inflate every reading by roughly 6x.
//!
//! Use this when retuning `KdfParams::RECOMMENDED`: pick the highest cost that still feels
//! instant on the slowest machine the app has to support. Memory is the better lever than
//! iterations — it is what denies an attacker cheap GPU and ASIC parallelism.

use std::time::Instant;

use password_manager_lib::crypto::kdf::{derive_key, KdfParams, Salt};

const PASSWORD: &[u8] = b"correct horse battery staple";

fn main() {
    let salt = Salt::generate().expect("system RNG must be available");

    println!("{:>10}  {:>6}  {:>6}  {:>12}", "memory", "t", "p", "median");

    for memory_mib in [19, 32, 64, 128, 256, 512] {
        let params = KdfParams::new(memory_mib * 1024, 3, 1).expect("candidate must be valid");

        let mut timings: Vec<_> = (0..3)
            .map(|_| {
                let start = Instant::now();
                derive_key(PASSWORD, &salt, params).expect("derivation must succeed");
                start.elapsed()
            })
            .collect();
        timings.sort();

        let marker = if params == KdfParams::RECOMMENDED {
            "  <- RECOMMENDED"
        } else {
            ""
        };

        println!(
            "{memory_mib:>7} MiB  {:>6}  {:>6}  {:>9} ms{marker}",
            params.iterations(),
            params.lanes(),
            timings[1].as_millis()
        );
    }
}
