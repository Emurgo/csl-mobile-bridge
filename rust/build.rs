extern crate cbindgen;

use std::env;

fn main() {
  #[cfg(not(target_os = "android"))]
  {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    cbindgen::generate(crate_dir)
      .expect("Unable to generate bindings")
      .write_to_file("include/react_native_haskell_shelley.h");
  }
}
