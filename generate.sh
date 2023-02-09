#!/bin/bash
CSL_VERSION=`grep 'cardano-serialization-lib =' rust/Cargo.toml | awk '{print $3}' | tr -d '"'`
cd codegen
git clone  --branch "$CSL_VERSION" https://github.com/Emurgo/cardano-serialization-lib/
cd cardano-serialization-lib/rust
# mark all wasm_bindgen functions as wasm_accessible to make them visible in the json docs for python script
find . -name "*.rs" -exec grep -q "#\[wasm_bindgen\]" {} \; -print | while read file; do
  # Insert the line "#[doc = "wasm_accessible"]" after "#[wasm_bindgen]"
  awk '{
    if (/^[[:space:]]*#\[wasm_bindgen\]/) {
      space = substr($0, 1, match($0, /[^[:space:]]/) - 1)
      print $0
      print space "#[doc = \"wasm_accessible\"]"
    } else {
      print $0
    }
  }' "$file" > "$file.tmp" && mv "$file.tmp" "$file"
done
# generate json docs, you need to have nightly rust installed
cargo +nightly rustdoc --target="wasm32-unknown-unknown" -- -Zunstable-options --output-format json
cp target/wasm32-unknown-unknown/doc/cardano_serialization_lib.json ../..
cd ../..
# needs python 3.9+
python generator.py
rm -rf cardano-serialization-lib