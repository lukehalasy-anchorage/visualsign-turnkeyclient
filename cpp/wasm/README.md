# Turnkey Client WASM (C++)

Minimal WebAssembly build of the Turnkey VisualSign client using C++ and wasi-sdk.

## Why C++ + wasi-sdk?

Following the MiniLisp C++ approach:

| Toolchain | Output Size | What You Get |
|-----------|-------------|--------------|
| **wasi-sdk + wasm-opt** | **<100KB** | Single .wasm file |
| Go WASM | 6.1MB | Large Go runtime |
| Emscripten | 100KB+ | .wasm + JavaScript runtime |

wasi-sdk produces a minimal WASI-compliant binary without JavaScript bloat or POSIX emulation.

## Build Requirements

1. **wasi-sdk** - WebAssembly toolchain
   ```bash
   # Download from GitHub releases
   wget https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-21/wasi-sdk-21.0-linux.tar.gz
   tar xzf wasi-sdk-21.0-linux.tar.gz -C /opt
   ```

2. **wasm-opt** (optional, for optimization)
   ```bash
   # Install from Binaryen
   npm install -g wasm-opt
   # Or download from: https://github.com/WebAssembly/binaryen/releases
   ```

## Building

```bash
cd cpp/wasm
./build.sh
```

### Build Flags Explained

```bash
clang++ -std=c++20 -Os -fno-exceptions -Wl,--no-entry -Wl,--export-dynamic
```

- `-std=c++20` - Modern C++ features
- `-Os` - Optimize for size
- `-fno-exceptions` - No C++ exceptions (reduces binary size)
- `-fno-rtti` - No runtime type information
- `-Wl,--no-entry` - Library mode, no main()
- `-Wl,--export-dynamic` - Export functions for JS access
- `-Wl,--allow-undefined` - Allow JS imports (fetch, crypto)

### Optimization

```bash
wasm-opt -Oz --strip-debug --strip-producers turnkey_client.wasm -o turnkey_client.wasm
```

- `-Oz` - Aggressive size optimization
- `--strip-debug` - Remove debug info
- `--strip-producers` - Remove toolchain metadata

## Architecture

### Exported Functions

- `parseTransaction()` - Main entry point for transaction parsing
- `malloc()` / `free()` - Memory management for JS interop

### JavaScript Imports

The WASM module imports these functions from JavaScript:

```javascript
// HTTP fetch
js_fetch(method, url, headers_json, body, ...)

// Cryptography
js_sign_message(message, private_key, out_signature, ...)
js_sha256(data, out_hash)
```

### File Structure

```
cpp/wasm/
├── main.cpp          - Entry point and parseTransaction
├── http_client.cpp   - HTTP client using JS fetch
├── http_client.hpp
├── crypto.cpp        - ECDSA signing via JS crypto
├── crypto.hpp
├── types.hpp         - Type definitions
├── build.sh          - Build script
└── README.md         - This file
```

## Usage from JavaScript

```javascript
// Load WASM module
const importObject = {
  env: {
    // Provide JS implementations of imported functions
    js_fetch: (method, url, headers, body, ...) => { /* ... */ },
    js_sign_message: (msg, key, out_sig, ...) => { /* ... */ },
    js_sha256: (data, out_hash) => { /* ... */ }
  }
};

const { instance } = await WebAssembly.instantiateStreaming(
  fetch('turnkey_client.wasm'),
  importObject
);

// Call parseTransaction
const result = instance.exports.parseTransaction(
  rawTransaction,
  chain,
  organizationId,
  publicKey,
  privateKey
);
```

## Error Handling

The module uses return codes instead of exceptions:

- `0` - Success
- `1` - Invalid arguments
- `2` - HTTP request failed
- `3` - Cryptography failed
- `4` - JSON parsing failed

## Size Comparison

| Implementation | Size | Runtime |
|----------------|------|---------|
| Go WASM | 6.1 MB | Go runtime included |
| C++ + Emscripten | ~100 KB | JS runtime required |
| **C++ + wasi-sdk** | **<100 KB** | **Minimal, no bloat** |

## References

- [MiniLisp C++](https://nextdoorhacker.com/2025/12/26/minilisp-c-a-compile-time-lisp-interpreter-in-c-20/)
- [wasi-sdk](https://github.com/WebAssembly/wasi-sdk)
- [Binaryen (wasm-opt)](https://github.com/WebAssembly/binaryen)
