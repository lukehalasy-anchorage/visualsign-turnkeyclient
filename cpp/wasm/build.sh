#!/bin/bash

# Build script for WASM using wasi-sdk
# Produces minimal WASM binary without JavaScript bloat

set -e

# Check for wasi-sdk
if ! command -v /opt/wasi-sdk/bin/clang++ &> /dev/null; then
    echo "Error: wasi-sdk not found at /opt/wasi-sdk"
    echo "Please install wasi-sdk from: https://github.com/WebAssembly/wasi-sdk/releases"
    echo "Or set WASI_SDK_PATH environment variable"
    exit 1
fi

WASI_CLANG="${WASI_SDK_PATH:-/opt/wasi-sdk}/bin/clang++"
WASM_OPT="${WASM_OPT:-wasm-opt}"

echo "Building Turnkey Client WASM..."

# Compile with wasi-sdk
$WASI_CLANG \
    -std=c++20 \
    -Os \
    -fno-exceptions \
    -fno-rtti \
    -Wl,--no-entry \
    -Wl,--export-dynamic \
    -Wl,--allow-undefined \
    -o turnkey_client.wasm \
    main.cpp \
    http_client.cpp \
    crypto.cpp

echo "✓ Compiled to turnkey_client.wasm"

# Check if wasm-opt is available
if command -v $WASM_OPT &> /dev/null; then
    echo "Optimizing with wasm-opt..."

    # First pass: asyncify transformation
    # This allows C++ to call async JS functions as if they were synchronous
    $WASM_OPT \
        --asyncify \
        turnkey_client.wasm \
        -o turnkey_client.asyncify.wasm

    echo "✓ Applied asyncify transformation"

    # Second pass: optimize size
    $WASM_OPT \
        -Oz \
        --strip-debug \
        --strip-producers \
        turnkey_client.asyncify.wasm \
        -o turnkey_client.wasm

    # Clean up intermediate file
    rm -f turnkey_client.asyncify.wasm

    echo "✓ Optimized with wasm-opt"
else
    echo "⚠️  wasm-opt not found, skipping optimization and asyncify"
    echo "   Install from: https://github.com/WebAssembly/binaryen"
    echo "   WARNING: WASM will not support async JS calls without asyncify!"
fi

# Show size
SIZE=$(wc -c < turnkey_client.wasm)
SIZE_KB=$((SIZE / 1024))

echo ""
echo "✓ Build complete!"
echo "  Output: turnkey_client.wasm"
echo "  Size: ${SIZE_KB}KB (${SIZE} bytes)"
