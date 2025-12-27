# WASM Proof of Concept

This directory contains test files demonstrating the Turnkey Client WASM module in action.

## 📦 What's Included

- **`test.html`** - Interactive browser-based test page with UI
- **`test.js`** - Node.js command-line test script
- **`js_glue.js`** - JavaScript glue code providing WASM imports
- **`turnkey_client.wasm`** - Compiled WASM module (413.67 KB)

## 🚀 Running the Tests

### Browser Test (Recommended)

1. Start a local web server:
   ```bash
   # Using Python 3
   python3 -m http.server 8000

   # Or using Node.js
   npx http-server -p 8000
   ```

2. Open browser to: `http://localhost:8000/test.html`

3. The page will:
   - Load the WASM module automatically
   - Display file size, load time, and memory usage
   - Show all available WASM exports
   - Provide form to test `parseTransaction` function

### Node.js Test

```bash
node test.js
```

Expected output:
```
═══════════════════════════════════════════════════════════
  Turnkey Client WASM - Proof of Concept Test
═══════════════════════════════════════════════════════════

🔄 Loading WASM module...

📦 WASM file size: 413.67 KB
✅ WASM module loaded in 4ms
💾 Memory allocated: 16.00 MB

🧪 Testing parseTransaction function...
...
```

## 📊 Performance Metrics

From our POC testing:

| Metric | Value |
|--------|-------|
| **File Size** | 413.67 KB (uncompressed) |
| **Load Time** | ~4ms (Node.js), varies in browser |
| **Memory Usage** | 16 MB (256 pages × 64KB) |
| **Exports** | 500+ functions (C++ stdlib + custom) |

Compare to Go WASM: ~6.1 MB

## 🔍 Available Exports

The WASM module exports:

- **`parseTransaction`** - Main function for parsing transactions
- **`memory`** - Linear memory (shared with JavaScript)
- **C++ stdlib functions** - String manipulation, memory management, etc.

Example of calling `parseTransaction`:

```javascript
// In browser or Node.js (with proper setup)
const result = wasmInstance.exports.parseTransaction(
  rawTransaction,  // hex string
  chain,          // "ETHEREUM", "BITCOIN", etc.
  organizationId, // Your Turnkey org ID
  publicKey,      // API public key
  privateKey      // API private key
);
```

## 🏗️ Architecture

```
┌─────────────────┐
│  JavaScript     │
│  (Browser/Node) │
└────────┬────────┘
         │
         ↓ js_glue.js provides:
         │ - js_fetch (HTTP requests)
         │ - js_sign_message (ECDSA)
         │ - js_sha256 (Hashing)
         │ - WASI stubs (filesystem, etc.)
         │
┌────────┴────────┐
│  WASM Module    │
│  (C++)          │
│                 │
│  • HTTP client  │
│  • Crypto ops   │
│  • Parsing      │
└─────────────────┘
```

## 🛠️ How It Works

1. **Module Loading**:
   - JavaScript fetches `turnkey_client.wasm`
   - Creates WebAssembly.Memory (256 pages = 16MB)
   - Provides import object with WASI and custom functions
   - Instantiates module

2. **Function Calls**:
   - JavaScript calls WASM exported functions
   - WASM can call back to JavaScript via imports
   - Data passes through shared linear memory

3. **HTTP Requests**:
   - WASM calls `js_fetch` import
   - JavaScript uses fetch API or Node.js https
   - Response written to WASM memory

## 🎯 Next Steps

- [ ] Implement full parseTransaction logic
- [ ] Add error handling and validation
- [ ] Optimize binary size (current: 413KB, target: <100KB)
- [ ] Add compression (gzip/brotli)
- [ ] Benchmark against Go implementation
- [ ] Add integration tests with real Turnkey API
- [ ] Document memory layout and calling conventions

## 📝 Notes

### Current Status

✅ WASM module compiles and loads
✅ JavaScript glue code provides all imports
✅ `parseTransaction` function is exported
⏳ Function implementation in progress

### Known Limitations

1. **Async operations**: WASI doesn't support true async, so HTTP requests use workarounds
2. **Error handling**: Currently minimal, needs expansion
3. **Memory management**: Fixed 16MB allocation (can grow to 32MB)
4. **Binary size**: Larger than target due to C++ stdlib inclusion

### File Size Optimization Ideas

- Strip unnecessary C++ stdlib functions
- Use custom allocator instead of stdlib
- Enable LTO (Link Time Optimization) in build
- Use `wasm-opt -Oz` for aggressive size reduction
- Implement custom string/vector classes

## 🐛 Troubleshooting

**Module fails to load**:
- Check that `turnkey_client.wasm` exists
- Verify web server allows WASM MIME type
- Check browser console for errors

**"Import not found" errors**:
- Ensure `js_glue.js` is imported before loading WASM
- Verify all WASI stubs are present

**Memory errors**:
- Increase initial memory pages in import object
- Check memory.grow() succeeds if needed

## 📚 References

- [WebAssembly Specification](https://webassembly.org/specs/)
- [WASI Documentation](https://wasi.dev/)
- [wasi-sdk GitHub](https://github.com/WebAssembly/wasi-sdk)
- [MiniLisp C++ Inspiration](https://nextdoorhacker.com/2025/12/26/minilisp-c-a-compile-time-lisp-interpreter-in-c-20/)
