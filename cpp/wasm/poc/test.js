#!/usr/bin/env node

/**
 * Node.js POC test for Turnkey Client WASM module
 *
 * Usage: node test.js
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { createImportObject } from '../js_glue.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function loadWASM() {
    console.log('🔄 Loading WASM module...\n');

    const wasmPath = path.join(__dirname, 'turnkey_client.wasm');
    const wasmBuffer = fs.readFileSync(wasmPath);

    console.log(`📦 WASM file size: ${(wasmBuffer.byteLength / 1024).toFixed(2)} KB`);

    // Create memory and import object using js_glue
    const memory = new WebAssembly.Memory({ initial: 256, maximum: 512 });
    const importObject = createImportObject(memory);

    const startTime = Date.now();
    const module = await WebAssembly.compile(wasmBuffer);
    const instance = await WebAssembly.instantiate(module, importObject);
    const loadTime = Date.now() - startTime;

    console.log(`✅ WASM module loaded in ${loadTime}ms`);
    console.log(`💾 Memory allocated: ${(memory.buffer.byteLength / (1024 * 1024)).toFixed(2)} MB\n`);

    return { instance, memory };
}

async function testParseTransaction(instance) {
    console.log('🧪 Testing parseTransaction function...\n');

    // Test data
    const testData = {
        rawTransaction: '02f87301808459682f008459682f0e82520894c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2880de0b6b3a764000080c0',
        chain: 'ETHEREUM',
        organizationId: 'test-org-123',
        publicKey: '04a1b2c3d4e5f6789...',
        privateKey: 'a1b2c3d4e5f6...'
    };

    console.log('📝 Test Parameters:');
    console.log(`   Raw TX: ${testData.rawTransaction.substring(0, 40)}...`);
    console.log(`   Chain: ${testData.chain}`);
    console.log(`   Org ID: ${testData.organizationId}\n`);

    // Check available exports
    console.log('📋 Available WASM exports:');
    Object.keys(instance.exports).forEach(key => {
        const value = instance.exports[key];
        const type = value instanceof Function ? 'function' : typeof value;
        console.log(`   - ${key} (${type})`);
    });
    console.log('');

    // Try to call parseTransaction if it exists
    if (instance.exports.parseTransaction) {
        try {
            console.log('▶️  Calling parseTransaction...');
            const startTime = performance.now();

            const result = instance.exports.parseTransaction(
                testData.rawTransaction,
                testData.chain,
                testData.organizationId,
                testData.publicKey,
                testData.privateKey
            );

            const duration = (performance.now() - startTime).toFixed(2);

            console.log(`✅ parseTransaction completed in ${duration}ms`);
            console.log('\n📤 Result:');
            console.log(JSON.stringify(result, null, 2));
        } catch (error) {
            console.error('❌ Error calling parseTransaction:', error.message);
        }
    } else {
        console.log('ℹ️  parseTransaction function not found in exports');
        console.log('   This is expected if the WASM module is still under development\n');
    }
}

async function main() {
    console.log('═══════════════════════════════════════════════════════════');
    console.log('  Turnkey Client WASM - Proof of Concept Test');
    console.log('═══════════════════════════════════════════════════════════\n');

    try {
        const { instance, memory } = await loadWASM();
        await testParseTransaction(instance);

        console.log('\n═══════════════════════════════════════════════════════════');
        console.log('✅ POC test completed successfully!');
        console.log('═══════════════════════════════════════════════════════════\n');
    } catch (error) {
        console.error('\n❌ POC test failed:', error.message);
        console.error(error.stack);
        process.exit(1);
    }
}

// Run if called directly
if (require.main === module) {
    main();
}

module.exports = { loadWASM, testParseTransaction };
