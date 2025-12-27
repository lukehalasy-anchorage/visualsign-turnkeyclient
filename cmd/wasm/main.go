// +build js,wasm

package main

import (
	"context"
	"syscall/js"

	"github.com/anchorageoss/visualsign-turnkeyclient/api"
	"github.com/anchorageoss/visualsign-turnkeyclient/wasm"
)

func main() {
	c := make(chan struct{}, 0)

	// Register parseTransaction function
	js.Global().Set("parseTransaction", js.FuncOf(parseTransactionWrapper))

	println("VisualSign Turnkey Client WASM loaded")

	<-c
}

// parseTransactionWrapper wraps the parseTransaction call for JavaScript
func parseTransactionWrapper(this js.Value, args []js.Value) interface{} {
	// Create a promise handler
	handler := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		resolve := args[0]
		reject := args[1]

		go func() {
			// Parse arguments from JavaScript
			if len(args) < 5 {
				reject.Invoke(js.ValueOf("Expected 5 arguments: rawTransaction, chain, organizationId, publicKey, privateKey"))
				return
			}

			// Note: These are passed from JavaScript at runtime
			jsArgs := js.Global().Get("parseTransactionArgs")
			rawTransaction := jsArgs.Index(0).String()
			chain := jsArgs.Index(1).String()
			organizationId := jsArgs.Index(2).String()
			publicKey := jsArgs.Index(3).String()
			privateKey := jsArgs.Index(4).String()

			// Call the actual parse function
			result, err := parseTransaction(rawTransaction, chain, organizationId, publicKey, privateKey)
			if err != nil {
				reject.Invoke(js.ValueOf(err.Error()))
				return
			}

			resolve.Invoke(js.ValueOf(result))
		}()

		return nil
	})

	promiseConstructor := js.Global().Get("Promise")
	return promiseConstructor.New(handler)
}

// parseTransaction calls Turnkey API to parse a transaction
func parseTransaction(rawTransaction, chain, organizationId, publicKey, privateKey string) (string, error) {
	ctx := context.Background()

	// Create memory-based key provider
	keyProvider := wasm.NewMemoryKeyProvider(publicKey, privateKey)

	// Create HTTP client for WASM environment
	httpClient := wasm.NewWASMHTTPClient()

	// Create API client
	apiClient, err := api.NewClient(
		"https://api.turnkey.com",
		httpClient,
		organizationId,
		keyProvider,
	)
	if err != nil {
		return "", err
	}

	// Call Turnkey API
	response, err := apiClient.CreateSignablePayload(ctx, &api.CreateSignablePayloadRequest{
		UnsignedPayload: rawTransaction,
		Chain:           chain,
	})
	if err != nil {
		return "", err
	}

	// Return the parsed VisualSign JSON
	return response.SignablePayload, nil
}
