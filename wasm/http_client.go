// +build js,wasm

package wasm

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"syscall/js"
)

// WASMHTTPClient implements http.Client interface using JavaScript fetch API
type WASMHTTPClient struct{}

// NewWASMHTTPClient creates a new WASM HTTP client
func NewWASMHTTPClient() *WASMHTTPClient {
	return &WASMHTTPClient{}
}

// Do performs an HTTP request using JavaScript fetch API
func (c *WASMHTTPClient) Do(req *http.Request) (*http.Response, error) {
	// Read request body
	var bodyBytes []byte
	if req.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
		req.Body.Close()
	}

	// Create fetch options
	opts := js.Global().Get("Object").New()
	opts.Set("method", req.Method)

	// Set headers
	headers := js.Global().Get("Object").New()
	for key, values := range req.Header {
		if len(values) > 0 {
			headers.Set(key, values[0])
		}
	}
	opts.Set("headers", headers)

	// Set body if present
	if len(bodyBytes) > 0 {
		// Convert body to Uint8Array
		uint8Array := js.Global().Get("Uint8Array").New(len(bodyBytes))
		js.CopyBytesToJS(uint8Array, bodyBytes)
		opts.Set("body", uint8Array)
	}

	// Call fetch
	promise := js.Global().Call("fetch", req.URL.String(), opts)

	// Wait for promise to resolve
	result := await(promise)
	if !result.success {
		return nil, fmt.Errorf("fetch failed: %v", result.error)
	}

	jsResp := result.value

	// Get response status
	status := jsResp.Get("status").Int()

	// Get response headers
	respHeaders := make(http.Header)
	// Note: JavaScript Headers API is complex to iterate, skipping for now
	_ = jsResp.Get("headers") // jsHeaders - not used yet

	// Read response body
	textPromise := jsResp.Call("text")
	textResult := await(textPromise)
	if !textResult.success {
		return nil, fmt.Errorf("failed to read response body: %v", textResult.error)
	}

	bodyText := textResult.value.String()
	respBody := io.NopCloser(bytes.NewReader([]byte(bodyText)))

	// Create http.Response
	resp := &http.Response{
		Status:     fmt.Sprintf("%d", status),
		StatusCode: status,
		Header:     respHeaders,
		Body:       respBody,
		Request:    req,
	}

	return resp, nil
}

// awaitResult holds the result of awaiting a promise
type awaitResult struct {
	success bool
	value   js.Value
	error   string
}

// await waits for a JavaScript promise to resolve
func await(promise js.Value) awaitResult {
	done := make(chan awaitResult, 1)

	// Create success handler
	onSuccess := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		done <- awaitResult{success: true, value: args[0]}
		return nil
	})
	defer onSuccess.Release()

	// Create error handler
	onError := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		errorMsg := "unknown error"
		if len(args) > 0 {
			errorMsg = args[0].String()
		}
		done <- awaitResult{success: false, error: errorMsg}
		return nil
	})
	defer onError.Release()

	// Attach handlers to promise
	promise.Call("then", onSuccess).Call("catch", onError)

	// Wait for result
	return <-done
}
