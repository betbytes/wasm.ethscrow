package main

import (
	"fmt"
	"syscall/js"
	"wasm.ethscrow/ethscrow"
)

// init is called even before main is called. This ensures that as soon as our WebAssembly module is ready in the browser, it runs and prints "Hello, webAssembly!" to the console. It then proceeds to create a new channel. The aim of this channel is to keep our Go app running until we tell it to abort.
func init() {
	fmt.Println("Go running...")
}

func main() {
	js.Global().Set("generateKeyPair", js.FuncOf(ethscrow.GenerateKeyPair))
	js.Global().Set("sign", js.FuncOf(ethscrow.Sign))
	js.Global().Set("encrypt", js.FuncOf(ethscrow.Encrypt))
	js.Global().Set("decrypt", js.FuncOf(ethscrow.Decrypt))
	select {}
}
