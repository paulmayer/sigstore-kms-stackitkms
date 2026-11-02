package main

import (
	"fmt"
	"os"

	"github.com/paulmayer/sigstore-kms-stackitkms/internal/stackitkms"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin/handler"
)

const expectedProtocolVersion = "v1"

func main() {
	// follows example implementation patterns from
	// https://github.com/sigstore/sigstore/blob/main/test/cliplugin/localkms
	if protocolVersion := os.Args[1]; protocolVersion != expectedProtocolVersion {
		err := fmt.Errorf("expected protocol version: %s, got %s", expectedProtocolVersion, protocolVersion)
		_ = handler.WriteErrorResponse(os.Stdout, err)
		panic(err)
	}

	pluginArgs, err := handler.GetPluginArgs(os.Args)
	if err != nil {
		_ = handler.WriteErrorResponse(os.Stdout, err)
		panic(err)
	}

	signerVerifier, err := stackitkms.NewSignerVerifier(pluginArgs.InitOptions.HashFunc, pluginArgs.InitOptions.KeyResourceID)
	if err != nil {
		_ = handler.WriteErrorResponse(os.Stdout, err)
		panic(err)
	}

	_, err = handler.Dispatch(os.Stdout, os.Stdin, pluginArgs, signerVerifier)
	if err != nil {
		// Dispatch calls WriteResponse
		panic(err)
	}
}
