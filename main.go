package main

import (
	"context"
	"fmt"

	"scanner/core"
	"scanner/scanners/discovery"
)

func main() {
	ctx := context.Background()

	registry := core.NewRegistry()

	registry.Register(discovery.NewDNSScanner())
	registry.Register(discovery.NewCrtCTScanner())
	registry.Register(discovery.NewCertSpotterCTScanner())
	registry.Register(discovery.NewSubdomainBruteforceScanner())


	pipeline := core.NewPipeline(registry)

	results, err := pipeline.Execute(ctx, "google.com")
	if err != nil {
		panic(err)
	}

	for _, r := range results {
		fmt.Printf("%+v\n", r)
	}
}
