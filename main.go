package main

import (
	"context"
	"fmt"

	"scanner/scanners/discovery"
	"scanner/core"
)

func main() {
	ctx := context.Background()

	registry := core.NewRegistry()

	registry.Register(discovery.NewDNSScanner())

	pipeline := core.NewPipeline(registry)

	results, err := pipeline.Execute(ctx, "google.com")
	if err != nil {
		panic(err)
	}

	for _, r := range results {
		fmt.Printf("%+v\n", r)
}
}