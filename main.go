package main

import (
	"context"
	"fmt"

	"scanner/core"
	"scanner/scanners/discovery"
	"scanner/scanners/filters"
)

func main() {
	ctx := context.Background()

	registry := core.NewRegistry()

	registry.Register(discovery.NewDNSScanner())
	// registry.Register(discovery.NewCrtCTScanner())
	// registry.Register(discovery.NewCertSpotterCTScanner())
	// registry.Register(discovery.NewSubdomainBruteforceScanner())
	// registry.Register(discovery.NewSubdomainChaosScanner())
	registry.Register(discovery.NewSubdomainSubFinderScanner())

	pipeline := core.NewPipeline(registry)

	// results, err := pipeline.Execute(ctx, "allianzcloud.com")
	// results, err := pipeline.Execute(ctx, "example.com")
	results, err := pipeline.Execute(ctx, "google.com")
	if err != nil {
		panic(err)
	}

	// for _, r := range results {
	// 	fmt.Printf("%+v\n", r)
	// }

	fmt.Println("final result count : ", len(results))

	filter_registry := core.NewFilterScannerRegistry()

	filter_registry.RegisterFilterScanner(filters.NewDedupFilter())
	filter_registry.RegisterFilterScanner(filters.NewDNSFilter())
	// filter_registry.RegisterFilterScanner(filters.NEWDNSTEST()) // test dns

	filter_pipeline := core.NewFilterPipeline(filter_registry)

	// filtered_results, err := filter_pipeline.ExecuteFilterScanners(ctx, results, "example.com")
	filtered_results, err := filter_pipeline.ExecuteFilterScanners(ctx, results, "google.com")
	// filtered_results, err := filter_pipeline.ExecuteFilterScanners(ctx, results, "allianzcloud.com")
	if err != nil {
		panic(err)
	}

	results = filtered_results

	// for _, r := range results {
	// 	fmt.Printf("After Filter %+v\n", r)
	// }
	fmt.Println(len(results))
}
