package core

import (
	"context"
	"fmt"
)

type Pipeline struct {
	registry *Registry
	runner   *Runner
}

func NewPipeline(registry *Registry) *Pipeline {
	return &Pipeline{
		registry: registry,
		runner:   NewRunner(),
	}
}

func (p *Pipeline) Execute(ctx context.Context, target string) ([]Result, error) {
	var results []Result

	for _, scanner := range p.registry.All() {
		fmt.Println("Running scanner:", scanner.Name())
		res, err := p.runner.Run(ctx, scanner, target)
		if err != nil {
			fmt.Println("Scanner error:", scanner.Name(), err)
			continue
		}
		results = append(results, res...)
		fmt.Println("Completed scanner:", scanner.Name())
	}

	return results, nil
}