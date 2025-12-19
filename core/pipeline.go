package core

import "context"

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
		res, err := p.runner.Run(ctx, scanner, target)
		if err != nil {
			continue
		}
		results = append(results, res...)
	}

	return results, nil
}