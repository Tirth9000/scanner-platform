package core

import "context"

type Scanner interface {
	Name() string
	Category() string
	Run(ctx context.Context, target string) ([]Result, error)
}