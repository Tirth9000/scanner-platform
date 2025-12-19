package core

type Registry struct {
	scanners []Scanner
}

func NewRegistry() *Registry {
	return &Registry{}
}

func (r *Registry) Register(scanner Scanner) {
	r.scanners = append(r.scanners, scanner)
}

func (r *Registry) All() []Scanner {
	return r.scanners
}