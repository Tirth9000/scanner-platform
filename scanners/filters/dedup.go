package filters


import (
	"context"
	"strings"
	"fmt"

	"scanner/core"
)


type DedupFilter struct {}

func NewDedupFilter() *DedupFilter {
	return &DedupFilter{}
}

func (f *DedupFilter) Name() string {
	return "DedupFilter"
}

func (f *DedupFilter) Category() string {
	return "FilterScanner"
}


func normalizeSubdomain(s string) string {
    s = strings.TrimSpace(strings.ToLower(s))
    s = strings.TrimSuffix(s, ".")

    if after, ok :=strings.CutPrefix(s, "*."); ok  {
        s = after
    }

    return s
}


func IsValidSubdomain(sub, domain string) bool {
    sub = strings.TrimSpace(sub)

    if sub == "" {
        return false
    }

    sub = strings.TrimSuffix(sub, ".")

    if strings.HasPrefix(sub, ".") ||
        strings.Contains(sub, "*") ||
        strings.Contains(sub, "@") ||
        strings.Contains(sub, " ") ||
        strings.ContainsAny(sub, " <>\"'") {
        return false
    }

    if sub == domain {
        return false
    }

    if !strings.HasSuffix(sub, "."+domain) {
        return false
    }
    
    labels := strings.Split(sub, ".")
    for _, label := range labels {
        if label == "" || len(label) > 63 {
            return false
        }
        if label[0] == '-' || label[len(label)-1] == '-' {
            return false
        }
    }

    return true
}

func (d *DedupFilter) RunFilterScanner(
    ctx context.Context,
    input []core.Result,
	domain string,
) ([]core.Result, error) {

    seen := make(map[string]core.Result)
    var output []core.Result

    for _, sub := range input {
        if sub.Data.(map[string]string)["subdomain"] == "" {
            continue
        }

		if !IsValidSubdomain(sub.Data.(map[string]string)["subdomain"], domain) {
			fmt.Println(sub.Data.(map[string]string)["subdomain"])
			continue
		}

        normalized := normalizeSubdomain(sub.Data.(map[string]string)["subdomain"])

        sub.Data.(map[string]string)["subdomain"] = normalized
        seen[normalized] = sub
        output = append(output, sub)
    }

	fmt.Println(len(output))

    return output, nil
}
