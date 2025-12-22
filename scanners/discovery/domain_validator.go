package discovery

import (
	"strings"
)


func IsValidSubdomain(sub, domain string) bool {
    sub = strings.TrimSpace(sub)

    if sub == "" {
        return false
    }

    // Remove trailing dot (common in DNS dumps)
    sub = strings.TrimSuffix(sub, ".")

    // Hard filters (noise)
    if strings.HasPrefix(sub, ".") ||
        strings.Contains(sub, "*") ||
        strings.Contains(sub, "@") ||
        strings.Contains(sub, " ") {
        return false
    }

    // Must belong to domain
    if sub == domain {
        return false
    }

    if !strings.HasSuffix(sub, "."+domain) {
        return false
    }

    // Basic DNS label validation
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