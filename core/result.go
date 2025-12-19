package core

import "time"

type Result struct {
	Scanner   string
	Category  string
	Target    string
	Data      any
	Severity  string
	Timestamp time.Time
}