package gosec

import (
	"sort"
)

// Error is used when there are golang errors while parsing the AST
type Error struct {
	Line   int    `json:"line"`
	Column int    `json:"column"`
	Err    string `json:"error"`
}

// NewError creates Error object
func NewError(line, column int, err string) *Error {
	return &Error{
		Line:   line,
		Column: column,
		Err:    err,
	}
}

// sortErrors sorts the golang errors by line
func sortErrors(allErrors map[string][]Error) {
	keys := make([]string, 0, len(allErrors))
	for key := range allErrors {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	for _, key := range keys {
		errors := allErrors[key]
		sort.Slice(errors, func(i, j int) bool {
			if errors[i].Line == errors[j].Line {
				return errors[i].Column <= errors[j].Column
			}
			return errors[i].Line < errors[j].Line
		})
	}
}
