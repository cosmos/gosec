package sdk

import "testing"

func TestCanOverflowChecks32Bits(t *testing.T) {
	if !is32Bit {
		t.Skip("Not running on a 64-bit machine!")
	}

	cases := []struct {
		endKind      string
		wantOverflow bool
	}{
		{"int8", true},
		{"int16", true},
		{"int32", false},
		{"int64", false},
		{"int", false},
		{"uint8", true},
		{"uint16", true},
		{"uint32", false},
		{"uint64", false},
		{"uint", false},
	}

	for _, tt := range cases {
		tt := tt
		t.Run(tt.endKind, func(t *testing.T) {
			if got := canLenOverflow32(tt.endKind); got != tt.wantOverflow {
				t.Fatalf("Mismatch\n\tGot: %t\n\tWant:%t", got, tt.wantOverflow)
			}
		})
	}
}

func TestCanOverflowChecks64Bits(t *testing.T) {
	if is32Bit {
		t.Skip("Not running on a 32-bit machine!")
	}

	cases := []struct {
		endKind      string
		wantOverflow bool
	}{
		{"int8", true},
		{"int16", true},
		{"int32", true},
		{"int", false},
		{"int64", false},
		{"uint8", true},
		{"uint16", true},
		{"uint32", true},
		{"uint64", false},
		{"uint", false},
	}

	for _, tt := range cases {
		tt := tt
		t.Run(tt.endKind, func(t *testing.T) {
			if got := canLenOverflow64(tt.endKind); got != tt.wantOverflow {
				t.Fatalf("Mismatch\n\tGot: %t\n\tWant:%t", got, tt.wantOverflow)
			}
		})
	}
}
