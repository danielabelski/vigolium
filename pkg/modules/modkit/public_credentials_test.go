package modkit

import "testing"

func TestIsReCaptchaSiteKeyShape(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want bool
	}{
		{"v2 site key", "6LfnSAoUAAAAAG49XsPZF3YJHzE3KiAuQuoivYZb", true},
		{"url-safe alphabet", "6Lc-1234567890abcdefABCDEF_-1234567890ab", true},
		{"39 chars is wrong length", "6LfnSAoUAAAAAG49XsPZF3YJHzE3KiAuQuoivYZ", false},
		{"41 chars is wrong length", "6LfnSAoUAAAAAG49XsPZF3YJHzE3KiAuQuoivYZbc", false},
		{"wrong prefix", "7LfnSAoUAAAAAG49XsPZF3YJHzE3KiAuQuoivYZb", false},
		{"illegal char", "6LfnSAoUAAAAAG49XsPZF3YJHzE3KiAuQuoiv=Zb", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsReCaptchaSiteKeyShape(tt.s); got != tt.want {
				t.Errorf("IsReCaptchaSiteKeyShape(%q) = %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}

func TestHasSalesforceConsumerKeyPrefix(t *testing.T) {
	const consumerKey = "3MVG9fTLmJ60pJ5KxSmtobJLmmeX3Yr9sJrDKgSb2xhl1znSnx8kH1.e7BbBcInj7bhGxZij011PyyEMAP23X"
	tests := []struct {
		name string
		s    string
		want bool
	}{
		{"connected app consumer key", consumerKey, true},
		{"surrounding whitespace is trimmed", "  " + consumerKey + "  ", true},
		{"consumer secret is not prefixed", "1955279925992207737", false},
		{"unrelated credential", "AKIAIOSFODNN7EXAMPLE", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HasSalesforceConsumerKeyPrefix(tt.s); got != tt.want {
				t.Errorf("HasSalesforceConsumerKeyPrefix(%q) = %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}
