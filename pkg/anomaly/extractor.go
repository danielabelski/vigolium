package anomaly

// ExtractAttributesFromRaw extracts attributes from raw response components.
// Useful when you already have the response data extracted.
func ExtractAttributesFromRaw(statusCode int, body string, headers map[string][]string) (*AttributeSet, error) {
	// Use webfinger to extract all attributes
	fp := NewFingerprint(AllFingerprintAttributes)
	fp.UpdateWith(statusCode, body, headers)

	// Create AttributeSet and populate it
	attrs := NewAttributeSet()
	for _, attrType := range AllFingerprintAttributes {
		if value, ok := fp.GetAttributeValue(attrType); ok && value != 0 {
			attrs.Set(attrType, value)
		}
	}

	return attrs, nil
}
