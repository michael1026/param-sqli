package payloads

func SingleQuoteSuccessPayloads() []string {
	return []string{
		`"`,
		`'||''||'`,
		`zx'||'zy`,
	}
}

func SingleQuoteErrorPayloads() []string {
	return []string{
		`'`,
		`'||''`,
		`z||'z(z'z`,
	}
}
