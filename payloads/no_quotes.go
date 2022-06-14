package payloads

func NoQuoteSuccessPayloads() []string {
	return []string{
		`"1"`,
		`'1'`,
		`1||1`,
	}
}

func NoQuoteErrorPayloads() []string {
	return []string{
		`'`,
		`"`,
		`'1`,
		`"1`,
	}
}
