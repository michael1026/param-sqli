package payloads

func DoubleQuoteSuccessPayloads() []string {
	return []string{
		`'`,
		`"||""||"`,
		`zx"||"zy`,
	}
}

func DoubleQuoteErrorPayloads() []string {
	return []string{
		`"`,
		`"||""`,
		`z||"z(z"z`,
	}
}
