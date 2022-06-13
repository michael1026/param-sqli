package payloads

func SuccessPayloads() []string {
	return []string{
		`"`,
		`'||''||'`,
		`zx'||'zy`,
	}
}

func ErrorPayloads() []string {
	return []string{
		`'`,
		`'||''`,
		`z||'z(z'z`,
	}
}
