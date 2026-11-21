package negctl

import "testing"

func TestParse(t *testing.T) {
	if _, _, err := Parse("en"); err != nil {
		t.Fatal(err)
	}
}
