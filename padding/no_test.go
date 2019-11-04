package padding

import (
	"testing"
)

func TestNo(t *testing.T) {
	a := []byte{1}
	b := NO.Padding(a, 16)
	// pad 15 length
	if len(b) != 1 {
		t.Error("padding error")
	}
	if b[0] != 1 {
		t.Error("padding error")
	}
	c, err := NO.Unpadding(b, 16)
	if err != nil {
		t.Error(err)
	}
	if len(c) != 1 {
		t.Error("padding error")
	}
	if c[0] != 1 {
		t.Error("padding error")
	}
}
