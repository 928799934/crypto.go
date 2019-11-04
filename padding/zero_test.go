package padding

import (
	"testing"
)

func TestZERO(t *testing.T) {
	a := []byte{1}
	b := ZERO.Padding(a, 16)
	// pad 15 length
	for i := 15; i > 0; i-- {
		if int(b[i]) != 0 {
			t.Error("padding error")
		}
	}
	if b[0] != 1 {
		t.Error("padding error")
	}
	c, err := ZERO.Unpadding(b, 16)
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
