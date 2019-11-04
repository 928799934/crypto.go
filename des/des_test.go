package des

import (
	"github.com/928799934/crypto.go/padding"
	"testing"
)

func TestDes(t *testing.T) {
	a := []byte("11111111")
	k := []byte("aaaaaaaa")
	v := []byte("11111111")
	/*
		b, err := ECBEncrypt(a, a)
		if err != nil {
			t.Error(err)
		}
		c, err := ECBDecrypt(b, a)
		if err != nil {
			t.Error(err)
		}
		if string(a) != string(c) {
			t.Error("decrypt error")
		}
	*/
	b, err := CBCEncrypt(a, k, v, padding.PKCS5)
	if err != nil {
		t.Error(err)
	}
	c, err := CBCDecrypt(b, k, v, padding.PKCS5)
	if err != nil {
		t.Error(err)
	}
	if string(a) != string(c) {
		t.Error("decrypt error")
	}
	return
	d := []byte("1")
	b, err = CBCEncrypt(d, a, a, padding.PKCS5)
	if err != nil {
		t.Error(err)
	}
	c, err = CBCDecrypt(b, a, a, padding.PKCS5)
	if err != nil {
		t.Error(err)
	}
	if string(d) != string(c) {
		t.Error("decrypt error")
	}
}
