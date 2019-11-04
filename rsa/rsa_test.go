package rsa

import (
	"encoding/base64"
	"log"
	"testing"
)

var (
	privateKeyString = "MIIBOQIBAAJBALuCRM5wqGt5Ehhq/pdGHVFZ5kemv5NSSaOf6wc0GBJZ4ZBRGsg0SnYsdbb3p3/a9L5IU66b72tWDb89jZur4jUCAwEAAQJAZa8bSShm7QFXAs7jCX4IYBl0e969fVLehFEwz1M8ypXsHadtFQECpxXN5wlpzLQ0yQxrNpzz+4pzVZ6qdwPTcQIhAPbhN4KaqNLOTpf6a6Vpb6rN8+Oyvsy/afXy+w0hxvAfAiEAwm+STK+Pnm/SpqQIRVmJu6cx3ETCLUzD9xD2oz2o0ysCIAeGyjhzGp6Cp6a+fbWnRz4/1SWl92cqlsJmy/yUgQolAiAc8nloe1a5ctJ8xr0Ifh0YV/r/XSk/j0c5mEfv47UnwwIgc3AWLSSIGjmXg5aDP4eEZ2ZuR7yjXFG9x8CFCDY4sRk="
	//publicKeyString = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKnE+vONZvFCSHaMfAONWNpsAc3iAbSsG+8kMUJZi6hmRB7TPG1s9R6hNleXWpV7BvvGxXamySgM9tjPp6jzq0kCAwEAAQ=="
	//privateKeyString = "MIIBPAIBAAJBAMMNYHIOe73v08t+Zls57//v66j3NW2ndAeuDVX1AAOLG5NQbzmPnNHcGPKDFmW4wYWf0+jtnNIVzY20hud+m1ECAwEAAQJBAJcWbIfM+kMlW8y8K3MszOBWqxfl7cfztygfxYq4zfrvUvL8LAQZUD6LbQ+mieArB1gnikbcRhogwZ8dhd6qWSUCIQDk2lTtHe6mrZRTNpNOhGyz/TX0s2keVbdp4PrLZDZuiwIhANowm7MAgbWRna3i2Wh3REd9RkW1OEL31+2fU3GIiRUTAiBfYgxxg787Iy+l+yIsYI85+Xhqk/hlF07Jx2ZgLVVufwIhAItsQDH0Au6ZLB7vNGmyvKjJ/luQ33C7mvk2tEV6L86NAiEAh3wWVjDIek5re7mXQsHHf2/WX0rB/FThDniv+IlwdLQ="
	//publicKeyString  = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMMNYHIOe73v08t+Zls57//v66j3NW2ndAeuDVX1AAOLG5NQbzmPnNHcGPKDFmW4wYWf0+jtnNIVzY20hud+m1ECAwEAAQ=="

	publicKey = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALuCRM5wqGt5Ehhq/pdGHVFZ5kemv5NSSaOf6wc0GBJZ4ZBRGsg0SnYsdbb3p3/a9L5IU66b72tWDb89jZur4jUCAwEAAQ=="
)

func TestRsa(t *testing.T) {
	public, _ := GetPublicKeyByBase64Str(publicKey)
	password := []byte("aaa")
	bs, e := RsaEncrypt(password, public)
	if e != nil {
		t.Errorf("rsa encrypt password(%s) error(%v)", password, e)
		t.FailNow()
	}
	strPassword := base64.StdEncoding.EncodeToString(bs)

	privateKey, _ := GetPKCS1PrivateKeyByBase64Str(privateKeyString)
	//password := "Rn4/lpwgEWCIex6uOEo1t1y1sugXNEP20AJtHuu64EEAj1T6cC00rZxVuW+L5UxgXCLC2iZD7lsDWqn/kESr+g=="
	//password := "uzuHgXigdmxRQskGhd/9FIDd8+hlkn49A+Lm7Dxk1tdRbVpvcM38/m6jKKEWCE8Baj3zwJimhTVsjNfyr8XT/g=="
	//password := "kGrXolpfrFLu3OhRe3rJBXMwd6q6a9aKATGot1hCLrO1iR3XkKIxnHPAiaZHh9KKeUFgsFJOfMxSwwaObf8cAha9cxCVsF7ByfPHy5IiJPHwmBYIyP4SECP+yhiYDaxtfBdq4ec+gsYmd5Dk2X7wrnG5O3SjZgAaxMskgcoobs+vyaC1jCwzjk5JPmLu4oAXuNaOESbC1ndun5EfdN+ZxtsJ5VrpMwLNNhsSrJeQUh+CNel50UmaO7NhS5p0q8EcDv/HFwNvhSKDHKLbAAl/4OegKBcZrudwX/2/nt3aUROh6DQfBVGwZexa+OxLSwEWiGuHA8oEPolQEzS9lXfG7w30O5TryP44QupTmupa+2vEC96mBHE2b3BPdkZA3KtBDRozqCfIAxVrZB+i7LwjfFVhQG8ejW/+s/It7pj1urA="

	bs, e = base64.StdEncoding.DecodeString(strPassword)
	if e != nil {
		t.Errorf("base64 decode password(%s) error(%v)", password, e)
		t.FailNow()
	}
	bs, e = RsaDecrypt(bs, privateKey)
	if e != nil {
		t.Errorf("rsa decode password(%s) error(%v)", password, e)
		t.FailNow()
	}
	/*
		bs, e = RsaSegmentDecrypt(bs, privateKey)
		if e != nil {
			t.Errorf("rsa decode password(%s) error(%v)", strPassword, e)
			t.FailNow()
		}
	*/
	log.Println(strPassword, string(bs))
}
