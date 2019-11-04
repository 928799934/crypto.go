package hmac

import (
	"encoding/base64"
	"encoding/hex"
	"log"
	"testing"
)

func TestHmac(t *testing.T) {
	message := []byte("this is demo")
	key := []byte("cmcm")
	sign := HmacSha1(key, message)
	strSign := hex.EncodeToString(sign)
	//log.Printf("sign:%s", strSign)
	sign, _ = hex.DecodeString(strSign)
	//log.Println(HmacSha1Verify(message, sign, key))
	msg := []byte(`{"mobile":"13383624290","user_id":"999999999","task_id":"216221b0-1e13-11e6-bd19-005056ba0359","bills":["2016-05","2016-04","2016-03","2016-02","2016-01","2015-12"]}`)
	s := HmacSha256([]byte("27c7e4bc518c48d095d9caf544771876"), msg)
	log.Printf("%s", base64.StdEncoding.EncodeToString(s))
	d, _ := base64.StdEncoding.DecodeString("NJP5BaKQTOjdSFVsW4XbCM3dE4C5N8sTTcsXM5IWeow=")
	log.Println(HmacSha256Verify(msg, d, []byte("27c7e4bc518c48d095d9caf544771876")))
}
