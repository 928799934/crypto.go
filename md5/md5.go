package md5

import (
	"crypto/md5"
	"encoding/hex"
	"strconv"
)

func Sum(s interface{}) string {
	var src []byte
	switch inst := s.(type) {
	case string:
		src = []byte(inst)
	case []byte:
		src = inst
	case int:
		src = []byte(strconv.FormatInt(int64(inst), 10))
	case int8:
		src = []byte(strconv.FormatInt(int64(inst), 10))
	case int16:
		src = []byte(strconv.FormatInt(int64(inst), 10))
	case int32:
		src = []byte(strconv.FormatInt(int64(inst), 10))
	case int64:
		src = []byte(strconv.FormatInt(int64(inst), 10))
	case uint:
		src = []byte(strconv.FormatUint(uint64(inst), 10))
	case uint8:
		src = []byte(strconv.FormatUint(uint64(inst), 10))
	case uint16:
		src = []byte(strconv.FormatUint(uint64(inst), 10))
	case uint32:
		src = []byte(strconv.FormatUint(uint64(inst), 10))
	case uint64:
		src = []byte(strconv.FormatUint(uint64(inst), 10))
	}
	desc := md5.Sum(src)
	return hex.EncodeToString(desc[:])
}
