package blind

import (
	"testing"
)

func TestEncryptAndDecrypt(t *testing.T) {
	var key = "Utm.Pwd-53cr3t.5t4k!_3mpTy*"
	text := "efM4ywuRrE0PWVOyVnFDEIPwLflQFQUpv1HD+qBL"
	//encrypted, _ := Encrypt(key, text)
	decrypted, _ := Decrypt16([]byte(key), text)

	if text == decrypted {
		t.Error("Text should be:", text)
	} else {
		t.Error("value:", decrypted)
	}
}
