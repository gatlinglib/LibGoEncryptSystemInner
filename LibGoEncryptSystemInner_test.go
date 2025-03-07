package LibGoEncryptSystemInner

import "testing"

const C_TestText = "test123"

func TestLGESI_Encrypt(t *testing.T) {
	text1, err := LGESI_Encrypt(C_TestText)
	if err != nil {
		t.Error(err)
		return
	}
	text2, err := LGESI_Decrypt(text1)
	if err != nil {
		t.Error(err)
		return
	}

	t.Log("encrypt code: ", text1)
	t.Log("decrypt code: ", text2)
	if text2 != C_TestText {
		t.Error("system wrong: decrypt text != encrypt text")
	}

}
