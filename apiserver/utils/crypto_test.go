package utils

import (
	"testing"
)

func TestAddressGenerate(t *testing.T) {
	p, p1, p2 := CreateAddressandKey()
	t.Log(p)
	t.Log(p1)
	t.Log(p2)
}

func TestCryptAndDescrypt(t *testing.T) {
	origData := []byte("hello world!")
	pubkey := "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETgzVXIVyimLgSqCRm4oLPncBYAWRDz7tn/GFHxiYXTpS6hYdqXmYXISIMyn1uSkZRvSlKYFwtOsKQiiCYfCPRA=="
	privatekey := "MHcCAQEEIEwXnmo6M1+ZXZa6c7xzXKY6Ng3vx6OJ1jObuaIGOabRoAoGCCqGSM49AwEHoUQDQgAETgzVXIVyimLgSqCRm4oLPncBYAWRDz7tn/GFHxiYXTpS6hYdqXmYXISIMyn1uSkZRvSlKYFwtOsKQiiCYfCPRA=="
	p1, p2, err := EncryptData(origData, pubkey)
	if err != nil {
		t.Fatalf(err.Error())
		return
	}
	t.Log(p1)
	t.Log(p2)
	t.Log(string(p1[:]))
	t.Log(string(p2[:]))
	p3, err := DecryptData(p1, p2, privatekey)
	if err != nil {
		t.Fatalf(err.Error())
		return
	}
	str1 := string(origData[:])
	str2 := string(p3[:])

	t.Log(str1)
	t.Log(str2)

}
