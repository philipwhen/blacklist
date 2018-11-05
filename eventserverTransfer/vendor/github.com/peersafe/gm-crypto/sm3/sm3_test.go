package sm3

import (
	"bytes"
	"fmt"
	"testing"
)

const (
	sm3MsgBytes    = 3
	sm3DigestBytes = 32
)

type sm3Test struct {
	in  []byte
	out []byte
}

var golden = []sm3Test{
	{[]byte{0x61, 0x62, 0x63}, []byte{0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9, 0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2, 0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2, 0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0}},
}

func TestSm3(t *testing.T) {
	sm3Engine := New()
	for i := 0; i < len(golden); i++ {
		g := golden[i]
		sm3Engine.Write(g.in)
		s := sm3Engine.Sum(nil)
		if bytes.Compare(g.out, s) != 0 {
			t.Fatalf("Sum function: sum(%s) = %s want %s", g.in, s, g.out)
		}
	}
}

func TestSM3Hash(t *testing.T) {
	test := []byte("12345678")
	sm3Hash := New()
	sm3Hash.Write(test)
	digest := sm3Hash.Sum(nil)
	fmt.Printf("digest : %x\n", digest)

	sm3Hash1 := New()
	sm3Hash1.Write(test)
	digest1 := sm3Hash1.Sum(nil)
	fmt.Printf("digest1 : %x\n", digest1)

	sm3Hash2 := New()
	sm3Hash2.Write(test)
	digest2 := sm3Hash2.Sum(nil)
	fmt.Printf("digest2 : %x\n", digest2)
}

func BenchmarkSm3(t *testing.B) {

}
