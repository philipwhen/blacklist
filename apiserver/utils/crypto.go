package utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	butils "github.com/hyperledger/fabric/bccsp/utils"
	"github.com/hyperledger/fabric/core/crypto/primitives"
	"github.com/hyperledger/fabric/core/crypto/primitives/ecies"
	"golang.org/x/crypto/ripemd160"
)

//	"crypto/aes"
//	"crypto/cipher"
const version = byte(0x00)
const addressChecksumLen = 4

func CreateAddressandKey() (string, string, string) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Printf("Generate ecdsa key err : %s\n", err.Error())
		return "", "", ""
	}

	// Private Key DER format
	der, err := butils.PrivateKeyToDER(key)
	if err != nil {
		fmt.Printf("faled to generate der type err : %s\n", err.Error())
		return "", "", ""
	}
	skencodeString := base64.StdEncoding.EncodeToString(der)
	der1, err := butils.PublicKeyToDER(&key.PublicKey)
	if err != nil {
		fmt.Printf("faled to generate der type err : %s\n", err.Error())
		return "", "", ""
	}
	pkencodeString := base64.StdEncoding.EncodeToString(der1)

	pubKey := append(key.PublicKey.X.Bytes(), key.PublicKey.Y.Bytes()...)
	publicSHA256 := sha256.Sum256(pubKey)
	RIPEMD160Hasher := ripemd160.New()
	_, err = RIPEMD160Hasher.Write(publicSHA256[:])
	if err != nil {
		fmt.Printf("faled to generate der type err : %s\n", err.Error())
		return "", "", ""
	}
	pubKeyHash := RIPEMD160Hasher.Sum(nil)
	versionedPayload := append([]byte{version}, pubKeyHash...)
	checksum := checksum(versionedPayload)
	fullPayload := append(versionedPayload, checksum...)
	addressString := base64.StdEncoding.EncodeToString(fullPayload)

	return skencodeString, pkencodeString, addressString
}
func checksum(payload []byte) []byte {
	firstSHA := sha256.Sum256(payload)
	secondSHA := sha256.Sum256(firstSHA[:])

	return secondSHA[:addressChecksumLen]
}

//crypto "github.com/hyperledger/fabric/core/crypto"
//	"github.com/hyperledger/fabric/core/crypto/primitives"
//	"github.com/hyperledger/fabric/core/crypto/primitives/ecies"
//func init() {
//	if err := crypto.Init(); err != nil {
//		panic("crypto init err : " + err.Error())
//	}
//}

//func GetPublicKey(pem []byte) (interface{}, error) {
//	publicKey, err := primitives.PEMtoPublicKey(pem, nil)
//	return publicKey, err
//}

//func GetPrivateKey(pem []byte) (interface{}, error) {
//	privatekey, err := primitives.PEMtoPrivateKey(pem, nil)
//	return privatekey, err
//}

//func IsFileExist(filename string) (bool, error) {
//	_, err := os.Stat(filename)
//	if err == nil {
//		return true, nil
//	}
//	if os.IsNotExist(err) {
//		return false, nil
//	}
//	return false, err
//}

//func ReadFile(path string) ([]byte, error) {
//	f, err := os.OpenFile(path, os.O_RDONLY|os.O_CREATE, 0666)
//	if err != nil {
//		fmt.Printf("ReadFile open file [%s] err : %s\n", path, err.Error())
//		return nil, err
//	}
//	info, err := os.Stat(path)
//	fileSize := info.Size()
//	buff := make([]byte, fileSize)
//	_, err = f.Read(buff)
//	if err != nil {
//		fmt.Printf("ReadFile read file [%s] err : %s\n", path, err.Error())
//		return nil, err
//	}

//	f.Close()

//	return buff, nil
//}

//func GenerateKey(bitsize int) []byte {
//	key := ""

//	r := rand.New(rand.NewSource(time.Now().UnixNano()))
//	for i := 0; i < bitsize/2; i++ {
//		key += fmt.Sprintf("%x", r.Int63())
//	}

//	return []byte(key)
//}
func DescryptKey(ekeyStr string, key string) ([]byte, error) {
	err := primitives.SetSecurityLevel("SHA2", 256)
	if err != nil {
		return nil, err
	}
	skdecodeBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}
	private, err := butils.DERToPrivateKey(skdecodeBytes)
	if err != nil {
		return nil, err
	}

	//descrypt the key from the EncryptKey
	ekeyByte, err := base64.StdEncoding.DecodeString(ekeyStr)
	if err != nil {
		return nil, err
	}
	aesKey, err := EciesDecrypt(ekeyByte, private)
	if err != nil {
		return nil, err
	}
	return aesKey, nil
}
func EncryptKey(keyByte []byte, key string) (string, error) {
	err := primitives.SetSecurityLevel("SHA2", 256)
	if err != nil {
		return "", err
	}
	pkdecodeBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", err
	}
	pub, err := butils.DERToPublicKey(pkdecodeBytes)
	if err != nil {
		return "", err
	}
	//generate encrytKey of the aeskey
	EncryptKey, err := EciesEncrypt(keyByte, pub)
	if err != nil {
		return "", err
	}
	ekeyStr := base64.StdEncoding.EncodeToString(EncryptKey)
	return ekeyStr, nil
}
func EncryptData(origData []byte, key string) ([]byte, []byte, error) {
	//generate a random aeskey
	err := primitives.SetSecurityLevel("SHA2", 256)
	if err != nil {
		return nil, nil, err
	}
	AesKey, err := primitives.GenAESKey()
	if err != nil {
		return nil, nil, err
	}
	//generate encrytData of the blacklist by the aeskey
	EncryptData, err := primitives.AesEncrypt(origData, AesKey)
	if err != nil {
		return nil, nil, err
	}

	//generate the public key interface
	pkdecodeBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, nil, err
	}
	pub, err := butils.DERToPublicKey(pkdecodeBytes)
	if err != nil {
		return nil, nil, err
	}
	//generate encrytKey of the aeskey
	EncryptKey, err := EciesEncrypt(AesKey, pub)
	if err != nil {
		return nil, nil, err
	}
	return EncryptData, EncryptKey, nil
}
func DecryptData(EncryptData, EncryptKey []byte, key string) ([]byte, error) {

	//generate the private key interface
	err := primitives.SetSecurityLevel("SHA2", 256)
	if err != nil {
		return nil, err
	}
	skdecodeBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}
	private, err := butils.DERToPrivateKey(skdecodeBytes)
	if err != nil {
		return nil, err
	}

	//descrypt the key from the EncryptKey
	aesKey, err := EciesDecrypt(EncryptKey, private)
	if err != nil {
		return nil, err
	}

	//descrypt the data from the EncryptData
	srcData, err := primitives.AesDecrypt(EncryptData, aesKey)
	if err != nil {
		return nil, err
	}
	return srcData, nil

}
func EciesEncrypt(originData []byte, pubkey interface{}) ([]byte, error) {
	err := primitives.SetSecurityLevel("SHA2", 256)
	if err != nil {
		return nil, err
	}
	spi := ecies.NewSPI()

	tmpPubKey, err := spi.NewPublicKey(nil, pubkey)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	publicKey, err := spi.NewAsymmetricCipherFromPublicKey(tmpPubKey)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	cryptoData, err := publicKey.Process([]byte(originData))
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	return cryptoData, nil
}

func EciesDecrypt(cryptoData []byte, tmpPrivateKey interface{}) ([]byte, error) {

	spi := ecies.NewSPI()

	tmpPriKey, err := spi.NewPrivateKey(nil, tmpPrivateKey)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	privateKey, err := spi.NewAsymmetricCipherFromPrivateKey(tmpPriKey)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	srcData, err := privateKey.Process(cryptoData)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	return srcData, nil
}
