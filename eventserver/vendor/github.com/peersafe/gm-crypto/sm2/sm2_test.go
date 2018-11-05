package sm2

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func getTime() int64 {
	return time.Now().UnixNano() / 1000 / 1000
}

func genCert(priv *PrivateKey) error {
	// templateReq := CertificateRequest{
	// 	Subject: pkix.Name{
	// 		CommonName:   "test.example.com",
	// 		Organization: []string{"Test"},
	// 	},
	// 	//		SignatureAlgorithm: ECDSAWithSHA256,
	// 	SignatureAlgorithm: SM2WithSM3,
	// }
	// _, err = CreateCertificateRequestToPem("./test/req.pem", &templateReq, privKey)
	// if err != nil {
	// 	log.Fatal("CreateCertificateRequestToPem err : ", err)
	// }
	// req, err := ReadCertificateRequestFromPem("./test/req.pem")
	// if err != nil {
	// 	log.Fatal("ReadCertificateRequestFromPem err : ", err)
	// }
	// err = req.CheckSignature()
	// if err != nil {
	// 	log.Fatal("CheckSignature err : ", err)
	// } else {
	// 	fmt.Printf("CheckSignature ok\n")
	// }
	ok, err := WritePrivateKeytoPem("./test/priv.pem", priv, nil) // 生成密钥文件
	if ok != true {
		log.Fatal("WritePrivateKeytoPem err : ", err)
	}
	privKey, err := ReadPrivateKeyFromPem("./test/priv.pem", nil) // 读取密钥
	if err != nil {
		log.Fatal("ReadPrivateKeyFromPem err : ", err)
	}
	testExtKeyUsage := []ExtKeyUsage{ExtKeyUsageClientAuth, ExtKeyUsageServerAuth}
	testUnknownExtKeyUsage := []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 59, 1}}
	extraExtensionData := []byte("extra extension")
	commonName := "test.example.com"
	template := Certificate{
		// SerialNumber is negative to ensure that negative
		// values are parsed. This is due to the prevalence of
		// buggy code that produces certificates with negative
		// serial numbers.
		SerialNumber: big.NewInt(-1),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"org1"},
			Country:      []string{"China"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  []int{2, 5, 4, 42},
					Value: "Gopher",
				},
				// This should override the Country, above.
				{
					Type:  []int{2, 5, 4, 6},
					Value: "NL",
				},
			},
		},
		NotBefore: time.Unix(1000, 0),
		NotAfter:  time.Unix(100000, 0),

		//		SignatureAlgorithm: ECDSAWithSHA256,
		SignatureAlgorithm: SM2WithSM3,

		SubjectKeyId: []byte{1, 2, 3, 4},
		KeyUsage:     KeyUsageCertSign,

		ExtKeyUsage:        testExtKeyUsage,
		UnknownExtKeyUsage: testUnknownExtKeyUsage,

		BasicConstraintsValid: true,
		IsCA: true,

		OCSPServer:            []string{"http://ocsp.example.com"},
		IssuingCertificateURL: []string{"http://crt.example.com/ca1.crt"},

		DNSNames:       []string{"test.example.com"},
		EmailAddresses: []string{"gopher@golang.org"},
		IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},

		PolicyIdentifiers:   []asn1.ObjectIdentifier{[]int{1, 2, 3}},
		PermittedDNSDomains: []string{".example.com", "example.com"},

		CRLDistributionPoints: []string{"http://crl1.example.com/ca1.crl", "http://crl2.example.com/ca1.crl"},

		ExtraExtensions: []pkix.Extension{
			{
				Id:    []int{1, 2, 3, 4},
				Value: extraExtensionData,
			},
			// This extension should override the SubjectKeyId, above.
			{
				Id:       oidExtensionSubjectKeyId,
				Critical: false,
				Value:    []byte{0x04, 0x04, 4, 3, 2, 1},
			},
		},
	}
	pubKey, _ := priv.Public().(*PublicKey)
	ok, _ = CreateCertificateToPem("./test/cert.pem", &template, &template, pubKey, privKey)
	if ok != true {
		fmt.Printf("failed to create cert file\n")
	}

	return nil
}

func TestOnlySign(t *testing.T) {
	msg := []byte("123456")

	priv, err := GenerateKey() // 生成密钥对
	if err != nil {
		log.Fatal(err)
	}

	sign1, err := priv.Sign(nil, msg, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("sign1 111 len = %d, data = %x\n", len(sign1), sign1)

	privKey, err := ReadPrivateKeyFromPem("./test/priv.pem", nil)
	if err != nil {
		log.Fatal("failed to ReadPrivateKeyFromPem err : ", err.Error())
	}
	fmt.Printf("privKey %#v\n", privKey)

	pub := &privKey.PublicKey
	fmt.Printf("pub : %#v\n", pub)
	// sign data
	sign, err := privKey.Sign(nil, msg, nil)
	if err != nil {
		log.Fatal("failed to Sign err : ", err.Error())
	}
	fmt.Printf("sign len = %d, data = %x\n", len(sign), sign)
	err = ioutil.WriteFile("./test/signature", sign, os.FileMode(0666))
	if err != nil {
		log.Fatal("failed to WriteFile err : ", err.Error())
	}

	fmt.Printf("verify : %v\n", pub.Verify(msg, sign))
}

func TestOnlyVerify(t *testing.T) {
	for i := 0; i < 10000; i++ {
		msg := []byte("123456")
		cert, err := ReadCertificateFromPem("./test/cert.pem")
		if err != nil {
			fmt.Println(err)
			log.Fatal("failed to ReadCertificateFromPem err : ", err.Error())
		}

		sign, err := ioutil.ReadFile("./test/signature")
		if err != nil {
			log.Fatal("failed to ReadFile err : ", err.Error())
		}
		// fmt.Printf("sign len = %d, data = %x\n", len(sign), sign)

		// verify
		tmp := cert.PublicKey.(*ecdsa.PublicKey)
		pub := &PublicKey{
			X:     tmp.X,
			Y:     tmp.Y,
			Curve: tmp.Curve,
		}
		// fmt.Printf("pub : %#v\n", pub)
		// for i := 0; i < 10000; i++ {

		verify := false
		verify = pub.Verify(msg, sign)
		if !verify {
			fmt.Println("verify failed")
			break
		}
	}
}

func TestKey(t *testing.T) {
	//for i := 0; i < 500000; i++ {
		GenerateKey()
	//}
}

func TestSm2Cert(t *testing.T) {
	i := 0
	for  {
		testSm2Cert()
		fmt.Println(i)
		i++
	}
}

func testSm2Cert() {
	msg := []byte("123456")
	priv, err := GenerateKey() // 生成密钥对
	if err != nil {
		log.Fatal(err)
	}
	// generate cert and write to file
	if err = genCert(priv); err != nil {
		log.Fatal(err)
	}

	cert, err := ReadCertificateFromPem("./test/cert.pem")
	if err != nil {
		log.Fatal("failed to read cert file err : ", err.Error())
	}

	privKey, err := ReadPrivateKeyFromPem("./test/priv.pem", nil)
	// sign data
	sign, err := privKey.Sign(nil, msg, nil)
	if err != nil {
		log.Fatal("failed to Sign err : ", err.Error())
	}

	// verify
	tmp := cert.PublicKey.(*ecdsa.PublicKey)
	pub := &PublicKey{
		X:     tmp.X,
		Y:     tmp.Y,
		Curve: tmp.Curve,
	}

	// for i := 0; i < 100; i++ {
	verify := pub.Verify(msg, sign)
	if !verify {
		log.Fatal("verify failed")
		// break
	}
	// }

	// fmt.Printf("pub key : \n%#v\n", pub)
	// pub1 := &PublicKey{}
	// curve := P256Sm2()
	// pub1.Curve = curve
	// pub1.X = tmp.X
	// pub1.Y = tmp.Y
	// fmt.Printf("pub1 key : \n%#v\n", pub1)
	// fmt.Printf("pub1 key verify : %v\n", pub1.Verify(msg, sign))

	err = cert.CheckSignatureFrom(cert)
	if err != nil {
		fmt.Printf("check signature from ret : %v\n", err)
	}
	err = cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	if err != nil {
		fmt.Printf("check signature ret : %v\n", err)
	}

	priv_son, err := GenerateKey() // 生成密钥对
	if err != nil {
		log.Fatal(err)
	}

	pub_son := priv_son.PublicKey
	cert_son, err := SignCertificate("./test", "son.pem", nil, &pub_son, cert.KeyUsage, cert.ExtKeyUsage, priv, cert)
	if err != nil {
		log.Fatal(err)
	}
	err = cert_son.CheckSignatureFrom(cert)
	if err != nil {
		fmt.Printf("check signature from 111111 ret : %v\n", err)
	}
}

func x509Template() Certificate {

	// generate a serial number
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	// set expiry to around 10 years
	expiry := 3650 * 24 * time.Hour
	// backdate 5 min
	notBefore := time.Now().Add(-5 * time.Minute).UTC()

	//basic template to use
	x509 := Certificate{
		SerialNumber:          serialNumber,
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(expiry).UTC(),
		BasicConstraintsValid: true,
	}
	return x509

}

func subjectTemplate() pkix.Name {
	return pkix.Name{
		Country:  []string{"US"},
		Locality: []string{"San Francisco"},
		Province: []string{"California"},
	}
}

func SignCertificate(baseDir, name string, sans []string, pub *PublicKey,
	ku KeyUsage, eku []ExtKeyUsage, priv *PrivateKey, signCert *Certificate) (*Certificate, error) {

	template := x509Template()
	template.KeyUsage = ku
	template.ExtKeyUsage = eku

	//set the organization for the subject
	subject := subjectTemplate()
	subject.CommonName = name

	template.Subject = subject
	template.DNSNames = sans
	template.PublicKey = pub

	sm2Tpl := ParseX509Certificate2Sm2(&template)
	cert, err := genCertificateGMSM2(baseDir, name, sm2Tpl, signCert, pub, priv)

	if err != nil {
		return nil, err
	}

	return cert, nil
}

func ParseX509Certificate2Sm2(x509Cert *Certificate) *Certificate {
	sm2cert := &Certificate{
		Raw:                     x509Cert.Raw,
		RawTBSCertificate:       x509Cert.RawTBSCertificate,
		RawSubjectPublicKeyInfo: x509Cert.RawSubjectPublicKeyInfo,
		RawSubject:              x509Cert.RawSubject,
		RawIssuer:               x509Cert.RawIssuer,

		Signature:          x509Cert.Signature,
		SignatureAlgorithm: SignatureAlgorithm(x509Cert.SignatureAlgorithm),

		PublicKeyAlgorithm: PublicKeyAlgorithm(x509Cert.PublicKeyAlgorithm),
		PublicKey:          x509Cert.PublicKey,

		Version:      x509Cert.Version,
		SerialNumber: x509Cert.SerialNumber,
		Issuer:       x509Cert.Issuer,
		Subject:      x509Cert.Subject,
		NotBefore:    x509Cert.NotBefore,
		NotAfter:     x509Cert.NotAfter,
		KeyUsage:     KeyUsage(x509Cert.KeyUsage),

		Extensions: x509Cert.Extensions,

		ExtraExtensions: x509Cert.ExtraExtensions,

		UnhandledCriticalExtensions: x509Cert.UnhandledCriticalExtensions,

		//ExtKeyUsage:	[]x509.ExtKeyUsage(x509Cert.ExtKeyUsage) ,
		UnknownExtKeyUsage: x509Cert.UnknownExtKeyUsage,

		BasicConstraintsValid: x509Cert.BasicConstraintsValid,
		IsCA:       x509Cert.IsCA,
		MaxPathLen: x509Cert.MaxPathLen,
		// MaxPathLenZero indicates that BasicConstraintsValid==true and
		// MaxPathLen==0 should be interpreted as an actual maximum path length
		// of zero. Otherwise, that combination is interpreted as MaxPathLen
		// not being set.
		MaxPathLenZero: x509Cert.MaxPathLenZero,

		SubjectKeyId:   x509Cert.SubjectKeyId,
		AuthorityKeyId: x509Cert.AuthorityKeyId,

		// RFC 5280, 4.2.2.1 (Authority Information Access)
		OCSPServer:            x509Cert.OCSPServer,
		IssuingCertificateURL: x509Cert.IssuingCertificateURL,

		// Subject Alternate Name values
		DNSNames:       x509Cert.DNSNames,
		EmailAddresses: x509Cert.EmailAddresses,
		IPAddresses:    x509Cert.IPAddresses,

		// Name constraints
		PermittedDNSDomainsCritical: x509Cert.PermittedDNSDomainsCritical,
		PermittedDNSDomains:         x509Cert.PermittedDNSDomains,

		// CRL Distribution Points
		CRLDistributionPoints: x509Cert.CRLDistributionPoints,

		PolicyIdentifiers: x509Cert.PolicyIdentifiers,
	}
	for _, val := range x509Cert.ExtKeyUsage {
		sm2cert.ExtKeyUsage = append(sm2cert.ExtKeyUsage, ExtKeyUsage(val))
	}

	return sm2cert
}

func genCertificateGMSM2(baseDir, name string, template, parent *Certificate, pub *PublicKey,
	key *PrivateKey) (*Certificate, error) {

	//create the x509 public cert
	certBytes, err := CreateCertificateToMem(template, parent, pub, key)

	if err != nil {
		return nil, err
	}

	//write cert out to file
	fileName := filepath.Join(baseDir, name+"-cert.pem")
	err = ioutil.WriteFile(fileName, certBytes, os.FileMode(0666))

	// certFile, err := os.Create(fileName)
	if err != nil {
		return nil, err
	}

	// //pem encode the cert
	// err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	// certFile.Close()
	// if err != nil {
	// 	return nil, err
	// }
	//x509Cert, err := sm2.ReadCertificateFromPem(fileName)

	x509Cert, err := ReadCertificateFromMem(certBytes)
	if err != nil {
		return nil, err
	}
	return x509Cert, nil

}

// func TestSign(t *testing.T) {
// 	msg := []byte{1}
// 	msg1 := []byte{1}

// 	priv, err := GenerateKey() // 生成密钥对
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	signature, err := priv.Sign(nil, msg, nil)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	signature1 := make([]byte, len(signature))
// 	signature1 = signature

// 	fmt.Printf("signature len = %d, data = %x\n", len(signature), signature)

// 	if priv.Verify(msg, signature) {
// 		fmt.Println("Use msg verify successed 11111111111111111111!")
// 	} else {
// 		fmt.Println("Use msg verify failed !")
// 	}

// 	if priv.Verify(msg1, signature) {
// 		fmt.Println("Use msg1 verify successed 2222222222222222222222!")
// 	} else {
// 		fmt.Println("Use msg1 verify failed !")
// 	}

// 	if priv.Verify(msg1, signature1) {
// 		fmt.Println("Use msg1, signature1 verify successed 3333333333333333!")
// 	} else {
// 		fmt.Println("Use msg1, signature1 verify failed !")
// 	}
// }

// func TestSm2(t *testing.T) {
// var err error
// var sign []byte
// // var d0 []byte
// var start, end int64
// var priv *PrivateKey
// blockSize := 1024
// cricleTimes := 1
// ok := true

// start = getTime()
// for i := 0; i < cricleTimes; i++ {
// 	priv, err = GenerateKey() // 生成密钥对
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	break
// }
// end = getTime()
// fmt.Printf("generate key %d times use %d ms!\n", cricleTimes, end-start)

// pub := &priv.PublicKey
// var msg []byte
// for i := 0; i < blockSize; i++ {
// 	msg = append(msg, 'a')
// }

// start = getTime()
// for i := 0; i < cricleTimes; i++ {
// 	break
// 	d0, err = pub.Encrypt(msg)
// 	if err != nil {
// 		fmt.Printf("Error: failed to encrypt %s: %v\n", msg, err)
// 		return
// 	}
// }
// end = getTime()
// fmt.Printf("encrypt %d times use %d ms!\n", cricleTimes, end-start)

// start = getTime()
// for i := 0; i < cricleTimes; i++ {
// 	break
// 	_, err = priv.Decrypt(d0)
// 	if err != nil {
// 		fmt.Printf("Error: failed to decrypt: %v\n", err)
// 	}
// }
// end = getTime()
// fmt.Printf("decrypt %d times use %d ms!\n", cricleTimes, end-start)

// start = getTime()
// for i := 0; i < cricleTimes; i++ {
// 	sign, err = priv.Sign(msg) // 签名
// 	if err != nil {
// 		fmt.Printf("Error: failed to sign: %v\n", err)
// 	}
// }
// end = getTime()
// fmt.Printf("sign %d times use %d ms!\n", cricleTimes, end-start)

// start = getTime()
// for i := 0; i < cricleTimes; i++ {
// 	ok = priv.Verify(msg, sign) // 签名
// 	if !ok {
// 		fmt.Printf("Error: failed to verify: %v\n", err)
// 	}
// }
// end = getTime()
// fmt.Printf("verify %d times use %d ms!\n", cricleTimes, end-start)
// }

// func BenchmarkSM2(t *testing.B) {
// 	t.ReportAllocs()
// 	for i := 0; i < t.N; i++ {
// 		priv, err := GenerateKey() // 生成密钥对
// 		if err != nil {
// 			log.Fatal(err)
// 		}
// 		msg := []byte("test")
// 		sign, err := priv.Sign(rand.Reader, msg, nil) // 签名
// 		if err != nil {
// 			log.Fatal(err)
// 		}
// 		ok := priv.Verify(msg, sign) // 密钥验证
// 		if ok != true {
// 			fmt.Printf("Verify error\n")
// 		} else {
// 			fmt.Printf("Verify ok\n")
// 		}
// 	}
// }
