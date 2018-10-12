package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/flynn/u2f/u2fhid"
	"github.com/flynn/u2f/u2ftoken"
)

var outputPath = "../data"

func main() {
	// Enumerate devices
	devices, err := u2fhid.Devices()
	if err != nil {
		panic(err)
	}

	// List device info
	for _, device := range devices {
		fmt.Printf("manufacturer: %s, product: %s\n", device.Manufacturer, device.Product)
	}

	// pick first device to use
	device, err := u2fhid.Open(devices[0])
	if err != nil {
		panic(err)
	}

	// create token for registration
	token := u2ftoken.NewToken(device)
	// determine version
	version, err := token.Version()
	if err != nil {
		panic(err)
	}
	fmt.Println("version:", version)

	// build appID and challenge
	application := "http://developanunderstanding.com"
	appID := sha256.Sum256([]byte(application))
	data := "streaming test"
	challenge := sha256.Sum256([]byte(data))
	registrationReq := u2ftoken.RegisterRequest{
		Challenge:   challenge[:],
		Application: appID[:],
	}

	// get user presence button press
	fmt.Println("test user presence")
	var res []byte
	for {
		res, err = token.Register(registrationReq)
		if err == u2ftoken.ErrPresenceRequired {
			continue
		}
		if err != nil {
			panic(err)
		}
		break
	}
	fmt.Println("user is present")
	fmt.Println()

	fmt.Printf("response: %x\n", res)

	err = os.RemoveAll(outputPath + "/")
	if err != nil {
		panic(err)
	}

	err = os.Mkdir(outputPath, 0666)
	if err != nil {
		panic(err)
	}

	// parse response
	if res[0] != 5 {
		panic(errors.New("registration response must begin with magic byte 0x05"))
	}
	res = res[1:] // remove magic byte
	rawpubkey := res[:65]
	ioutil.WriteFile(filepath.Join(outputPath, "pubkey"), rawpubkey, 0666)

	res = res[65:] // remove pubkey
	keyHandleLen := res[0]
	res = res[1:] // remove key handle length
	keyHandle := res[:keyHandleLen]
	res = res[keyHandleLen:] // remove key handle
	fmt.Printf("Key Handle: %x\n", keyHandle)

	ioutil.WriteFile(filepath.Join(outputPath, "keyHandle"), keyHandle, 0666)

	signature, err := asn1.Unmarshal(res, &asn1.RawValue{}) // skip cert
	if err != nil {
		panic(err)
	}

	fmt.Printf("signature: %x\n", signature)
	res = res[:len(res)-len(signature)] // remove signature from tail
	// this leaves only cert in res

	err = ioutil.WriteFile(filepath.Join(outputPath, "attestation.crt"), res, 0666)
	if err != nil {
		panic(err)
	}

	// parse cert
	cert, err := x509.ParseCertificate(res)
	if err != nil {
		panic(err)
	}

	// build signature data for verification
	buf := []byte{0}
	buf = append(buf, appID[:]...)
	buf = append(buf, challenge[:]...)
	buf = append(buf, keyHandle...)
	buf = append(buf, rawpubkey...)

	// parse r and s from signature
	// var r *big.Int
	// var s *big.Int

	// sig := signature[:]
	// if sig[0] != 48 {
	// 	panic(errors.New("signature must begin with magic byte 48"))
	// }
	// sig = sig[1:] // remove magic byte
	// zLen := int(sig[0])
	// sig = sig[1:] // remove z length
	// if len(sig) != zLen {
	// 	panic(errors.New("signature length doesn't match z length"))
	// }

	// if sig[0] != 2 {
	// 	panic(errors.New("unexpected type identifier, should be unsigned int 0x02"))
	// }
	// sig = sig[1:] // remove type specifier for r
	// rLen := sig[0]

	// sig = sig[1:] // remove r length
	// rawR := sig[:rLen]

	// sig = sig[rLen:] // remove r
	// if sig[0] != 2 {
	// 	panic(errors.New("unexpected type identifier, should be unsigned int 0x02"))
	// }

	// sig = sig[1:] // remove type specifier for s
	// sLen := sig[0]
	// sig = sig[1:] // remove s len
	// rawS := sig[:sLen]

	// r = big.NewInt(0).SetBytes(rawR)
	// s = big.NewInt(0).SetBytes(rawS)

	err = cert.CheckSignature(x509.ECDSAWithSHA256, buf, signature)
	if err == nil {
		fmt.Println("VERIFIED")
	} else {
		fmt.Printf("NOT VERIFIED: %s", err)
	}
}
