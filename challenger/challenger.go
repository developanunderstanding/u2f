package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"strconv"

	"github.com/flynn/u2f/u2fhid"
	"github.com/flynn/u2f/u2ftoken"
)

var outputPath = "../data/"

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

	keyHandle, err := ioutil.ReadFile(outputPath + "keyHandle")
	if err != nil {
		panic(err)
	}

	authReq := u2ftoken.AuthenticateRequest{
		Application: appID[:],
		Challenge:   challenge[:],
		KeyHandle:   keyHandle,
	}
	err = token.CheckAuthenticate(authReq)
	if err != nil {
		panic(err)
	}

	fmt.Println("auth request checks out")

	fmt.Println("test user presence")
	var res *u2ftoken.AuthenticateResponse
	for {
		res, err = token.Authenticate(authReq)
		if err == u2ftoken.ErrPresenceRequired {
			continue
		}
		if err != nil {
			panic(err)
		}
		break
	}
	fmt.Println("user is present")

	fmt.Printf("raw: %x\n", res.RawResponse)

	var prevCounter uint32
	rawPrevCounter, err := ioutil.ReadFile(outputPath + "prevCounter")
	if os.IsNotExist(err) {
		prevCounter = 1
	} else if err != nil {
		panic(err)
	} else {
		temp, err := strconv.ParseUint(string(rawPrevCounter), 10, 32)
		if err != nil {
			panic(err)
		}
		prevCounter = uint32(temp)
	}
	if res.Counter != prevCounter+1 {
		panic(errors.New("key was used somewhere else"))
	} else {
		fmt.Printf("counter value %d is what it's expected to be\n", res.Counter)
	}

	buf := appID[:]
	buf = append(buf, res.RawResponse[:5]...)
	buf = append(buf, challenge[:]...)
	hash := sha256.Sum256(buf)

	rawpubkey, err := ioutil.ReadFile(outputPath + "pubkey")
	if err != nil {
		panic(err)
	}

	x, y := elliptic.Unmarshal(elliptic.P256(), rawpubkey)
	pubkey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	// parse r and s from signature
	var r *big.Int
	var s *big.Int

	sig := res.Signature[:]
	if sig[0] != 48 {
		panic(errors.New("signature must begin with magic byte 48"))
	}
	sig = sig[1:] // remove magic byte
	zLen := int(sig[0])
	sig = sig[1:] // remove z length
	if len(sig) != zLen {
		panic(errors.New("signature length doesn't match z length"))
	}

	if sig[0] != 2 {
		panic(errors.New("unexpected type identifier, should be unsigned int 0x02"))
	}
	sig = sig[1:] // remove type specifier for r
	rLen := sig[0]

	sig = sig[1:] // remove r length
	rawR := sig[:rLen]

	sig = sig[rLen:] // remove r
	if sig[0] != 2 {
		panic(errors.New("unexpected type identifier, should be unsigned int 0x02"))
	}

	sig = sig[1:] // remove type specifier for s
	sLen := sig[0]
	sig = sig[1:] // remove s len
	rawS := sig[:sLen]

	r = big.NewInt(0).SetBytes(rawR)
	s = big.NewInt(0).SetBytes(rawS)

	verified := ecdsa.Verify(pubkey, hash[:], r, s)
	if verified {
		fmt.Println("AUTHENTICATED")
	} else {
		fmt.Println("NOT AUTHENTICATED")
		os.Exit(0)
	}

	counterStr := strconv.FormatUint(uint64(res.Counter), 10)
	err = ioutil.WriteFile(outputPath+"prevCounter", []byte(counterStr), 0666)
	if err != nil {
		panic(err)
	}
}
