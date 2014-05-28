//+build skip

package main

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"log"
	"os"
)

func generateSharedKey(sesskey, siteid string) []byte {
	z := hmac.New(sha512.New, []byte(sesskey))
	z.Write([]byte(siteid))
	key := z.Sum([]byte{})
	return key
}

func main() {
	if len(os.Args) != 3 {
		log.Fatalln(os.Args[0], "<key> <siteid>")
	}

	log.Println("Shared secret for", os.Args[2], "-", hex.EncodeToString(generateSharedKey(os.Args[1], os.Args[2])))
}
