package securetoken_test

import (
	"crypto/aes"
	"crypto/sha1"
	"fmt"
	"time"

	"github.com/nicksnyder/go-securetoken/securetoken"
)

func Example() {
	key := []byte("1234567887654321")
	tokener, err := securetoken.NewTokener(key, 24*time.Hour, sha1.New, aes.NewCipher)
	if err != nil {
		panic(err)
	}

	token, err := tokener.Encode([]byte("secretuserid"))
	if err != nil {
		panic(err)
	}

	data, err := tokener.Decode(token)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(data))

	// Output:
	// secretuserid
}
