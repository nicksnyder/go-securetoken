package securetoken_test

import (
	"fmt"
	"github.com/nicksnyder/go-securetoken/securetoken"
	"time"
)

func Example() {
	key := []byte("1111111111111111")
	tok, err := securetoken.NewTokener(key, 1*time.Minute)
	if err != nil {
		panic(err)
	}
	sealed, err := tok.SealString("hello world")
	if err != nil {
		panic(err)
	}
	unsealed, err := tok.UnsealString(sealed)
	if err != nil {
		panic(err)
	}

	fmt.Println(unsealed)

	// Output:
	// hello world
}
