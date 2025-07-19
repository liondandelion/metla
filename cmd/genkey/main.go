package main

import (
	"crypto/rand"
	"os"
)

func main() {
	key := make([]byte, 32)
	rand.Read(key)
	os.Stdout.Write(key)
}
