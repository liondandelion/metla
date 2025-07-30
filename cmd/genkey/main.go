package main

import (
	"crypto/rand"
	"log"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatalln("Specify filepath for the key")
	}
	key := make([]byte, 32)
	rand.Read(key)
	err := os.WriteFile(os.Args[1], key, 0600)
	if err != nil {
		log.Fatal(err)
	}
}
