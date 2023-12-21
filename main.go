package main

import (
	"bufio"
	"fmt"
	"os"

	"github.com/whitejokeer/jwt/app/itunes"
)

func main() {
	var jws itunes.JWS
	jws = itunes.NewJWS()

	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Select an option:")
	fmt.Println("1. Generate JWT")
	fmt.Println("2. Decrypt Receipt")

	option, _ := reader.ReadString('\n')

	switch option {
	case "1\n":
		generateJWT(jws)
	case "2\n":
		fmt.Println("Enter receipt:")
		receipt, _ := reader.ReadString('\n')
		decryptJWT(jws, receipt)
	default:
		fmt.Println("Invalid option")
	}
}

func decryptJWT(jws itunes.JWS, receipt string) {
	data, err := jws.ExtractJWSPayload(receipt)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(data)
}

func generateJWT(jws itunes.JWS) {
	jwt, err := jws.GenerateJWT()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(jwt)
}
