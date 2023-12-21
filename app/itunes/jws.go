package itunes

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/joho/godotenv"
)

type JWS interface {
	GenerateJWT() (string, error)
	ExtractJWSPayload(jws string) (string, error)
}

type jws struct{}

func NewJWS() JWS {
	return jws{}
}

func (j jws) GenerateJWT() (string, error) {
	err := godotenv.Load()
	if err != nil {
		return "", fmt.Errorf("Error loading .env file: %v", err)
	}

	// Obtener las variables de entorno
	issuerID := os.Getenv("ISSUER_ID")
	keyID := os.Getenv("KEY_ID")
	bundleID := os.Getenv("BUNDLE_ID")

	now := time.Now()
	issuedAt := now.Unix()
	expiration := now.Add(time.Minute).Unix()

	claims := jwt.MapClaims{
		"iss": issuerID,
		"iat": issuedAt,
		"exp": expiration,
		"aud": "appstoreconnect-v1",
		"bid": bundleID,
	}

	privateKeyPEM, err := os.ReadFile("app/config/private_key.pem")
	if err != nil {
		return "", err
	}

	block, _ := pem.Decode(privateKeyPEM)
	if block == nil || block.Type != "PRIVATE KEY" {
		return "", fmt.Errorf("failed to decode PEM block containing private key")
	}

	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

	token.Header["kid"] = keyID
	tokenString, err := token.SignedString(privKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (j jws) ExtractJWSPayload(jws string) (string, error) {
	parts := strings.Split(jws, ".")

	payloadBase64 := parts[0]

	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadBase64)
	if err != nil {
		// Manejo de errores en caso de que la decodificación falle
		return "", err
	}

	return string(payloadBytes), nil
}
