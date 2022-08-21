package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"github.com/spcnvdr/gopost/internal/files"
)

/* Generate TLS keys and helper functions */

/*
genKeys - Generate self-signed TLS certificate and key.
Shamelessly stolen and modified from:
https://go.dev/src/crypto/tls/generate_cert.go
*/
func GenKeys(host string) {

	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	notBefore := time.Now()
	// Good for 2 weeks
	notAfter := notBefore.Add(14 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Mini File Server"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	hosts := strings.Split(host, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}

	// Don't overwrite existing certs
	if files.Exists("cert.pem") {
		log.Fatal("Failed to write cert.pem: file already exists!")
	}

	if err = WriteCertFile("cert.pem", derBytes); err != nil {
		log.Fatalf("Failed to create TLS certificate")
	}

	// Don't overwrite existing key file
	if files.Exists("key.pem") {
		log.Fatal("Failed to write key.pem: file already exists!")
	}

	if err = WriteKeyFile("key.pem", priv); err != nil {
		log.Fatalf("Failed to write key file: %v", err)
	}

}

/*
writeKeyFile creates and writes an ECDSA private key to a pem file with
the given name
*/
func WriteKeyFile(name string, privKey *ecdsa.PrivateKey) error {
	keyOut := OpenKeyFile(name)
	defer files.CloseFile(keyOut)

	privBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return err
	}
	err = pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	return err
}

// openKeyFile creates and opens a file to write ecdsa key to
func OpenKeyFile(name string) *os.File {
	keyOut, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Failed to open key.pem for writing: %v", err)
	}
	return keyOut
}

// Write an X.509 certificate to a file with the given name
func WriteCertFile(name string, data []byte) error {
	certOut := files.CreateFile(name)
	defer files.CloseFile(certOut)

	err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: data})
	return err
}
