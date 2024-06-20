package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	//"golang.org/x/oauth2/google"
	//"google.golang.org/api/cloudkms/v1"
        kms "cloud.google.com/go/kms/apiv1"
        kmspb "cloud.google.com/go/kms/apiv1/kmspb"	
)

func main() {
	keyFlag := flag.String("key", "", "")
	commonNameFlag := flag.String("common-name", "", "")
	//orgFlag := flag.String("org", "", "")
	outFlag := flag.String("out", "out.csr", "")
	//countryFlag := flag.String("country", "", "")
	//localityFlag := flag.String("locality", "", "")

	flag.Parse()

	// Create the client.
        ctx := context.Background()
        client, err := kms.NewKeyManagementClient(ctx)
        if err != nil {
                log.Fatalf("failed to setup client: %v", err)
        }
        defer client.Close()

	s, err := NewGoogleKMSSigner(client, *keyFlag)
	if err != nil {
		log.Fatal(err)
	}
        template := x509.CertificateRequest{
            Subject: pkix.Name{
	    	CommonName:         *commonNameFlag,
		//Organization:       []string{*orgFlag},
		//Country:            []string{*countryFlag},
		//Locality:           []string{*localityFlag},
            },
        }
	
	f, err := os.Create(*outFlag)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	if err := CreateCertificateRequest(f, template, s); err != nil {
		log.Fatal(err)
	}
}

func CreateCertificateRequest(w io.Writer, template *x509.CertificateRequest, signer crypto.Signer) error {
	out, err := x509.CreateCertificateRequest(rand.Reader, template, signer)
	if err != nil {
		return err
	}

	return pem.Encode(w, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: out})
}

type GoogleKMS struct {
	keyResourceId string
	publicKey     crypto.PublicKey
	client	kms.AutokeyClient
}

func NewGoogleKMSSigner(client kms.AutokeyClient, keyResourceId string) (*GoogleKMS, error) {
	g := &GoogleKMS{
		keyResourceId: keyResourceId,
		client: client,
	}

	err := g.getAsymmetricPublicKey()
	if err != nil {
		return nil, err
	}

	return g, nil
}

// Public returns the Public Key from Google Cloud KMS
func (g *GoogleKMS) Public() crypto.PublicKey {
	return g.publicKey
}

// Sign calls Google Cloud KMS API and performs AsymmetricSign
func (g *GoogleKMS) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	// API expects the digest to be base64 encoded
	digest64 := base64.StdEncoding.EncodeToString(digest)

	req := &kmspb.AsymmetricSignRequest{
		Name: keyResourceId,
		Digest: &kmspb.Digest{
			Sha256: digest64, // TODO: sha256 needs to follow sign algo
		},
	}
        // Call the API.
        response, err := client.AsymmetricSign(ctx, req)
        if err != nil {
                return fmt.Errorf("failed to sign digest: %w", err)
        }

	// The response signature is base64 encoded
	return base64.StdEncoding.DecodeString(response.Signature)
}

// getAsymmetricPublicKey pulls public key from Google Cloud KMS API
func (g *GoogleKMS) getAsymmetricPublicKey() error {
// Retrieve the public key from KMS.
        response, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: keyResourceId})
        if err != nil {
                return fmt.Errorf("failed to get public key: %w", err)
        }
	
	block, _ := pem.Decode([]byte(response.Pem))
	if block == nil || block.Type != "PUBLIC KEY" {
		return fmt.Errorf("not a public key")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}

	g.publicKey = publicKey
	return nil
}
