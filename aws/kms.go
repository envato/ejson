package aws

import (
	"encoding/base64"
	"log"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
)

// DecryptPrivateKeyWithKMS decrypts private key with given KMS Key ID
func DecryptPrivateKeyWithKMS(privateKeyEnc string) (key string, err error) {
	awsSession := session.Must(session.NewSession())
	kmsSvc := kms.New(awsSession)

	encryptedValue, err := base64.StdEncoding.DecodeString(privateKeyEnc)
	if err != nil {
		return "", err
	}

	params := &kms.DecryptInput{
		CiphertextBlob: []byte(encryptedValue),
	}
	resp, err := kmsSvc.Decrypt(params)
	if err != nil {
		log.Fatalf("Unable to decrypt parameter: %v", err)
	}
	return string(resp.Plaintext), nil
}

// EncryptPrivateKeyWithKMS does stugg
func EncryptPrivateKeyWithKMS(privateKey string, kmsKeyID string) (key string, err error) {
	awsSession := session.Must(session.NewSession())
	kmsSvc := kms.New(awsSession)
	params := &kms.EncryptInput{
		KeyId:     &kmsKeyID,
		Plaintext: []byte(privateKey),
	}
	resp, err := kmsSvc.Encrypt(params)
	if err != nil {
		log.Fatalf("Unable to encrypt parameter: %v", err)
	}

	encodedPrivKey := base64.StdEncoding.EncodeToString(resp.CiphertextBlob)
	return encodedPrivKey, nil
}
