package common

/*
TODO: Add serializing of messages, so the server can easily communicate with client.
*/

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"fmt"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	//	"encoding/hex"
	"log"
)

func ClientCreatetpmregistrationdata() (rsa.PublicKey, tpmutil.U16Bytes) {
	pubkey, rawAttestation, _ := attestNonceInternal(generateNonce())

	attestationDecoded, err := tpm2.DecodeAttestationData(rawAttestation)
	if err != nil {
		log.Fatal(err)
	}

	return pubkey, (*attestationDecoded.AttestedQuoteInfo).PCRDigest
}

func ServerTpmgenerateNonce() []byte {
	return generateNonce()
}

func ClientAttestnonce(nonce []byte) ([]byte, *tpm2.Signature) {
	_, rawAttestation, signature := attestNonceInternal(nonce)
	return rawAttestation, signature
}

func ServerVerifyattestation(clientPubKey rsa.PublicKey, clientGoldenAttestationValue tpmutil.U16Bytes, nonce []byte, attestation []byte, signature *tpm2.Signature) bool {
	hsh := crypto.SHA256.New()
	hsh.Write(attestation)
	if err := rsa.VerifyPKCS1v15(&clientPubKey, crypto.SHA256, hsh.Sum(nil), signature.RSA.Signature); err != nil {
		fmt.Println("VerifyPKCS1v15 failed: %v", err)
		return false
	}

	attestationDecoded, err := tpm2.DecodeAttestationData(attestation)
	if err != nil {
		fmt.Println(err)
		return false
	}

	if bytes.Compare(clientGoldenAttestationValue, (*attestationDecoded.AttestedQuoteInfo).PCRDigest) != 0 {
		log.Println("Expected digest: ", clientGoldenAttestationValue)
		log.Println("Found digest: ", (*attestationDecoded.AttestedQuoteInfo).PCRDigest)
		fmt.Println("Attested quote is not equal to golden value")
		return false
	}

	if bytes.Compare(nonce, (*attestationDecoded).ExtraData) != 0 {
		log.Println("Expected nonce: ", nonce)
		log.Println("Found nonce: ", (*attestationDecoded).ExtraData)
		fmt.Println("Invalid nonce in attestation data.")
		return false
	}
	return true
}
