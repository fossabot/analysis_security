package common

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"io"
	//	"encoding/hex"
	"log"
)

func getPCRCount(tpmHandle io.ReadWriteCloser) uint32 {
	caps, _, err := tpm2.GetCapability(tpmHandle, tpm2.CapabilityTPMProperties, 1, uint32(tpm2.PCRCount))
	if err != nil {
		log.Fatal(err)
	}
	return caps[0].(tpm2.TaggedProperty).Value
}

func isAlgorithmSupportedByTPM(tpmHandle io.ReadWriteCloser, checkedAlgorithm tpm2.Algorithm) bool {
	algorithms, _, err := tpm2.GetCapability(tpmHandle, tpm2.CapabilityAlgs, 1000, 0)

	if err != nil {
		log.Fatal(err)
	}

	for _, currentAlgorithm := range algorithms {
		if currentAlgorithm.(tpm2.AlgorithmDescription).ID == checkedAlgorithm {
			return true
		}
	}

	return false
}

func isCurrentTPMSupported(tpmHandle io.ReadWriteCloser) error {
	if !isAlgorithmSupportedByTPM(tpmHandle, tpm2.AlgRSA) {
		return errors.New("AlgRSA is not supported by your TPM")
	}
	if !isAlgorithmSupportedByTPM(tpmHandle, tpm2.AlgSHA256) {
		return errors.New("AlgSHA256 is not supported by your TPM")
	}
	if !isAlgorithmSupportedByTPM(tpmHandle, tpm2.AlgRSASSA) {
		return errors.New("AlgRSASSA is not supported by your TPM")
	}
	if getPCRCount(tpmHandle) < 8 {
		return errors.New("Your TPM does not support enough PCR registers")
	}
	return nil
}

/*
	Returns public key.

	Owner of the handle needs to dispose of it using

	defer tpm2.FlushContext(tpm_handle, keyHandle)

*/
func getEndorsementKeyHandle(tpmHandle io.ReadWriteCloser, pcrs tpm2.PCRSelection) (tpmutil.Handle, rsa.PublicKey) {
	params := tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagSignerDefault | tpm2.FlagNoDA,
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSASSA,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits: 2048,
		},
	}

	keyHandle, pub, err := tpm2.CreatePrimary(tpmHandle, tpm2.HandleEndorsement, pcrs, "", "", params)
	if err != nil {
		log.Fatal("CreatePrimary failed: %s", err)
	}

	return keyHandle, *(pub.(*rsa.PublicKey))
}

func attestNonce(tpmHandle io.ReadWriteCloser, pcrs tpm2.PCRSelection, nonce []byte, keyHandle tpmutil.Handle) ([]byte, *tpm2.Signature) {
	attestationRaw, signature, err := tpm2.Quote(tpmHandle, keyHandle, "", "", nonce, pcrs, tpm2.AlgNull)
	if err != nil {
		log.Fatal(err)
	}
	return attestationRaw, signature

}

func generateNonce() []byte {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		log.Fatal(err)
	}
	return bytes
}

func chosenPCRSelection() tpm2.PCRSelection {
	return tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{0, 1, 2, 3, 4, 5, 6, 7, 8}}
}

func attestNonceInternal(nonce []byte) (rsa.PublicKey, []byte, *tpm2.Signature) {
	tpmHandle := getTPMHandle()
	defer tpmHandle.Close()

	pcrs := chosenPCRSelection()

	keyHandle, pubkey := getEndorsementKeyHandle(tpmHandle, pcrs)
	rawAttestationData, signature := attestNonce(tpmHandle, pcrs, nonce, keyHandle)
	tpm2.FlushContext(tpmHandle, keyHandle)

	return pubkey, rawAttestationData, signature

}
