// +build !windows

package common

import (
	"io"
	"log"

	"github.com/google/go-tpm/tpm2"
)

var TPM_PATH = "/dev/tpm0" // This is default, but it might get overwriten from CLI.

func getTPMHandle() io.ReadWriteCloser {
	tpmHandle, err := tpm2.OpenTPM(TPM_PATH)
	if err != nil {
		log.Fatal("Failed to open TPM path: ", TPM_PATH, err)
	}
	return tpmHandle
}
