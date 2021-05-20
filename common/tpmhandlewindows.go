// +build windows

package common

import (
	"io"
	"log"

	"github.com/google/go-tpm/tpm2"
)

var TPM_PATH = "IGNORED_ON_WINDOWS"

func getTPMHandle() io.ReadWriteCloser {
	tpm_handle, err := tpm2.OpenTPM()
	if err != nil {
		log.Fatal(err)
	}
	return tpm_handle
}
