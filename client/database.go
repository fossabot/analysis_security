package main

import (
	"encoding/gob"
	"fmt"
	"os"

	"github.com/BorysekOndrej/PV204_Noise_Protocol_and_TPM/common"
)

type clientDataStruct struct {
	ClientKeypair    common.Keypair
	ClientName       string
	ServerInfo       common.ServerInformation
	NextMsgIdToFetch uint
}

// This global variable presumes that a single process only handles a single server.
// todo: possibly change?
var localPersistenceFile string

func closeFile(f *os.File) {
	err := f.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error closing file: %v\n", err)
		os.Exit(1)
	}
}

func savePersistentData(clientData clientDataStruct) {
	file, err := os.Create(localPersistenceFile)
	defer closeFile(file)
	if err != nil {
		panic("error in create file")
	}
	encoder := gob.NewEncoder(file)
	encoder.Encode(clientData)
}

func loadPersistentData() clientDataStruct {
	file, err := os.Open(localPersistenceFile)
	if err != nil {
		panic("error loading persistent data")
	}
	var clientData clientDataStruct
	fileDecoder := gob.NewDecoder(file)
	fileDecoder.Decode(&clientData)
	return clientData
}

func doesPersistentDataExist() bool {
	_, err := os.Stat(localPersistenceFile)
	return !os.IsNotExist(err)
}
