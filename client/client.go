package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/BorysekOndrej/PV204_Noise_Protocol_and_TPM/common"
)

func sendMessage(message string) {
	encryptedSession := initializeSecureConnection(common.MessageTypeSend)
	encryptedSession.SendEncryptedData(message)
}

func receiveMessages() {
	persData := loadPersistentData()
	var maxIdSeenInBatch uint = 0

	encryptedSession := initializeSecureConnection(common.MessageTypeReceive)
	encryptedSession.SendEncryptedData(persData.NextMsgIdToFetch)

	var simplifiedMessages []common.SimplifiedMessage
	encryptedSession.ReceiveEncryptedData(&simplifiedMessages)
	// fmt.Println(simplifiedMessages)

	if len(simplifiedMessages) > 0 {
		fmt.Println("")
		for _, s := range simplifiedMessages {
			maxIdSeenInBatch = common.MaxUint(maxIdSeenInBatch, s.ID)
			fmt.Println(s.AuthorUsername, "| ", s.Content)
		}
		fmt.Print("> ")
	}

	// log.Println(maxIdSeenInBatch, persData.NextMsgIdToFetch)

	if maxIdSeenInBatch >= persData.NextMsgIdToFetch {
		persData.NextMsgIdToFetch = maxIdSeenInBatch + 1
		savePersistentData(persData)
	}
}

func registrationProcess(serverString string, username string, keyfile string) {
	var serverData common.ServerInformation
	serverData, serverString = handleServerString(serverString, serverData)
	fmt.Println(serverData)

	registerClient(username, serverData)
}

func handleServerString(serverString string, serverData common.ServerInformation) (common.ServerInformation, string) {

	serverDecodedString, err := base64.StdEncoding.DecodeString(serverString)
	if err != nil {
		log.Fatal("Please check your server string", err)
	}
	buf := bytes.Buffer{}
	_, err = buf.Write(serverDecodedString)
	if err != nil {
		log.Fatal("Buffer internal error ", err)
	}
	decoder := gob.NewDecoder(&buf)
	err = decoder.Decode(&serverData)

	if err != nil {
		log.Fatal("Please check your server string", err)
	}

	return serverData, serverString
}

func pollingFunction(period int) {
	for {
		receiveMessages()
		time.Sleep(time.Duration(period) * time.Second)
	}
}

func login(keyfile string) {
	localPersistenceFile = filepath.Clean(keyfile)
	if !doesPersistentDataExist() {
		log.Fatal("Perform registration first. Aborting.")
	}

}

func interactiveMode(period int) {
	scanner := bufio.NewScanner(os.Stdin)

	go pollingFunction(period)
	for {
		fmt.Print("> ")
		scanner.Scan()
		sendMessage(scanner.Text())
	}

}

func registerSafe(serverString string, username string, keyfile string) {
	localPersistenceFile = filepath.Clean(keyfile)
	if doesPersistentDataExist() {
		log.Fatal("Local registration already exists. Aborting.")
	}
	registrationProcess(serverString, username, keyfile)
}
