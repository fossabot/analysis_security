package main

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"fmt"
	"log"
	"net"

	"github.com/BorysekOndrej/PV204_Noise_Protocol_and_TPM/common"
	"github.com/google/go-tpm/tpm2"
)

const location string = "127.0.0.1:6666"

func initServer() {
	/*
		This function should check initialize database,
		generate public key if it's not in database etc.
	*/
	CreateDatabase()
	getOrGenerateServerKeypair()
}

func getOrGenerateServerKeypair() common.Keypair {
	var serverKeypair common.Keypair
	var existingServerKeypair *common.Keypair

	existingServerKeypair = getServerKeypair()

	if existingServerKeypair == nil {
		fmt.Println("No server keypair was found in DB, generating a new one.")
		saveServerKeypair(common.GenerateKeypair())
		existingServerKeypair = getServerKeypair()
	}
	serverKeypair = *existingServerKeypair

	// fmt.Println(server_keypair)
	return serverKeypair
}

func handleRegistration(session *common.PlaintextSession, tmpEncSession *common.EncryptedSession) {
	var regStruct common.RegistrationStruct
	var clientPubKey [32]byte
	returnCode := common.RegistrationOK
	err := tmpEncSession.ReceiveEncryptedData(&clientPubKey)

	if err != nil {
		fmt.Println("Registration failed", err)
		returnCode = common.RegistrationFail
		return
	}
	encSession, err := handshake(session, clientPubKey)
	if err != nil {
		log.Println(err)
		_ = encSession.SendEncryptedData(common.RegistrationFail)
		return
	}

	err = encSession.ReceiveEncryptedData(&regStruct)
	if err != nil {
		fmt.Println("Registration failed ")
		_ = encSession.SendEncryptedData(common.RegistrationFail)
		return
	}
	errRegistation := registerUser(regStruct)
	if errRegistation == DuplicateRegistration {
		returnCode = common.RegistionUsernameAlreadyUsed
	}

	err = encSession.SendEncryptedData(returnCode)
	if err != nil {
		return
	}
}

func attestTPM(session *common.EncryptedSession, reg common.RegistrationStruct) bool {

	// Step 1: server generates nonce and sends it to client
	nonce := common.ServerTpmgenerateNonce()
	err := session.SendEncryptedData(nonce)
	if err != nil {
		return false
	}

	// Step 2:

	var attestation []byte
	var signature *tpm2.Signature

	err = session.ReceiveEncryptedData(&attestation)
	if err != nil {
		return false
	}
	err = session.ReceiveEncryptedData(&signature)
	if err != nil {
		return false
	}

	return common.ServerVerifyattestation(reg.TPMPublicKey, reg.TpmGoldenString, nonce, attestation, signature)
}

func initSession(session *common.PlaintextSession, username string) (*common.EncryptedSession, string, error) {

	regStructLocal := getRegistrationStructByUsername(username)
	noiseSession, err := handshake(session, regStructLocal.NoisePubKey)
	if err != nil {
		return nil, "", err
	}

	if attestTPM(noiseSession, *regStructLocal) {
		fmt.Println("TPM Succesfuly attested")
	} else {
		fmt.Println("Session not initiated")
		return nil, "", errors.New("Session not initiated")
	}

	/*
		Here the noise handshake should be performed. function should return noisesession
	*/

	return noiseSession, username, nil

}

func handshake(session *common.PlaintextSession, clientpubkey [32]byte) (*common.EncryptedSession, error) {
	var noiseSession common.Noisesession
	noiseSession = common.InitSession(false, []byte("demo"), getOrGenerateServerKeypair(), clientpubkey)

	msgFromClient := common.Messagebuffer{}
	err := session.ReceivePlaintextData(&msgFromClient)
	if err != nil {
		return nil, err
	}

	_, _, valid := common.RecvMessage(&noiseSession, &msgFromClient)
	if !valid {
		return nil, errors.New("handshake is not valid")
	}

	_, msg := common.SendMessage(&noiseSession, []byte("Accept, second message"))
	err = session.SendPlaintextData(&msg)
	if err != nil {
		return nil, err
	}

	fmt.Println("Noise handshake finished")

	encsess := common.CreateEncryptedSession(session, &noiseSession)
	return &encsess, nil
}

func handleReadMessages(session *common.PlaintextSession, tmpEncSession *common.EncryptedSession) {
	/*
		This function should read messages from server.
		- handshake should happen here.
		- after hadnshake, the server should send back all the messages it has in database
		- todo: should it send all or only the ones not seen by the user?

	*/

	var username string

	err := tmpEncSession.ReceiveEncryptedData(&username)

	const msgFail = "FAIL during read and sending message"
	if err != nil {
		fmt.Println(err)
		return

	}
	encryptedSession, _, err := initSession(session, username)
	if err != nil {
		log.Println(err)
		_ = encryptedSession.SendEncryptedData(msgFail)
		return
	}

	var fromMsgIdOnwards uint
	err = encryptedSession.ReceiveEncryptedData(&fromMsgIdOnwards)
	if err != nil {
		fmt.Println(err)
		_ = encryptedSession.SendEncryptedData(msgFail)
		return
	}
	allPosts, err := getNewMessages(uint8(fromMsgIdOnwards))
	if err != nil {
		fmt.Println(err)
		_ = encryptedSession.SendEncryptedData(msgFail)
		return
	}

	err = encryptedSession.SendEncryptedData(postsToSimplifiedMsgs(allPosts))
	if err != nil {
		fmt.Println(err)
		return
	}

}

func handleSendMessages(session *common.PlaintextSession, tmpEncSession *common.EncryptedSession) {

	/*
		Handshake should be performed, then client will send a message and server will save it.
	*/

	var username string
	err := tmpEncSession.ReceiveEncryptedData(&username)
	if err != nil {
		fmt.Println(err)
		return
	}

	encryptedSession, username, err := initSession(session, username)
	if err != nil {
		log.Println(err)
		return
	}

	var message string
	err = encryptedSession.ReceiveEncryptedData(&message)
	if err != nil {
		fmt.Println(err)
		return
	}
	_, err = saveMessage(username, message)
	if err != nil {
		fmt.Println("error with saving messgaes")
		return
	}
	fmt.Println(username + ": " + message)

}

func handleRequest(conn net.Conn) {
	defer conn.Close()

	session := common.CreatePlaintextSession(&conn)

	tmpEncSession, err := handshake(&session, common.GetOriginalKeypair().Public_key)
	if err != nil {
		fmt.Println("Could not create temporary encrypted session")
		return
	}

	var messageType string
	err = tmpEncSession.ReceiveEncryptedData(&messageType)
	if err != nil {
		fmt.Println("client send bad request, be aware")
		return
	}

	switch messageType {

	case common.MessageTypeRegistration:
		// Registration request
		handleRegistration(&session, tmpEncSession)

	case common.MessageTypeReceive:
		// Read messages from server

		handleReadMessages(&session, tmpEncSession)

	case common.MessageTypeSend:
		// Send message to server
		handleSendMessages(&session, tmpEncSession)
	}

}

func printServerData() {
	keypair := getOrGenerateServerKeypair()
	serverInfo := common.ServerInformation{Location: location, PublicKey: keypair.Public_key}
	serverBytes := bytes.Buffer{}
	encoder := gob.NewEncoder(&serverBytes)
	err := encoder.Encode(serverInfo)

	if err != nil {
		fmt.Println("Error in printServerData: ", err)
		return
	}

	fmt.Println("Server registration string: " + base64.StdEncoding.EncodeToString(serverBytes.Bytes()))

}

func main() {

	initServer()

	// fmt.Println(savemessage("test1", "lorem"))
	// fmt.Println(getnewmessages(0))
	// allMsgs, _ := getNewMessages(0)
	// fmt.Println(postsToSimplifiedMsgs(allMsgs))

	listener, err := net.Listen("tcp", location)
	if err != nil {
		fmt.Println("cannot setup a listener: ", err)
		return
	}

	printServerData()

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error accepting: ", err.Error())
			// os.Exit(1)
		}
		go handleRequest(conn)
	}

}
