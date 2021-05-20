package main

import (
	"fmt"
	"github.com/BorysekOndrej/PV204_Noise_Protocol_and_TPM/common"
	"log"
	"net"
)

func connectToServer(serverData common.ServerInformation) *common.PlaintextSession {
	conn, err := net.Dial("tcp", serverData.Location)

	if err != nil {
		fmt.Println("Connection error", err)
		fmt.Println("Let's try it again")
		conn, err = net.Dial("tcp", serverData.Location)
		if err != nil {
			log.Fatal("Connection error", err)
		}
	}

	session := common.CreatePlaintextSession(&conn)
	return &session
}

func handshakeWithServer(session *common.PlaintextSession, keypair common.Keypair, serverPubKey [32]byte, secondAttempt bool) *common.EncryptedSession {
	/*Initialize session, client is initiator so it must send first */

	noiseSession := common.InitSession(true, []byte("demo"), keypair, serverPubKey)

	/*Send init message */

	_, msgA := common.SendMessage(&noiseSession, []byte("Handshake begin"))
	session.SendPlaintextData(&msgA)

	/*now we want receive messages from server*/

	msgB := common.Messagebuffer{}
	session.ReceivePlaintextData(&msgB)

	_, _, valid := common.RecvMessage(&noiseSession, &msgB)
	if !valid && secondAttempt {
		log.Fatal("invalid message, handshake was not successful")
	}
	if !valid {
		fmt.Println("invalid message, handshake was not successful")
		fmt.Println("let's try it again")
		return handshakeWithServer(session, keypair, serverPubKey, true)
	}
	/*now we will send another msg*/

	encSession := common.CreateEncryptedSession(session, &noiseSession)
	return &encSession
}

func attestTPM(session *common.EncryptedSession) {
	// Step 1: server generates nonce and sends it to client
	var nonce []byte

	session.ReceiveEncryptedData(&nonce)

	//Step 2: client sends attested nonce to server
	attestation, signature := common.ClientAttestnonce(nonce)

	session.SendEncryptedData(attestation)
	session.SendEncryptedData(signature)
}

func initializeSecureConnection(messageType string) *common.EncryptedSession {

	clientData := loadPersistentData()
	plaintextSession := connectToServer(clientData.ServerInfo)

	tmpEncSession := handshakeWithServer(plaintextSession, common.GetOriginalKeypair(), clientData.ServerInfo.PublicKey, false)

	tmpEncSession.SendEncryptedData(messageType)
	tmpEncSession.SendEncryptedData(clientData.ClientName)

	encSession := handshakeWithServer(plaintextSession, clientData.ClientKeypair, clientData.ServerInfo.PublicKey, false)
	attestTPM(encSession)

	return encSession
}

func registerClient(username string, serverData common.ServerInformation) bool {
	pubkey, goldenValue := common.ClientCreatetpmregistrationdata()
	noiseKeyPair := common.GenerateKeypair()
	registrationData := common.RegistrationStruct{TPMPublicKey: pubkey, Username: username, TpmGoldenString: goldenValue, NoisePubKey: noiseKeyPair.Public_key}
	ptSession := connectToServer(serverData)

	tmpEncSession := handshakeWithServer(ptSession, common.GetOriginalKeypair(), serverData.PublicKey, false)

	tmpEncSession.SendEncryptedData(common.MessageTypeRegistration)
	tmpEncSession.SendEncryptedData(noiseKeyPair.Public_key)

	encSession := handshakeWithServer(ptSession, noiseKeyPair, serverData.PublicKey, false)

	encSession.SendEncryptedData(registrationData)

	var serverResponse string
	encSession.ReceiveEncryptedData(&serverResponse)

	var clientData clientDataStruct = clientDataStruct{ClientKeypair: noiseKeyPair, ClientName: username, ServerInfo: serverData}

	if serverResponse == common.RegistrationOK {
		fmt.Println("Registration was succesful")
		savePersistentData(clientData)
		return true
	} else if serverResponse == common.RegistionUsernameAlreadyUsed {
		fmt.Println("Please select different username - this one is already used")
		return false
	}
	if serverResponse == common.RegistrationFail {
		fmt.Println("registration error, handshake or tpm was not valid probably , try again")
		return false
	}

	fmt.Println("This should not happen")
	return false
}
