package common

import (
	"bytes"
	"crypto/rsa"
	"encoding/gob"
	"errors"
	"fmt"
	"net"

	"github.com/google/go-tpm/tpmutil"
)

type RegistrationStruct struct {
	TPMPublicKey    rsa.PublicKey
	Username        string
	TpmGoldenString tpmutil.U16Bytes
	NoisePubKey     [32]byte
}

type SimplifiedMessage struct {
	ID                  uint
	LastChangeTimestamp uint
	AuthorUsername      string
	Content             string
	Order               int
}

type ServerInformation struct {
	Location  string
	PublicKey [32]byte
}

type PlaintextSession struct {
	encoder    *gob.Encoder
	decoder    *gob.Decoder
	connection *net.Conn
}

type EncryptedSession struct {
	noisesession *Noisesession
	session      *PlaintextSession
}

func CreatePlaintextSession(connection *net.Conn) PlaintextSession {
	encoder := gob.NewEncoder(*connection)
	decoder := gob.NewDecoder(*connection)
	return PlaintextSession{encoder: encoder, decoder: decoder, connection: connection}
}

func CreateEncryptedSession(session *PlaintextSession, noisesession *Noisesession) EncryptedSession {
	return EncryptedSession{noisesession: noisesession, session: session}
}

func (session *PlaintextSession) SendPlaintextData(s interface{}) error {
	err := session.encoder.Encode(s)
	if err != nil {
		fmt.Println("Internal error with sending plaintext data", err)
		return err
	}
	return nil
}

func (session *PlaintextSession) ReceivePlaintextData(s interface{}) error {
	err := session.decoder.Decode(s)
	if err != nil {
		fmt.Println("Internal error with receiving plaintext data", err)
		return err
	}
	return nil
}

func (session *EncryptedSession) SendEncryptedData(s interface{}) error {
	message := bytes.Buffer{}
	e := gob.NewEncoder(&message)
	if err := e.Encode(s); err != nil {
		fmt.Println("message not sended", err)
		return errors.New("message not sended")
	}
	if session == nil {
		return errors.New("session is nil")
	}

	_, msgbf := SendMessage(session.noisesession, message.Bytes())

	err := session.session.encoder.Encode(&msgbf)
	if err != nil {
		fmt.Println("Invalid encoding and sending meesage", err)
		return errors.New("message not sended")
	}

	return nil
}

func (session *EncryptedSession) ReceiveEncryptedData(s interface{}) error {

	var msgbf Messagebuffer

	err := session.session.decoder.Decode(&msgbf)
	if err != nil {
		return err
	}
	_, decryptedtext, valid := RecvMessage(session.noisesession, &msgbf)
	if !valid {
		fmt.Println("Noise message invalid in ReceiveStruct")
		return errors.New("Noise message invalid in ReceiveStruct")
	}

	buf := bytes.Buffer{}
	buf.Write(decryptedtext)

	d := gob.NewDecoder(&buf)

	err = d.Decode(s)
	if err != nil {

		fmt.Println("Invalid decode of message", err)
		return err
	}

	return nil
}

func MaxUint(x uint, y uint) uint {
	if x >= y {
		return x
	}
	return y
}
