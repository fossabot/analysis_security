/*
KK:
  -> s
  <- s
  ...
  -> e, es, ss
  <- e, ee, se
  ->
  <-
*/

// Implementation Version: 1.0.2

/* ---------------------------------------------------------------- *
 * PARAMETERS                                                       *
 * ---------------------------------------------------------------- */

package common

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"hash"
	"io"
	"math"
)

/* ---------------------------------------------------------------- *
 * TYPES                                                            *
 * ---------------------------------------------------------------- */

type Keypair struct {
	Public_key  [32]byte
	Private_key [32]byte
}

type Messagebuffer struct {
	Ne         [32]byte
	Ns         []byte
	Ciphertext []byte
}

type cipherstate struct {
	k [32]byte
	n uint32
}

type symmetricstate struct {
	cs cipherstate
	ck [32]byte
	h  [32]byte
}

type handshakestate struct {
	ss  symmetricstate
	s   Keypair
	e   Keypair
	rs  [32]byte
	re  [32]byte
	psk [32]byte
}

type Noisesession struct {
	Hs  handshakestate
	H   [32]byte
	Cs1 cipherstate
	Cs2 cipherstate
	Mc  uint64
	I   bool
}

/* ---------------------------------------------------------------- *
 * CONSTANTS                                                        *
 * ---------------------------------------------------------------- */

var emptyKey = [32]byte{
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
}

var minNonce = uint32(0)

/* ---------------------------------------------------------------- *
 * UTILITY FUNCTIONS                                                *
 * ---------------------------------------------------------------- */

func getPublicKey(kp *Keypair) [32]byte {
	return kp.Public_key
}

func isEmptyKey(k [32]byte) bool {
	return subtle.ConstantTimeCompare(k[:], emptyKey[:]) == 1
}

func validatePublicKey(k []byte) bool {
	forbiddenCurveValues := [12][]byte{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		{224, 235, 122, 124, 59, 65, 184, 174, 22, 86, 227, 250, 241, 159, 196, 106, 218, 9, 141, 235, 156, 50, 177, 253, 134, 98, 5, 22, 95, 73, 184, 0},
		{95, 156, 149, 188, 163, 80, 140, 36, 177, 208, 177, 85, 156, 131, 239, 91, 4, 68, 92, 196, 88, 28, 142, 134, 216, 34, 78, 221, 208, 159, 17, 87},
		{236, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127},
		{237, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127},
		{238, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127},
		{205, 235, 122, 124, 59, 65, 184, 174, 22, 86, 227, 250, 241, 159, 196, 106, 218, 9, 141, 235, 156, 50, 177, 253, 134, 98, 5, 22, 95, 73, 184, 128},
		{76, 156, 149, 188, 163, 80, 140, 36, 177, 208, 177, 85, 156, 131, 239, 91, 4, 68, 92, 196, 88, 28, 142, 134, 216, 34, 78, 221, 208, 159, 17, 215},
		{217, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255},
		{218, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255},
		{219, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 25},
	}

	for _, testValue := range forbiddenCurveValues {
		if subtle.ConstantTimeCompare(k[:], testValue[:]) == 1 {
			panic("Invalid public key")
		}
	}
	return true
} /* ---------------------------------------------------------------- *
 * PRIMITIVES                                                       *
 * ---------------------------------------------------------------- */

func incrementNonce(n uint32) uint32 {
	return n + 1
}

func dh(private_key [32]byte, public_key [32]byte) [32]byte {
	var ss [32]byte
	curve25519.ScalarMult(&ss, &private_key, &public_key)
	return ss
}

func GenerateKeypair() Keypair {
	var public_key [32]byte
	var private_key [32]byte
	_, _ = rand.Read(private_key[:])
	curve25519.ScalarBaseMult(&public_key, &private_key)
	if validatePublicKey(public_key[:]) {
		return Keypair{public_key, private_key}
	}
	return GenerateKeypair()
}

func generatePublicKey(private_key [32]byte) [32]byte {
	var public_key [32]byte
	curve25519.ScalarBaseMult(&public_key, &private_key)
	return public_key
}

func encrypt(k [32]byte, n uint32, ad []byte, plaintext []byte) []byte {
	var nonce [12]byte
	var ciphertext []byte
	enc, _ := chacha20poly1305.New(k[:])
	binary.LittleEndian.PutUint32(nonce[4:], n)
	ciphertext = enc.Seal(nil, nonce[:], plaintext, ad)
	return ciphertext
}

func decrypt(k [32]byte, n uint32, ad []byte, ciphertext []byte) (bool, []byte, []byte) {
	var nonce [12]byte
	var plaintext []byte
	enc, err := chacha20poly1305.New(k[:])
	binary.LittleEndian.PutUint32(nonce[4:], n)
	plaintext, err = enc.Open(nil, nonce[:], ciphertext, ad)
	return (err == nil), ad, plaintext
}

func getHash(a []byte, b []byte) [32]byte {
	return blake2s.Sum256(append(a, b...))
}

func hashProtocolName(protocolName []byte) [32]byte {
	var h [32]byte
	if len(protocolName) <= 32 {
		copy(h[:], protocolName)
	} else {
		h = getHash(protocolName, []byte{})
	}
	return h
}

func blake2HkdfInterface() hash.Hash {
	h, _ := blake2s.New256([]byte{})
	return h
}

func getHkdf(ck [32]byte, ikm []byte) ([32]byte, [32]byte, [32]byte) {
	var k1 [32]byte
	var k2 [32]byte
	var k3 [32]byte
	output := hkdf.New(blake2HkdfInterface, ikm[:], ck[:], []byte{})
	io.ReadFull(output, k1[:])
	io.ReadFull(output, k2[:])
	io.ReadFull(output, k3[:])
	return k1, k2, k3
}

/* ---------------------------------------------------------------- *
 * STATE MANAGEMENT                                                 *
 * ---------------------------------------------------------------- */

/* CipherState */
func initializeKey(k [32]byte) cipherstate {
	return cipherstate{k, minNonce}
}

func hasKey(cs *cipherstate) bool {
	return !isEmptyKey(cs.k)
}

func setNonce(cs *cipherstate, newNonce uint32) *cipherstate {
	cs.n = newNonce
	return cs
}

func encryptWithAd(cs *cipherstate, ad []byte, plaintext []byte) (*cipherstate, []byte) {
	e := encrypt(cs.k, cs.n, ad, plaintext)
	cs = setNonce(cs, incrementNonce(cs.n))
	return cs, e
}

func decryptWithAd(cs *cipherstate, ad []byte, ciphertext []byte) (*cipherstate, []byte, bool) {
	valid, ad, plaintext := decrypt(cs.k, cs.n, ad, ciphertext)
	cs = setNonce(cs, incrementNonce(cs.n))
	return cs, plaintext, valid
}

func reKey(cs *cipherstate) *cipherstate {
	e := encrypt(cs.k, math.MaxUint32, []byte{}, emptyKey[:])
	copy(cs.k[:], e)
	return cs
}

/* SymmetricState */

func initializeSymmetric(protocolName []byte) symmetricstate {
	h := hashProtocolName(protocolName)
	ck := h
	cs := initializeKey(emptyKey)
	return symmetricstate{cs, ck, h}
}

func mixKey(ss *symmetricstate, ikm [32]byte) *symmetricstate {
	ck, tempK, _ := getHkdf(ss.ck, ikm[:])
	ss.cs = initializeKey(tempK)
	ss.ck = ck
	return ss
}

func mixHash(ss *symmetricstate, data []byte) *symmetricstate {
	ss.h = getHash(ss.h[:], data)
	return ss
}

func mixKeyAndHash(ss *symmetricstate, ikm [32]byte) *symmetricstate {
	var tempH [32]byte
	var tempK [32]byte
	ss.ck, tempH, tempK = getHkdf(ss.ck, ikm[:])
	ss = mixHash(ss, tempH[:])
	ss.cs = initializeKey(tempK)
	return ss
}

func getHandshakeHash(ss *symmetricstate) [32]byte {
	return ss.h
}

func encryptAndHash(ss *symmetricstate, plaintext []byte) (*symmetricstate, []byte) {
	var ciphertext []byte
	if hasKey(&ss.cs) {
		_, ciphertext = encryptWithAd(&ss.cs, ss.h[:], plaintext)
	} else {
		ciphertext = plaintext
	}
	ss = mixHash(ss, ciphertext)
	return ss, ciphertext
}

func decryptAndHash(ss *symmetricstate, ciphertext []byte) (*symmetricstate, []byte, bool) {
	var plaintext []byte
	var valid bool
	if hasKey(&ss.cs) {
		_, plaintext, valid = decryptWithAd(&ss.cs, ss.h[:], ciphertext)
	} else {
		plaintext, valid = ciphertext, true
	}
	ss = mixHash(ss, ciphertext)
	return ss, plaintext, valid
}

func split(ss *symmetricstate) (cipherstate, cipherstate) {
	tempK1, tempK2, _ := getHkdf(ss.ck, []byte{})
	cs1 := initializeKey(tempK1)
	cs2 := initializeKey(tempK2)
	return cs1, cs2
}

/* HandshakeState */

func initializeInitiator(prologue []byte, s Keypair, rs [32]byte, psk [32]byte) handshakestate {
	var ss symmetricstate
	var e Keypair
	var re [32]byte
	name := []byte("Noise_KK_25519_ChaChaPoly_BLAKE2s")
	ss = initializeSymmetric(name)
	mixHash(&ss, prologue)
	mixHash(&ss, s.Public_key[:])
	mixHash(&ss, rs[:])
	return handshakestate{ss, s, e, rs, re, psk}
}

func initializeResponder(prologue []byte, s Keypair, rs [32]byte, psk [32]byte) handshakestate {
	var ss symmetricstate
	var e Keypair
	var re [32]byte
	name := []byte("Noise_KK_25519_ChaChaPoly_BLAKE2s")
	ss = initializeSymmetric(name)
	mixHash(&ss, prologue)
	mixHash(&ss, rs[:])
	mixHash(&ss, s.Public_key[:])
	return handshakestate{ss, s, e, rs, re, psk}
}

func writeMessageA(hs *handshakestate, payload []byte) (*handshakestate, Messagebuffer) {
	ne, ns, ciphertext := emptyKey, []byte{}, []byte{}
	hs.e = GenerateKeypair()
	ne = hs.e.Public_key
	mixHash(&hs.ss, ne[:])
	/* No PSK, so skipping mixKey */
	mixKey(&hs.ss, dh(hs.e.Private_key, hs.rs))
	mixKey(&hs.ss, dh(hs.s.Private_key, hs.rs))
	_, ciphertext = encryptAndHash(&hs.ss, payload)
	messageBuffer := Messagebuffer{ne, ns, ciphertext}
	return hs, messageBuffer
}

func writeMessageB(hs *handshakestate, payload []byte) ([32]byte, Messagebuffer, cipherstate, cipherstate) {
	ne, ns, ciphertext := emptyKey, []byte{}, []byte{}
	hs.e = GenerateKeypair()
	ne = hs.e.Public_key
	mixHash(&hs.ss, ne[:])
	/* No PSK, so skipping mixKey */
	mixKey(&hs.ss, dh(hs.e.Private_key, hs.re))
	mixKey(&hs.ss, dh(hs.e.Private_key, hs.rs))
	_, ciphertext = encryptAndHash(&hs.ss, payload)
	messageBuffer := Messagebuffer{ne, ns, ciphertext}
	cs1, cs2 := split(&hs.ss)
	return hs.ss.h, messageBuffer, cs1, cs2
}

func writeMessageRegular(cs *cipherstate, payload []byte) (*cipherstate, Messagebuffer) {
	ne, ns, ciphertext := emptyKey, []byte{}, []byte{}
	cs, ciphertext = encryptWithAd(cs, []byte{}, payload)
	messageBuffer := Messagebuffer{ne, ns, ciphertext}
	return cs, messageBuffer
}

func readMessageA(hs *handshakestate, message *Messagebuffer) (*handshakestate, []byte, bool) {
	valid1 := true
	if validatePublicKey(message.Ne[:]) {
		hs.re = message.Ne
	}
	mixHash(&hs.ss, hs.re[:])
	/* No PSK, so skipping mixKey */
	mixKey(&hs.ss, dh(hs.s.Private_key, hs.re))
	mixKey(&hs.ss, dh(hs.s.Private_key, hs.rs))
	_, plaintext, valid2 := decryptAndHash(&hs.ss, message.Ciphertext)
	return hs, plaintext, (valid1 && valid2)
}

func readMessageB(hs *handshakestate, message *Messagebuffer) ([32]byte, []byte, bool, cipherstate, cipherstate) {
	valid1 := true
	if validatePublicKey(message.Ne[:]) {
		hs.re = message.Ne
	}
	mixHash(&hs.ss, hs.re[:])
	/* No PSK, so skipping mixKey */
	mixKey(&hs.ss, dh(hs.e.Private_key, hs.re))
	mixKey(&hs.ss, dh(hs.s.Private_key, hs.re))
	_, plaintext, valid2 := decryptAndHash(&hs.ss, message.Ciphertext)
	cs1, cs2 := split(&hs.ss)
	return hs.ss.h, plaintext, (valid1 && valid2), cs1, cs2
}

func readMessageRegular(cs *cipherstate, message *Messagebuffer) (*cipherstate, []byte, bool) {
	/* No encrypted keys */
	_, plaintext, valid2 := decryptWithAd(cs, []byte{}, message.Ciphertext)
	return cs, plaintext, valid2
}

/* ---------------------------------------------------------------- *
 * PROCESSES                                                        *
 * ---------------------------------------------------------------- */

func InitSession(initiator bool, prologue []byte, s Keypair, rs [32]byte) Noisesession {
	var session Noisesession
	psk := emptyKey
	if initiator {
		session.Hs = initializeInitiator(prologue, s, rs, psk)
	} else {
		session.Hs = initializeResponder(prologue, s, rs, psk)
	}
	session.I = initiator
	session.Mc = 0
	return session
}

func SendMessage(session *Noisesession, message []byte) (*Noisesession, Messagebuffer) {
	var messageBuffer Messagebuffer
	if session.Mc == 0 {
		_, messageBuffer = writeMessageA(&session.Hs, message)
	}
	if session.Mc == 1 {
		session.H, messageBuffer, session.Cs1, session.Cs2 = writeMessageB(&session.Hs, message)
		session.Hs = handshakestate{}
	}
	if session.Mc > 1 {
		if session.I {
			_, messageBuffer = writeMessageRegular(&session.Cs1, message)
		} else {
			_, messageBuffer = writeMessageRegular(&session.Cs2, message)
		}
	}
	session.Mc = session.Mc + 1
	return session, messageBuffer
}

func RecvMessage(session *Noisesession, message *Messagebuffer) (*Noisesession, []byte, bool) {
	var plaintext []byte
	var valid bool
	if session.Mc == 0 {
		_, plaintext, valid = readMessageA(&session.Hs, message)
	}
	if session.Mc == 1 {
		session.H, plaintext, valid, session.Cs1, session.Cs2 = readMessageB(&session.Hs, message)
		session.Hs = handshakestate{}
	}
	if session.Mc > 1 {
		if session.I {
			_, plaintext, valid = readMessageRegular(&session.Cs2, message)
		} else {
			_, plaintext, valid = readMessageRegular(&session.Cs1, message)
		}
	}
	session.Mc = session.Mc + 1
	return session, plaintext, valid
}
