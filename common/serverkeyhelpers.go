package common

func GetPublicKey(kp *Keypair) [32]byte {
	return kp.Public_key
}

func GetPrivateKey(kp *Keypair) [32]byte {
	return kp.Private_key
}

func SetPrivateKey(kp *Keypair, secretKey [32]byte) {
	kp.Private_key = secretKey
}
