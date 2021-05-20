package main

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log"

	"github.com/BorysekOndrej/PV204_Noise_Protocol_and_TPM/common"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var db *gorm.DB
var DuplicateRegistration = errors.New("Username is already registered")

type User struct {
	gorm.Model
	ID              uint   `gorm:"primaryKey"`
	Username        string `gorm:"unique"`
	TpmGoldenString string
	TPMPublicKey    string
	NoisePubKey     string
}

type Post struct {
	gorm.Model
	ID       uint
	AuthorID uint
	Author   User
	Content  string
	Order    int `gorm:"default:0"`
}

type ServerOption struct {
	gorm.Model
	ID    uint
	Name  string `gorm:"unique"`
	Value string
}

func CreateDatabase() {
	firstConnectionInThisRun := db == nil
	var err error

	db, err = gorm.Open(sqlite.Open("gorm.db"), &gorm.Config{}) // todo: decide whether we want to keep it as global value
	if err != nil {
		panic("failed to connect database")
	}
	if firstConnectionInThisRun {
		err := db.AutoMigrate(&User{}, &Post{}, &ServerOption{})
		if err != nil {
			log.Fatal("db error, try restart db", err)
		}
	}
}

func registerUser(regStruct common.RegistrationStruct) error {
	user := User{
		Username:        regStruct.Username,
		TpmGoldenString: base64.StdEncoding.EncodeToString(regStruct.TpmGoldenString),
		TPMPublicKey:    base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(&regStruct.TPMPublicKey)),
		NoisePubKey:     base64.StdEncoding.EncodeToString(regStruct.NoisePubKey[:]),
	}
	result := db.Create(&user)
	if result.Error != nil {
		log.Println(result.Error)
		return DuplicateRegistration
	}
	return nil
}

func convertUserToRegistrationStruct(user User) common.RegistrationStruct {
	tpmPublickeyPkcs1, err := base64.StdEncoding.DecodeString(user.TPMPublicKey)
	if err != nil {
		log.Fatal(err)
	}
	TPMPublicKey, err := x509.ParsePKCS1PublicKey(tpmPublickeyPkcs1)
	if err != nil {
		log.Fatal(err)
	}

	TpmGoldenString, err := base64.StdEncoding.DecodeString(user.TpmGoldenString)
	if err != nil {
		log.Fatal(err)
	}

	NoisePubKey, err := base64.StdEncoding.DecodeString(user.NoisePubKey)
	if err != nil {
		log.Fatal(err)
	}
	regStruct := common.RegistrationStruct{
		Username:        user.Username,
		TPMPublicKey:    *TPMPublicKey,
		TpmGoldenString: TpmGoldenString,
		// NoisePubKey:     NoisePubKey[:32],
	}
	copy(regStruct.NoisePubKey[:], NoisePubKey)

	return regStruct
}

func getRegistrationStructByUsername(username string) *common.RegistrationStruct {

	var user User
	result := db.Preload(clause.Associations).Where("username = ?", username).First(&user)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) { // security: fail here will be timing side channel using which usernames can be enumerated
		return nil
	}

	regStruct := convertUserToRegistrationStruct(user)

	return &regStruct
}

func saveKey(name string, key [32]uint8) bool {
	keyBase64 := base64.StdEncoding.EncodeToString(key[:])
	return saveOption(name, keyBase64)
}

func saveOption(name string, value string) bool {
	dbOption := ServerOption{Name: name, Value: value}
	result := db.Create(&dbOption)

	if result.Error != nil {
		fmt.Println(result.Error)
		return false
	}
	return true
}

func getOption(name string) string {
	var serverOption ServerOption
	result := db.Where("name = ?", name).First(&serverOption)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) { // security: fail here will be timing side channel using which usernames can be enumerated
		return ""
	}
	return serverOption.Value
}

func saveServerKeypair(keypair common.Keypair) bool {
	if saveKey("privkey", common.GetPrivateKey(&keypair)) && saveKey("pubkey", common.GetPublicKey(&keypair)) {
		return true
	}
	fmt.Println("Saving server keypair failed. It's possible that another keypair is already saved")
	return false
}

func getServerKeypair() *common.Keypair {
	pubkey, err := base64.StdEncoding.DecodeString(getOption("pubkey"))
	if err != nil || len(pubkey) == 0 {
		fmt.Println(`failed`, err)
		return nil
	}

	privkey, err := base64.StdEncoding.DecodeString(getOption("privkey"))
	if err != nil || len(pubkey) == 0 {
		fmt.Println(`failed`, err)
		return nil
	}

	var pubKey32Bytes [32]byte
	var privKey32Bytes [32]byte
	copy(pubKey32Bytes[:], pubkey)
	copy(privKey32Bytes[:], privkey)

	keypairReconstructed := common.Keypair{
		Public_key: pubKey32Bytes,
	}
	common.SetPrivateKey(&keypairReconstructed, privKey32Bytes)

	return &keypairReconstructed
}

func saveMessage(username string, message string) (uint, error) {
	var user User
	result := db.Where("username = ?", username).First(&user)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return 0, gorm.ErrRecordNotFound
	}

	if result.Error != nil {
		log.Fatal("db error try to restart db", result.Error)
	}
	post := Post{Author: user, Content: message}
	// todo: check for creation failure
	db.Create(&post)
	return post.ID, nil
}

func getNewMessages(fromMessageId uint8) ([]Post, error) {
	var posts []Post
	result := db.Preload(clause.Associations).Where("id >= ?", fromMessageId).Find(&posts) // todo: check whether we want to include > or >=
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return posts, gorm.ErrRecordNotFound
	}

	if result.Error != nil {
		log.Fatal("db error try to restart db", result.Error)
	}

	return posts, nil
}

func postToSimplifiedMsg(post Post) common.SimplifiedMessage {
	// todo: implement LastChangeTimestamp
	answer := common.SimplifiedMessage{
		ID:             post.ID,
		AuthorUsername: post.Author.Username,
		Content:        post.Content,
		Order:          post.Order,
	}
	return answer
}

func postsToSimplifiedMsgs(posts []Post) []common.SimplifiedMessage {
	var answer []common.SimplifiedMessage
	for _, s := range posts {
		answer = append(answer, postToSimplifiedMsg(s))
	}
	return answer
}
