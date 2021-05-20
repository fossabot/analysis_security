package common
import (
	"bytes"
	"encoding/base64"
	"log"
	"encoding/gob"
)

const originalKeypair string = "Nv+BAwEBB0tleXBhaXIB/4IAAQIBClB1YmxpY19rZXkB/4QAAQtQcml2YXRlX2tleQH/hAAAABn/gwEBAQlbMzJddWludDgB/4QAAQYBQAAAbf+CASD/sf+NDS4mMv+K/6L/xf/7/7f/zD3/pf+VbP+i/9ZF/5tPYEj/1//Y/51G/91qbTd0ASD/pXL/tmL/0/+ZIP/u/8IL/+j/oTr/mv+Q/8H/0v+X/98S/5b/z//X/6pxVQf/3f+6/+InJAA="




func GetOriginalKeypair() Keypair {
	var keypair Keypair
	decodedString, err := base64.StdEncoding.DecodeString(originalKeypair)
	if err != nil {
		log.Fatal("Original keypair can not be decoded", err)
	}
	buf := bytes.Buffer{}
	_, err = buf.Write(decodedString)
	if err != nil {
		log.Fatal("Original keypair can not be decoded ", err)
	}
	decoder := gob.NewDecoder(&buf)
	err = decoder.Decode(&keypair)
	if err != nil {
		log.Fatal("Original keypair can not be decoded ", err)
	}
	return keypair
}