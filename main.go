package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"

	enc "github.com/FairBlock/DistributedIBE/encryption"
	govutils "github.com/cosmos/cosmos-sdk/x/gov/client/utils"
	v1 "github.com/cosmos/cosmos-sdk/x/gov/types/v1"
	bls "github.com/drand/kyber-bls12381"
)

func main() {
	voteOption := os.Args[1]
	randNo := os.Args[2]
	identity := os.Args[3]
	pubKey := os.Args[4]

	// Find out which vote option user chose
	byteVoteOption, err := v1.VoteOptionFromString(govutils.NormalizeVoteOption(voteOption))
	if err != nil {
		fmt.Println(err)
	}

	// parse the random number and convert to int
	i, err := strconv.ParseInt(randNo, 10, 64)
	if err != nil {
		fmt.Println(err)
	}

	// populate the structure
	var voteData = v1.DecryptedVoteOption{
		Option:   byteVoteOption,
		RandomNo: i,
	}

	// encrypt the vote structure
	encVote, err := EncryptVote(voteData, pubKey, identity)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(encVote)
	}
}

func EncryptVote(voteOption v1.DecryptedVoteOption, pubKey string, identity string) (string, error) {
	var encryptedDataBytes bytes.Buffer
	var voteDataBuffer bytes.Buffer

	// Marshal the vote structure to bytes
	voteBytes, err := voteOption.Marshal()
	if err != nil {
		return "", err
	}

	// Write into a buffer (since the encrypt function accepts byte-buffers)
	voteDataBuffer.Write(voteBytes)

	// decode hex pubkey and convert to bytes
	publicKeyByte, err := hex.DecodeString(pubKey)
	if err != nil {
		return "", err
	}

	// create the publickeypoint from the public key bytes
	suite := bls.NewBLS12381Suite()
	publicKeyPoint := suite.G1().Point()
	if err := publicKeyPoint.UnmarshalBinary(publicKeyByte); err != nil {
		return "", err
	}

	// encrypt the vote bytes
	if err := enc.Encrypt(publicKeyPoint, []byte(identity), &encryptedDataBytes, &voteDataBuffer); err != nil {
		return "", err
	}

	return hex.EncodeToString(encryptedDataBytes.Bytes()), nil
}
