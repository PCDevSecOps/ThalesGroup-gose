// Copyright 2019 Thales e-Security, Inc
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package gose

import (
	"crypto/cipher"
	"io"

	"github.com/ThalesGroup/gose/jose"
)

// AesCbcCryptor provides AES CBC encryption and decryption functions.
// It implements BlockEcryptionKey
type AesCbcCryptor struct {
	kid  string
	alg  jose.Alg
	blockCipher cipher.Block
	rng  io.Reader
	padding bool
}

// NewAesCbcCryptor create a new instance of an AesCbcCryptor from the supplied parameters.
// It implements AeadEncryptionKey
func NewAesCbcCryptor(blockCipher cipher.Block, rng io.Reader, kid string, alg jose.Alg, padding bool) BlockEncryptionKey {
	return &AesCbcCryptor{
		kid:  kid,
		alg:  alg,
		rng:  rng,
		blockCipher: blockCipher,
		padding: padding,
	}
}

// GenerateIV generates an IV of the correct size
func (cryptor *AesCbcCryptor) GenerateIV() ([]byte, error) {
	iv := make([]byte, cryptor.blockCipher.BlockSize())
	if _, err := cryptor.rng.Read(iv); err != nil {
		return nil, err
	}
	return iv, nil
}

func (cryptor *AesCbcCryptor) Kid() string {
	return cryptor.kid
}

func (cryptor *AesCbcCryptor) Algorithm() jose.Alg {
	return cryptor.alg
}

func getDestinationTextLength(inputLength int, blockSize int) int {
	var finalSize int
	if multiplier := inputLength / blockSize; multiplier > 0 {
		finalSize = multiplier*blockSize
		if remain := inputLength % blockSize; remain > 0 {
			finalSize = finalSize + blockSize
		}
	} else {
		finalSize = blockSize
	}
	return finalSize
}

func (cryptor *AesCbcCryptor) Seal(plaintext []byte) []byte {
	ciphertext := make([]byte, getDestinationTextLength(len(plaintext), cryptor.blockCipher.BlockSize()))
	cryptor.blockCipher.Encrypt(ciphertext, plaintext)
	return ciphertext
}

func (cryptor *AesCbcCryptor) Open(ciphertext []byte) (plaintext []byte) {
	plaintext = make([]byte, getDestinationTextLength(len(plaintext), cryptor.blockCipher.BlockSize()))
	cryptor.blockCipher.Decrypt(plaintext, ciphertext)
	return plaintext
}



