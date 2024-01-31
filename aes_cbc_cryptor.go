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
	opts []jose.KeyOps
	rng  io.Reader
}

// NewAesCbcCryptor create a new instance of an AesCbcCryptor from the supplied parameters.
// It implements AeadEncryptionKey
func NewAesCbcCryptor(blockCipher cipher.Block, rng io.Reader, kid string, alg jose.Alg, operations []jose.KeyOps) BlockEncryptionKey {
	return &AesCbcCryptor{
		kid:  kid,
		alg:  alg,
		rng:  rng,
		opts: operations,
		blockCipher: blockCipher,
	}
}

// GenerateIV generates an IV of the correct size for use with BlockMode encryption/decryption from a random source.
func (cryptor *AesCbcCryptor) GenerateIV() ([]byte, error) {
	// for CBC, IV size is 16 bytes
	iv := make([]byte, 16)
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

func (cryptor *AesCbcCryptor) Seal(operation jose.KeyOps, iv, plaintext []byte) (ciphertext []byte, err error) {
	ciphertext = make([]byte, len(plaintext))
	cryptor.blockCipher.Encrypt()
	cryptor.blockMode.CryptBlocks(ciphertext, plaintext)
	return
}

func (cryptor *AesCbcCryptor) Open(operation jose.KeyOps, iv, ciphertext []byte) (plaintext []byte, err error) {
	//TODO implement me
	panic("implement me")
}



