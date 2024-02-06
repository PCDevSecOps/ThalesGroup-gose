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
	"crypto/rand"
	"testing"

	"github.com/ThalesGroup/gose/jose"
	"github.com/stretchr/testify/require"
)


var (
	expectedCiphertext = "expectedciphertext"
	expectedCleartext = "expectedcleartext"
)

func TestAesCbcCryptor(t *testing.T) {
	var err error
	// init parameters
	fakeKeyMaterial = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	//var key cipher.Block
	rng := rand.Reader
	kid := "aes-cbc-0"
	alg := jose.AlgA256CBC
	blockSize := 32
	iv := make([]byte, blockSize)
	_, err = rng.Read(iv)
	require.NoError(t, err)
	// init key and cryptor
	mockKey := NewMockBlock(blockSize, expectedCleartext, expectedCiphertext)
	cryptor := NewAesCbcCryptor(mockKey, rng, kid, alg, true)
	require.NoError(t, err)
	require.NotNil(t, cryptor)

	t.Run("testGenerateAESCBCIV", func(t *testing.T) {
		testGenerateAESCBCIV(t, cryptor, mockKey)
	})
	t.Run("testAESCBCKid", func(t *testing.T) {
		testAESCBCKid(t, cryptor, kid)
	})
	t.Run("testAESCBCAlgorithm", func(t *testing.T) {
		testAESCBCAlgorithm(t, cryptor, alg)
	})
	t.Run("testAESCBCSeal", func(t *testing.T) {
		testAESCBCSeal(t, cryptor, blockSize, mockKey.MockCleartext())
	})
	t.Run("testAESCBCOpen", func(t *testing.T) {
		testAESCBCOpen(t, cryptor, blockSize, mockKey.MockCiphertext())
	})

}

func testGenerateAESCBCIV(t *testing.T, cryptor BlockEncryptionKey, key cipher.Block){
	iv, err := cryptor.GenerateIV()
	require.NoError(t, err)
	require.NotEmpty(t, iv)
	require.Equal(t, key.BlockSize(), len(iv))
}

func testAESCBCKid(t *testing.T, cryptor BlockEncryptionKey, expectedKid string){
	kid := cryptor.Kid()
	require.NotEmpty(t, kid)
	require.Equal(t, expectedKid, kid)
}

func testAESCBCAlgorithm(t *testing.T, cryptor BlockEncryptionKey, expectedAlg jose.Alg){
	alg := cryptor.Algorithm()
	require.NotEmpty(t, alg)
	require.Equal(t, expectedAlg, alg)
}

func testAESCBCSeal(t *testing.T, cryptor BlockEncryptionKey, blockSize int, plaintext string){
	expected := make([]byte, blockSize)
	copy(expected[:len(expectedCiphertext)], expectedCiphertext)
	ciphertext := cryptor.Seal([]byte(plaintext))
	require.NotNil(t, ciphertext)
	require.Equal(t, blockSize, len(ciphertext))
	require.Equal(t, expected, ciphertext)
}

func testAESCBCOpen(t *testing.T, cryptor BlockEncryptionKey, blockSize int, ciphertext string){
	expected := make([]byte, blockSize)
	copy(expected[:len(expectedCleartext)], expectedCleartext)
	plaintext := cryptor.Open([]byte(ciphertext))
	require.Equal(t, blockSize, len(plaintext))
	require.Equal(t, expected, plaintext)
}
