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
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"github.com/ThalesGroup/crypto11"
	"github.com/ThalesGroup/gose/jose"
	"github.com/miekg/pkcs11"
	"github.com/stretchr/testify/require"
	"log"
	"os"
	"strings"
	"testing"
)

func requireNoIssue(t *testing.T, o interface{}, err error) {
	require.NoError(t, err)
	require.NotNil(t, o)
}

var (
	pkcs11ConfigEnv = "PKCS11_CONFIG"
	secretKeyLabelEnv = "PKCS11_SECRET_KEY_LABEL"
	hmacKeyLabelEnv = "PKCS11_HMAC_KEY_LABEL"
)

func loadPkcs11Ctx(t *testing.T, pkcs11Config string, iv []byte) (ctx *crypto11.Context, cryptor *JweDirectEncryptorBlock, decryptor *JweDirectDecryptorBlock) {
	secretKeyLabel := os.Getenv(secretKeyLabelEnv)
	hmacKeyLabel := os.Getenv(hmacKeyLabelEnv)
	require.NotEmpty(t, secretKeyLabel)
	require.NotEmpty(t, hmacKeyLabel)

	// get pkcs11 context from config
	var err error
	ctx, err = crypto11.ConfigureFromFile(pkcs11Config)
	requireNoIssue(t, ctx, err)

	// get secret and hmac key from pkcs11 backend
	secretKey, err := ctx.FindKey(nil, []byte(secretKeyLabel))
	requireNoIssue(t, secretKey, err)
	hmacKey, err := ctx.FindKey(nil, []byte(hmacKeyLabel))
	requireNoIssue(t, hmacKey, err)

	// get encryption key material from pkcs11
	// secret key for aes
	cbcPkcs11Manager, err := secretKey.NewBlockManagerCBCPadding(iv)
	requireNoIssue(t, cbcPkcs11Manager, err)
	cbcKey := NewAesCbcCryptor(cbcPkcs11Manager, rand.Reader, secretKeyLabel, jose.AlgA256CBC, true)
	requireNoIssue(t, cbcKey, err)
	// hmac key
	hmacPkcs11Manager, err := hmacKey.NewHMAC(pkcs11.CKM_SHA256_HMAC, 0)
	requireNoIssue(t, hmacPkcs11Manager, err)
	hmacShaKey := NewHmacShaCryptor(hmacKeyLabel, hmacPkcs11Manager)
	requireNoIssue(t, hmacShaKey, err)

	// jwe direct encryption initialization
	cryptor = NewJweDirectEncryptorBlock(cbcKey, hmacShaKey, iv)
	requireNoIssue(t, cryptor, err)
	decryptor = NewJweDirectDecryptorBlock(cbcKey, hmacShaKey)
	requireNoIssue(t, decryptor, err)

	return ctx, cryptor, decryptor
}

func loadWithoutCtx(t *testing.T, blockSize int, iv []byte) (cryptor *JweDirectEncryptorBlock, decryptor *JweDirectDecryptorBlock) {
	// init key and cryptor
	mockKey := NewMockBlock(blockSize, expectedCleartext, expectedCiphertext)
	require.NotNil(t, mockKey)
	aesKey := mockKey.MakeCBCBlockEncryptionKey("aes-0", true)
	require.NotNil(t, aesKey)
	hmacKey := NewHmacShaCryptor("hmac-0", sha256.New())
	require.NotNil(t, hmacKey)

	cryptor = NewJweDirectEncryptorBlock(aesKey, hmacKey, iv)
	require.NotNil(t, cryptor)
	decryptor = NewJweDirectDecryptorBlock(aesKey, hmacKey)
	require.NotNil(t, decryptor)

	return cryptor, decryptor
}

func TestJweDirectEncryptorBlock(t *testing.T) {
	//var err error
	blockSize := 16
	iv := make([]byte, blockSize)
	_, err := rand.Read(iv)
	require.NoError(t, err)
	require.NotEmpty(t, iv)

	pkcs11Config := os.Getenv(pkcs11ConfigEnv)
	var cryptor *JweDirectEncryptorBlock
	var decryptor *JweDirectDecryptorBlock
	if pkcs11Config != "" {
		// load PKCS11 context if provided
		var ctx *crypto11.Context
		ctx, cryptor, decryptor = loadPkcs11Ctx(t, pkcs11Config, iv)
		log.Print(ctx)
		//defer func() {
		//	err = ctx.Close()
		//}()
	} else {
		// load normally without pkcs11 context
		cryptor, decryptor = loadWithoutCtx(t, blockSize, iv)
	}

	t.Run("testEncryptDecrypt", func(t *testing.T) {
		testEncryptDecrypt(t, cryptor, decryptor, iv)
	})
}

func testEncryptDecrypt(t *testing.T, cryptor *JweDirectEncryptorBlock, decryptor *JweDirectDecryptorBlock, expectedIV []byte) {
	// **********
	// ENCRYPTION
	// **********
	marshalledJwe, err := cryptor.Encrypt([]byte(expectedCleartext), nil)
	require.NoError(t, err)
	require.NotEmpty(t, marshalledJwe)
	// verify the structure
	splits := strings.Split(marshalledJwe,  ".")
	require.Equal(t, 5, len(splits))
	// For direct encryption, the encrypted key is nil
	// we expected an empty string for the second part of the JWE
	require.Empty(t, splits[1])
	// other parts should not be empty
	require.NotEmpty(t, splits[0])
	require.NotEmpty(t, splits[2])
	require.NotEmpty(t, splits[3])
	require.NotEmpty(t, splits[4])
	// verify structure
	iv, err := base64.RawURLEncoding.DecodeString(splits[2])
	require.NoError(t, err)
	require.Equal(t, expectedIV, iv)
	ciphertext, err := base64.RawURLEncoding.DecodeString(splits[3])
	require.NoError(t, err)
	require.Equal(t, 32, len(ciphertext))

	// **********
	// DECRYPTION
	// **********
	plaintext, err := decryptor.Decrypt(marshalledJwe)
	require.NoError(t, err)

	// decryption
	require.NotEmpty(t, plaintext)
	require.Equal(t, expectedCleartext, string(plaintext))
}




