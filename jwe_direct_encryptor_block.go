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
	"github.com/IceManGreen/gose/jose"
)

var (
	cbcAlgToEncMap = map[jose.Alg]jose.Enc{
		jose.AlgA256CBC: jose.EncA256CBC,
	}
)

// JweDirectEncryptorBlock
// implementation of JweDirectEncryptionEncryptor interface for BlockMode
// BlockMode is more efficient than Block for bulk operations
type JweDirectEncryptorBlock struct {
	key BlockEncryptionKey
	iv  []byte
}

// getEncryptorBlockIV generates a new iv if the encryptor's one is empty
// otherwise it returns the iv provided by the encryptor
func (encryptor *JweDirectEncryptorBlock) getEncryptorBlockIV() ([]byte, error) {
	var iv []byte
	var err error
	if encryptor.iv == nil {
		iv, err = encryptor.key.GenerateIV()
		if err != nil {
			return nil, err
		}
	} else {
		iv = encryptor.iv
	}
	return iv, err
}

// makeJwe builds the JWE structure
func (encryptor *JweDirectEncryptorBlock) makeJwe(customHeaderFields jose.JweCustomHeaderFields, plaintext, iv []byte) *jose.Jwe {
	return &jose.Jwe{
		Header: jose.JweHeader{
			JwsHeader: jose.JwsHeader{
				Alg: jose.AlgDir,
				Kid: encryptor.key.Kid(),
			},
			Enc:                   cbcAlgToEncMap[encryptor.key.Algorithm()],
			JweCustomHeaderFields: customHeaderFields,
		},
		EncryptedKey: []byte{},
		Iv:           iv,
		Plaintext:    plaintext,
	}
}

// Encrypt encrypts the given plaintext and AAD returning a compact JWE.
func (encryptor *JweDirectEncryptorBlock) Encrypt(plaintext, aad []byte) (string, error) {
	// aad, if any
	var blob *jose.Blob
	var customHeaderFields jose.JweCustomHeaderFields
	if len(aad) > 0 {
		blob = &jose.Blob{B: aad}
		customHeaderFields = jose.JweCustomHeaderFields{
			OtherAad: blob,
		}
	}
	// iv
	iv, err := encryptor.getEncryptorBlockIV()
	// jwe
	jwe := encryptor.makeJwe(customHeaderFields, plaintext, iv)
	if err = jwe.MarshalHeader(); err != nil {
		return "", err
	}
	// encrypt
	if jwe.Ciphertext, err = encryptor.key.Seal(jose.KeyOpsEncrypt, jwe.Iv, jwe.Plaintext); err != nil {
		return "", err
	}
	if encryptor.externalIV {
		/*
			If using an externally-generated IV this will have been returned in the tag field
			So we trim the tag field and update the IV field
		*/
		var throwawayNonceToGetLength []byte
		if throwawayNonceToGetLength, err = encryptor.key.GenerateIV(); nil != err {
			return "", err
		}
		jwe.Iv = jwe.Tag[len(jwe.Tag)-len(throwawayNonceToGetLength):]
		jwe.Tag = jwe.Tag[:len(jwe.Tag)-len(throwawayNonceToGetLength)]
	}
	return jwe.Marshal(), nil
}

// NewJweDirectEncryptorBlock construct an instance of a JweDirectEncryptorBlock.
func NewJweDirectEncryptorBlock(key BlockEncryptionKey, iv []byte) *JweDirectEncryptorBlock {
	return &JweDirectEncryptorBlock{
		key: key,
		iv:  iv,
	}
}
