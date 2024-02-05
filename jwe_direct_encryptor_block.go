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
	"fmt"
	"github.com/ThalesGroup/gose/jose"
)

var (
	cbcAlgToEncMap = map[jose.Alg]jose.Enc{
		jose.AlgA256CBC: jose.EncA256CBC,
	}
)

// JweDirectEncryptorBlock
// implementation of JweDirectEncryptionEncryptor interface for BlockMode which is more efficient than Block for bulk
// operations
type JweDirectEncryptorBlock struct {
	aesKey  BlockEncryptionKey
	hmacKey HmacKey
	iv      []byte
	jweVerifier JweHmacVerifierImpl
}

// getEncryptorBlockIV generates a new iv if the encryptor's one is empty
// otherwise it returns the iv provided by the encryptor
func (encryptor *JweDirectEncryptorBlock) getEncryptorBlockIV() ([]byte, error) {
	var iv []byte
	var err error
	if encryptor.iv == nil {
		iv, err = encryptor.aesKey.GenerateIV()
		if err != nil {
			return nil, err
		}
	} else {
		iv = encryptor.iv
	}
	return iv, err
}

// makeJwe builds the JWE structure
func (encryptor *JweDirectEncryptorBlock) makeJweProtectedHeader() *jose.JweProtectedHeader {
	return &jose.JweProtectedHeader{
		JwsHeader: jose.JwsHeader{
			Alg: encryptor.aesKey.Algorithm(),
			Kid: encryptor.aesKey.Kid(),
			Typ: "JWT",
			Cty: "JWT",
		},
		Enc: cbcAlgToEncMap[encryptor.aesKey.Algorithm()],
	}
}

// Encrypt encrypts the given plaintext and returns a compact JWE.
// aad is useless here : according to RFC7516, the AAD is computed from the JWE's private header
func (encryptor *JweDirectEncryptorBlock) Encrypt(plaintext, aad []byte) (string, error) {
	// The following steps respect the RFC7516 Appendix B for AES CBC and HMAC encryption instructions :
	// https://datatracker.ietf.org/doc/html/rfc7516#appendix-B
	var err error
	// iv
	var iv []byte
	if iv, err = encryptor.getEncryptorBlockIV(); err != nil {
		return "", fmt.Errorf("error getting the IV: %v", err)
	}
	// JWE header
	jweProtectedHeader := encryptor.makeJweProtectedHeader()
	// AAD
	//  = ASCII(BASE64URL(UTF8(JWE Protected Header)))
	if aad, err = jweProtectedHeader.MarshalProtectedHeader(); err != nil {
		return "", fmt.Errorf("error marshalling the JWE Header: %v", err)
	}
	// Encrypt Plaintext to Create Ciphertext
	ciphertext := encryptor.aesKey.Seal(plaintext)
	// HMAC computation
	outputHmac := encryptor.jweVerifier.ComputeHash(aad, iv, ciphertext)
	// Create Authentication Tag
	//  = the first half of the hash
	// THE TAG HAS TO BE VERIFIED WHEN THIS SAME JWE IS USED FOR DECRYPTION.
	// BEWARE that taking half of the hash for integrity check is part of the rfc 7516 :
	// https://datatracker.ietf.org/doc/html/rfc7516#appendix-B.7
	// I am not sure if we have to follow the specifications or get the max of the length of the hash to maximize the security
	//tag := outputHmac[:(len(outputHmac) / 2)]
	tag := outputHmac

	// TODO : according to this draft : https://datatracker.ietf.org/doc/html/draft-mcgrew-aead-aes-cbc-hmac-sha2-01#section-2.1
	//  The returned ciphertext should be the encrypted plaintext concatenated with the tag
	//  we should check if this syntax is supported for JWE consumers

	// Create the JWE
	// we store the length of the plaintext in the additional data held by the protected header.
	// It can be used to return the proper plaintext after decryption.
	jweProtectedHeader.OtherAad = &jose.Blob{B: uintToBytesBigEndian(uint64(len(plaintext)))}
	jwe := &jose.JweRfc7516Compact{
		ProtectedHeader:      *jweProtectedHeader,
		EncryptedKey:         nil,
		InitializationVector: iv,
		Ciphertext:           ciphertext,
		AuthenticationTag:    tag,
	}
	return jwe.Marshal()
}

// NewJweDirectEncryptorBlock construct an instance of a JweDirectEncryptorBlock.
func NewJweDirectEncryptorBlock(aesKey BlockEncryptionKey, hmacKey HmacKey, iv []byte) *JweDirectEncryptorBlock {
	return &JweDirectEncryptorBlock{
		aesKey:  aesKey,
		hmacKey: hmacKey,
		iv:      iv,
		jweVerifier: JweHmacVerifierImpl{hmacKey: hmacKey},
	}
}
