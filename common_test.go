package gose

import (
	"crypto/cipher"
	"crypto/rand"
	"github.com/ThalesGroup/gose/jose"
	"hash"
)

var (
	expectedCiphertext = "expectedciphertext"
	expectedShortCiphertext = "ciphertext"
	expectedCleartext = "expectedcleartext"
	expectedShortCleartext = "cleartext"
)

// MockBlock extends cipher.Block interface and adds useful functions for unit tests
type MockBlock interface {
	cipher.Block
	// MakeCBCBlockEncryptionKey builds a secret AES key for block encryption based on the cipher block
	MakeCBCBlockEncryptionKey(kid string, padding bool) BlockEncryptionKey
	MockCiphertext() string
	MockCleartext() string
}

type mockBlock struct {
	blockSize int
	// plaintext supposed to be returned for decryption operations, used for tests
	plaintext string
	// ciphertext supposed to be returned for encryption operations, used for tests
	ciphertext string
}

// NewMockBlock mocks a block cipher
// give the plaintext and the ciphertext it is supposed to provide with Decrypt() and Encrypt()
func NewMockBlock(blockSize int, plaintext string, ciphertext string) MockBlock {
	return &mockBlock{
		blockSize:  blockSize,
		plaintext:  plaintext,
		ciphertext: ciphertext,
	}
}

func (mb *mockBlock) BlockSize() int {
	return mb.blockSize
}

func (mb *mockBlock) MockCiphertext() string {
	return mb.ciphertext
}

func (mb *mockBlock) MockCleartext() string {
	return mb.plaintext
}


func (mb *mockBlock) Encrypt(dst, src []byte) {
	// returns the ciphertext from the builder for mockup
	copy(dst[:len(mb.ciphertext)], mb.ciphertext)
}

func (mb *mockBlock) Decrypt(dst, src []byte) {
	// returns the plaintext from the builder for mockup
	copy(dst[:len(mb.plaintext)], mb.plaintext)
}

func (mb *mockBlock) MakeCBCBlockEncryptionKey(kid string, padding bool) BlockEncryptionKey {
	return NewAesCbcCryptor(mb, rand.Reader, kid, jose.AlgA256CBC, padding)
}

type MockHash interface {
	hash.Hash
	// MakeHmacKey builds a hmac key for block encryption based on the cipher block
	MakeHmacKey(kid string, hash hash.Hash) HmacKey
}
