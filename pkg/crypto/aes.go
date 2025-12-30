package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

const (
	AESBlockSize = 16
	AESKeySize   = 32 // AES-256
)

var (
	ErrInvalidKeySize    = errors.New("crypto: invalid key size")
	ErrInvalidBlockSize  = errors.New("crypto: data size not multiple of block size")
	ErrInvalidIVSize     = errors.New("crypto: invalid IV size")
	ErrDataTooShort      = errors.New("crypto: data too short")
)

// AESEncryptECB encrypts data using AES-256 in ECB mode.
// ECB mode is used for tunnel IV encryption.
func AESEncryptECB(key, data []byte) ([]byte, error) {
	if len(key) != AESKeySize {
		return nil, ErrInvalidKeySize
	}
	if len(data)%AESBlockSize != 0 {
		return nil, ErrInvalidBlockSize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	result := make([]byte, len(data))
	for i := 0; i < len(data); i += AESBlockSize {
		block.Encrypt(result[i:i+AESBlockSize], data[i:i+AESBlockSize])
	}

	return result, nil
}

// AESDecryptECB decrypts data using AES-256 in ECB mode.
func AESDecryptECB(key, data []byte) ([]byte, error) {
	if len(key) != AESKeySize {
		return nil, ErrInvalidKeySize
	}
	if len(data)%AESBlockSize != 0 {
		return nil, ErrInvalidBlockSize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	result := make([]byte, len(data))
	for i := 0; i < len(data); i += AESBlockSize {
		block.Decrypt(result[i:i+AESBlockSize], data[i:i+AESBlockSize])
	}

	return result, nil
}

// AESEncryptCBC encrypts data using AES-256 in CBC mode.
func AESEncryptCBC(key, iv, data []byte) ([]byte, error) {
	if len(key) != AESKeySize {
		return nil, ErrInvalidKeySize
	}
	if len(iv) != AESBlockSize {
		return nil, ErrInvalidIVSize
	}
	if len(data)%AESBlockSize != 0 {
		return nil, ErrInvalidBlockSize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	result := make([]byte, len(data))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(result, data)

	return result, nil
}

// AESDecryptCBC decrypts data using AES-256 in CBC mode.
func AESDecryptCBC(key, iv, data []byte) ([]byte, error) {
	if len(key) != AESKeySize {
		return nil, ErrInvalidKeySize
	}
	if len(iv) != AESBlockSize {
		return nil, ErrInvalidIVSize
	}
	if len(data)%AESBlockSize != 0 {
		return nil, ErrInvalidBlockSize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	result := make([]byte, len(data))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(result, data)

	return result, nil
}

// AESCipher wraps an AES block cipher for repeated use.
type AESCipher struct {
	block cipher.Block
}

// NewAESCipher creates a new AES cipher with the given key.
func NewAESCipher(key []byte) (*AESCipher, error) {
	if len(key) != AESKeySize {
		return nil, ErrInvalidKeySize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return &AESCipher{block: block}, nil
}

// EncryptBlock encrypts a single AES block in place.
func (c *AESCipher) EncryptBlock(dst, src []byte) {
	c.block.Encrypt(dst, src)
}

// DecryptBlock decrypts a single AES block in place.
func (c *AESCipher) DecryptBlock(dst, src []byte) {
	c.block.Decrypt(dst, src)
}

// EncryptCBC encrypts data in CBC mode.
func (c *AESCipher) EncryptCBC(iv, data []byte) ([]byte, error) {
	if len(iv) != AESBlockSize {
		return nil, ErrInvalidIVSize
	}
	if len(data)%AESBlockSize != 0 {
		return nil, ErrInvalidBlockSize
	}

	result := make([]byte, len(data))
	mode := cipher.NewCBCEncrypter(c.block, iv)
	mode.CryptBlocks(result, data)

	return result, nil
}

// DecryptCBC decrypts data in CBC mode.
func (c *AESCipher) DecryptCBC(iv, data []byte) ([]byte, error) {
	if len(iv) != AESBlockSize {
		return nil, ErrInvalidIVSize
	}
	if len(data)%AESBlockSize != 0 {
		return nil, ErrInvalidBlockSize
	}

	result := make([]byte, len(data))
	mode := cipher.NewCBCDecrypter(c.block, iv)
	mode.CryptBlocks(result, data)

	return result, nil
}
