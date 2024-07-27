package hash

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

var (
	ErrInvalidHash         = errors.New("the encoded hash is not in the correct format")
	ErrIncompatibleVersion = errors.New("incompatible version of argon2")
)

type Argon struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

func (a *Argon) HashPassword(
	password string,
) (encodedHash string, err error) {

	// Generate the salt
	salt, err := generateSalt(a.SaltLength)
	if err != nil {
		return "", err
	}

	// Generate a hash of the password using the Argon2id variant
	hash := argon2.IDKey(
		[]byte(password),
		salt,
		a.Iterations,
		a.Memory,
		a.Parallelism,
		a.KeyLength,
	)

	// encode the salt and password in base64
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	// Return a string with the standard encoded hash representation
	encodedHash = fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		a.Memory,
		a.Iterations,
		a.Parallelism,
		b64Salt,
		b64Hash,
	)

	return encodedHash, nil
}

func (a *Argon) VerifyPassword(
	password string,
	encodedHash string,
) (match bool, err error) {

	// Extract the parameters, salt and hash
	a, salt, hash, err := decodeArgonHash(encodedHash)
	if err != nil {
		return false, err
	}

	// Derive the key from the other password using the same parameters.
	otherHash := argon2.IDKey(
		[]byte(password),
		salt,
		a.Iterations,
		a.Memory,
		a.Parallelism,
		a.KeyLength,
	)

	// Check if the hashes are identical. constant time compare is used to
	// prevent timing attacks.
	if subtle.ConstantTimeCompare(hash, otherHash) == 1 {
		return true, nil
	}

	return false, nil
}

func decodeArgonHash(
	encodedHash string,
) (
	a *Argon,
	salt []byte,
	hash []byte,
	err error,
) {
	vals := strings.Split(encodedHash, "$")
	if len(vals) != 6 {
		return nil, nil, nil, ErrInvalidHash
	}

	var version int
	_, err = fmt.Sscanf(vals[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, err
	}
	if version != argon2.Version {
		return nil, nil, nil, ErrIncompatibleVersion
	}

	a = &Argon{}
	_, err = fmt.Sscanf(
		vals[3],
		"m=%d,t=%d,p=%d",
		&a.Memory,
		&a.Iterations,
		&a.Parallelism,
	)
	if err != nil {
		return nil, nil, nil, err
	}

	salt, err = base64.RawStdEncoding.Strict().DecodeString(vals[4])
	if err != nil {
		return nil, nil, nil, err
	}
	a.SaltLength = uint32(len(salt))

	hash, err = base64.RawStdEncoding.Strict().DecodeString(vals[5])
	if err != nil {
		return nil, nil, nil, err
	}
	a.KeyLength = uint32(len(hash))

	return a, salt, hash, nil
}
