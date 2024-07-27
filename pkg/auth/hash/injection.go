package hash

func NewArgonService(
	memory uint32,
	iterations uint32,
	Parallelism uint8,
	SaltLength uint32,
	KeyLength uint32,
) *Argon {
	return &Argon{
		Memory:      memory,
		Iterations:  iterations,
		Parallelism: Parallelism,
		SaltLength:  SaltLength,
		KeyLength:   KeyLength,
	}
}

type HashService interface {
	HashPassword(password string) (string, error)
	VerifyPassword(password string, encodedHash string) (bool, error)
}
