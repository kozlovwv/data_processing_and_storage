package generator

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

func GenerateBookRef() string {
	const charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	result := make([]byte, 6)
	
	for i := range 6 {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			result[i] = charset[0]
			continue
		}
		result[i] = charset[num.Int64()]
	}
	
	return string(result)
}

func GenerateTicketNo() string {
	result := "000"
	
	for range 10 {
		num, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			result += "0"
			continue
		}
		result += fmt.Sprintf("%d", num.Int64())
	}
	
	return result
}