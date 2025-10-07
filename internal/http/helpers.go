package http

import (
	"crypto/cipher"
	"crypto/sha256"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"

	mdb "github.com/liondandelion/metla/internal/db"
)

func OTPValidate(username, otpCode string, db mdb.DB, ghGCM cipher.AEAD) (bool, error) {
	otpSecretEnc, err := db.UserOTPSecretGet(username)
	if err != nil {
		log.Printf("OTPValidate: failed to get secret: %v", err)
		return false, err
	}

	nonce := sha256.Sum256([]byte(username))
	otpSecretB, err := ghGCM.Open(nil, nonce[:12], otpSecretEnc, nil)
	if err != nil {
		log.Printf("OTPIsCodeValid: failed to open: %v", err)
		return false, err
	}
	otpSecret := string(otpSecretB)

	return totp.Validate(otpCode, otpSecret), nil
}

func HashPassword(password []byte) ([]byte, error) {
	/* encodedSaltSize = 22 bytes */
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return bytes, err
}

func HTMXRedirect(w http.ResponseWriter, path string) {
	h := w.Header()
	h.Set("HX-Redirect", path)
	w.WriteHeader(http.StatusOK)
}
