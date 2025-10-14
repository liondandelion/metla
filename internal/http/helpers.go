package http

import (
	"crypto/cipher"
	"crypto/sha256"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"

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

func LinksStringToEventIDs(links string) ([]mdb.EventID, error) {
	var linkIDs []mdb.EventID
	trimmed := strings.TrimRightFunc(links, unicode.IsSpace)
	if trimmed == "" {
		return linkIDs, nil
	}
	linkStrings := strings.Split(trimmed, " ")

	for _, linkString := range linkStrings {
		ls := strings.Split(linkString, "-")
		author := ls[0]
		idString := ls[1]

		id, err := strconv.ParseInt(idString, 10, 64)
		if err != nil {
			return nil, err
		}
		linkIDs = append(linkIDs, mdb.EventID{ID: id, Author: author})
	}
	return linkIDs, nil
}

func TimeStringToTimeUTC(timeString string) (time.Time, error) {
	layout := "2006-01-02T15:04"
	var err error
	t, err := time.Parse(layout, timeString)
	if err != nil {
		return t, err
	}
	return t.UTC(), err
}

func UsernameIsValid(username string) bool {
	if len(username) == 0 {
		return false
	}

	for _, r := range username {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			if r != '_' {
				return false
			}
		}
	}
	return true
}

func PasswordIsValid(password string) bool {
	return len(password) >= 4
}
