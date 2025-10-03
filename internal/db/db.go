package db

import (
	"context"
	"encoding/gob"

	"github.com/alexedwards/scs/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type DB struct {
	pool *pgxpool.Pool
	session *scs.SessionManager
}

type UserData struct {
	Username                               string
	IsAuthenticated, IsAdmin, IsOTPEnabled bool
}

type User struct {
	Username     string
	PasswordHash []byte
	IsAdmin      bool
}

func Create(dbPool *pgxpool.Pool, sessionManager *scs.SessionManager) DB {
	gob.Register(UserData{})
	return DB{dbPool, sessionManager}
}

func (db DB) UserDataCreateIfDoesNotExist(ctx context.Context) {
	if !db.session.Exists(ctx, "UserData") {
		db.session.Put(ctx, "UserData", UserData{})
	}
}

func (db DB) UserDataGet(ctx context.Context) UserData {
	data := db.session.Get(ctx, "UserData").(UserData)
	return data
}

func (db DB) UserDataSet(data UserData, ctx context.Context) {
	db.session.Put(ctx, "UserData", data)
}

func (db DB) UserDataDestroy(ctx context.Context) {
	db.session.Destroy(ctx)
}

func (db DB) UserExists(username string) (bool, error) {
	var exists bool
	err := db.pool.QueryRow(context.Background(), "select exists (select 1 from users where username = $1)", username).Scan(&exists)
	return exists, err
}

func (db DB) UserIsAdmin(username string) (bool, error) {
	var isAdmin bool
	err := db.pool.QueryRow(context.Background(), "select is_admin from users where username = $1", username).Scan(&isAdmin)
	return isAdmin, err
}

func (db DB) UserIsOTPEnabled(username string) (bool, error) {
	var isOTPEnabled bool
	err := db.pool.QueryRow(context.Background(), "select exists (select 1 from otp where username = $1)", username).Scan(&isOTPEnabled)
	return isOTPEnabled, err
}

func (db DB) UserTokenRenew(ctx context.Context) {
	db.session.RenewToken(ctx)
}

func (db DB) UserInsert(username string, passwordHash []byte, isAdmin bool) error {
	_, err := db.pool.Exec(context.Background(), "insert into users (username, password_hash, is_admin) values ($1, $2, $3)", username, passwordHash, isAdmin)
	return err;
}

func (db DB) UserPasswordHashGet(username string) ([]byte, error) {
	var passwordHash []byte
	err := db.pool.QueryRow(context.Background(), "select password_hash from users where username = $1", username).Scan(&passwordHash)
	return passwordHash, err
}

func (db DB) UserPasswordHashSet(username string, newHash []byte) error {
	_, err := db.pool.Exec(context.Background(), "update users set password_hash = $1 where username = $2", newHash, username)
	return err;
}

func (db DB) UserTableGet() ([]User, error) {
	rows, _ := db.pool.Query(context.Background(), "select * from users;")
	users, err := pgx.CollectRows(rows, pgx.RowToStructByName[User])
	return users, err
}

func (db DB) SessionOTPSecretPut(secret []byte, ctx context.Context) {
	db.session.Put(ctx, "otpSecret", secret)
}

func (db DB) SessionOTPSecretGet(ctx context.Context) []byte {
	secret := db.session.GetBytes(ctx, "otpSecret")
	return secret
}

func (db DB) SessionOTPSecretRemove(ctx context.Context) {
	db.session.Remove(ctx, "otpSecret")
}

func (db DB) UserOTPSecretInsert(username string, otpSecret []byte) error {
	_, err := db.pool.Exec(context.Background(), "insert into otp (username, otp) values ($1, $2)", username, otpSecret)
	return err
}

func (db DB) UserOTPSecretGet(username string) ([]byte, error) {
	var otpSecret []byte
	err := db.pool.QueryRow(context.Background(), "select otp from otp where username = $1", username).Scan(&otpSecret)
	return otpSecret, err
}

func (db DB) UserOTPSecretDelete(username string) error {
	_, err := db.pool.Exec(context.Background(), "delete from otp where username = $1", username)
	return err
}
