package db

import (
	"context"
	"encoding/gob"

	"github.com/alexedwards/scs/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type DB struct {
	pool    *pgxpool.Pool
	session *scs.SessionManager
}

type UserSessionData struct {
	Username                               string
	IsAuthenticated, IsAdmin, IsOTPEnabled bool
}

type User struct {
	Username     string
	PasswordHash []byte
	IsAdmin      bool
}

func Create(dbPool *pgxpool.Pool, sessionManager *scs.SessionManager) DB {
	gob.Register(UserSessionData{})
	return DB{dbPool, sessionManager}
}

func (db DB) UserSessionDataCreateIfDoesNotExist(ctx context.Context) {
	if !db.session.Exists(ctx, "UserSessionData") {
		db.session.Put(ctx, "UserSessionData", UserSessionData{})
	}
}

func (db DB) UserSessionDataGet(ctx context.Context) UserSessionData {
	data := db.session.Get(ctx, "UserSessionData").(UserSessionData)
	return data
}

func (db DB) UserSessionDataSet(data UserSessionData, ctx context.Context) {
	db.session.Put(ctx, "UserSessionData", data)
}

func (db DB) UserSessionDataDestroy(ctx context.Context) {
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
	return err
}

func (db DB) UserPasswordHashGet(username string) ([]byte, error) {
	var passwordHash []byte
	err := db.pool.QueryRow(context.Background(), "select password_hash from users where username = $1", username).Scan(&passwordHash)
	return passwordHash, err
}

func (db DB) UserPasswordHashSet(username string, newHash []byte) error {
	_, err := db.pool.Exec(context.Background(), "update users set password_hash = $1 where username = $2", newHash, username)
	return err
}

func (db DB) UserTableGet() ([]User, error) {
	rows, _ := db.pool.Query(context.Background(), "select * from users;")
	users, err := pgx.CollectRows(rows, pgx.RowToStructByName[User])
	return users, err
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

func (db DB) SessionPut(key string, value interface{}, ctx context.Context) {
	db.session.Put(ctx, key, value)
}

func (db DB) SessionGet(key string, ctx context.Context) interface{} {
	secret := db.session.Get(ctx, key)
	return secret
}

func (db DB) SessionRemove(key string, ctx context.Context) {
	db.session.Remove(ctx, key)
}
