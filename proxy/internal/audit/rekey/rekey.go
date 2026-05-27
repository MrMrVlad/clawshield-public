// Package rekey migrates encrypted audit fields from one AES-256-GCM key to another.
package rekey

import (
	"database/sql"
	"fmt"

	"github.com/SleuthCo/clawshield/proxy/internal/audit/crypto"
)

// dbQuerier is satisfied by *sql.DB and *sql.Tx.
type dbQuerier interface {
	Query(query string, args ...any) (*sql.Rows, error)
	Exec(query string, args ...any) (sql.Result, error)
}

// Options controls re-encryption behavior.
type Options struct {
	DryRun bool
	Batch  int
}

// Result summarizes a rekey run.
type Result struct {
	DecisionsUpdated  int
	ToolCallsUpdated  int
	SkippedPlaintext int
	Errors          int
}

// Run re-encrypts sensitive columns in the audit database.
func Run(db *sql.DB, oldKey, newKey []byte, opts Options) (*Result, error) {
	if len(oldKey) != crypto.KeySize || len(newKey) != crypto.KeySize {
		return nil, crypto.ErrInvalidKeySize
	}
	oldEnc, err := crypto.NewFieldEncryptor(oldKey)
	if err != nil {
		return nil, err
	}
	newEnc, err := crypto.NewFieldEncryptor(newKey)
	if err != nil {
		return nil, err
	}
	if opts.Batch <= 0 {
		opts.Batch = 100
	}

	res := &Result{}
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	if err := rekeyDecisions(tx, oldEnc, newEnc, opts, res); err != nil {
		return res, err
	}
	if err := rekeyToolCalls(tx, oldEnc, newEnc, opts, res); err != nil {
		return res, err
	}
	if opts.DryRun {
		return res, nil
	}
	if err := tx.Commit(); err != nil {
		return res, err
	}
	return res, nil
}

func rekeyDecisions(db dbQuerier, oldEnc, newEnc *crypto.FieldEncryptor, opts Options, res *Result) error {
	rows, err := db.Query(`SELECT decision_id, decision_details, arguments_hash FROM decisions`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var id int64
		var details, argsHash []byte
		if err := rows.Scan(&id, &details, &argsHash); err != nil {
			res.Errors++
			continue
		}
		newDetails, okD, err := rekeyField(oldEnc, newEnc, details)
		if err != nil {
			res.Errors++
			continue
		}
		newArgs, okA, err := rekeyField(oldEnc, newEnc, argsHash)
		if err != nil {
			res.Errors++
			continue
		}
		if !okD && !okA {
			res.SkippedPlaintext++
			continue
		}
		if opts.DryRun {
			res.DecisionsUpdated++
			continue
		}
		_, err = db.Exec(`UPDATE decisions SET decision_details = ?, arguments_hash = ? WHERE decision_id = ?`,
			newDetails, newArgs, id)
		if err != nil {
			res.Errors++
			continue
		}
		res.DecisionsUpdated++
	}
	return rows.Err()
}

func rekeyToolCalls(db dbQuerier, oldEnc, newEnc *crypto.FieldEncryptor, opts Options, res *Result) error {
	rows, err := db.Query(`SELECT rowid, request_json, response_json FROM tool_calls`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var id int64
		var req, resp []byte
		if err := rows.Scan(&id, &req, &resp); err != nil {
			res.Errors++
			continue
		}
		newReq, okR, err := rekeyField(oldEnc, newEnc, req)
		if err != nil {
			res.Errors++
			continue
		}
		newResp, okS, err := rekeyField(oldEnc, newEnc, resp)
		if err != nil {
			res.Errors++
			continue
		}
		if !okR && !okS {
			continue
		}
		if opts.DryRun {
			res.ToolCallsUpdated++
			continue
		}
		_, err = db.Exec(`UPDATE tool_calls SET request_json = ?, response_json = ? WHERE rowid = ?`,
			newReq, newResp, id)
		if err != nil {
			res.Errors++
			continue
		}
		res.ToolCallsUpdated++
	}
	return rows.Err()
}

func rekeyField(oldEnc, newEnc *crypto.FieldEncryptor, data []byte) ([]byte, bool, error) {
	if len(data) == 0 {
		return data, false, nil
	}
	if !crypto.IsEncrypted(data) {
		return data, false, nil
	}
	plain, err := oldEnc.Decrypt(data)
	if err != nil {
		return nil, false, fmt.Errorf("decrypt: %w", err)
	}
	out, err := newEnc.Encrypt(plain)
	if err != nil {
		return nil, false, err
	}
	return out, true, nil
}
