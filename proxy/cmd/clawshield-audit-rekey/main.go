// Command clawshield-audit-rekey re-encrypts audit DB fields after key rotation.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/SleuthCo/clawshield/proxy/internal/audit/rekey"
	_ "github.com/mattn/go-sqlite3"
	"database/sql"
)

func main() {
	dbPath := flag.String("db", "/var/lib/clawshield/audit.db", "audit SQLite path")
	oldKeyHex := flag.String("old-key", "", "previous 64-char hex key (or CLAWSHIELD_AUDIT_ENCRYPTION_KEY_OLD)")
	newKeyHex := flag.String("new-key", "", "new 64-char hex key (or CLAWSHIELD_AUDIT_ENCRYPTION_KEY)")
	dryRun := flag.Bool("dry-run", false, "report counts without writing")
	flag.Parse()

	oldHex := *oldKeyHex
	if oldHex == "" {
		oldHex = os.Getenv("CLAWSHIELD_AUDIT_ENCRYPTION_KEY_OLD")
	}
	newHex := *newKeyHex
	if newHex == "" {
		newHex = os.Getenv("CLAWSHIELD_AUDIT_ENCRYPTION_KEY")
	}
	oldKey, err := hex.DecodeString(oldHex)
	if err != nil || len(oldKey) != 32 {
		log.Fatal("invalid old key: need 64 hex chars")
	}
	newKey, err := hex.DecodeString(newHex)
	if err != nil || len(newKey) != 32 {
		log.Fatal("invalid new key: need 64 hex chars")
	}

	db, err := sql.Open("sqlite3", *dbPath)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer db.Close()

	res, err := rekey.Run(db, oldKey, newKey, rekey.Options{DryRun: *dryRun, Batch: 100})
	if err != nil {
		log.Fatalf("rekey: %v", err)
	}
	fmt.Printf("decisions_updated=%d tool_calls_updated=%d skipped_plaintext=%d errors=%d dry_run=%v\n",
		res.DecisionsUpdated, res.ToolCallsUpdated, res.SkippedPlaintext, res.Errors, *dryRun)
}
