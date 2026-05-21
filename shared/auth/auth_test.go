package auth

import (
	"testing"
	"time"
)

func TestCheckinSignVerify(t *testing.T) {
	secret, err := GenerateAgentSecret()
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"agent_id":"a1"}`)
	ts := time.Now().UTC().Unix()
	sig := SignCheckin(secret, "a1", ts, body)
	if err := VerifyCheckin(secret, "a1", ts, body, sig); err != nil {
		t.Fatal(err)
	}
}

func TestDEKWrapUnwrap(t *testing.T) {
	master := make([]byte, MasterKeySize)
	agentSecret, _ := GenerateAgentSecret()
	dek := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	sealed, err := SealDEKForStorage(dek, master)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenDEKFromStorage(sealed, master)
	if err != nil || opened != dek {
		t.Fatalf("storage roundtrip: %v got %q", err, opened)
	}
	wrapped, err := WrapDEKForAgent(dek, agentSecret)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := UnwrapDEKForAgent(wrapped, agentSecret)
	if err != nil || plain != dek {
		t.Fatalf("agent wrap: %v got %q", err, plain)
	}
}

func TestValidateReleaseVersion(t *testing.T) {
	if !ValidateReleaseVersion("1.2.3") {
		t.Fatal("expected valid")
	}
	if ValidateReleaseVersion("../etc") {
		t.Fatal("expected invalid")
	}
}
