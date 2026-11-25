package jose

import (
	"encoding/base64"
	"errors"
	"testing"
)

// protectedHeader is a small helper that base64url-encodes a raw protected
// header JSON object, as used in the JWE/JWS JSON serializations.
func protectedHeader(t *testing.T, raw string) string {
	t.Helper()
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// withDuplicateCompat temporarily enables the lenient compatibility mode and
// captures any duplicate-header warnings, restoring the previous state on
// cleanup. It returns a pointer to the slice of warned parameter names.
func withDuplicateCompat(t *testing.T) *[]HeaderKey {
	t.Helper()
	prevAllow := AllowDuplicateHeaderParameters
	prevWarn := DuplicateHeaderWarning
	var warned []HeaderKey
	DuplicateHeaderWarning = func(duplicates []HeaderKey) {
		warned = append(warned, duplicates...)
	}
	AllowDuplicateHeaderParameters = true
	t.Cleanup(func() {
		AllowDuplicateHeaderParameters = prevAllow
		DuplicateHeaderWarning = prevWarn
	})
	return &warned
}

func TestJWERejectsDuplicateProtectedUnprotected(t *testing.T) {
	// "kid" appears in both the authenticated protected header and the
	// shared unprotected header.
	protected := protectedHeader(t, `{"alg":"RSA-OAEP","enc":"A128GCM","kid":"trusted"}`)
	msg := `{
		"protected":"` + protected + `",
		"unprotected":{"kid":"attacker"},
		"encrypted_key":"dGVzdA",
		"iv":"dGVzdA",
		"ciphertext":"dGVzdA",
		"tag":"dGVzdA"
	}`

	_, err := ParseEncryptedJSON(msg, []KeyAlgorithm{RSA_OAEP}, []ContentEncryption{A128GCM})
	if !errors.Is(err, ErrDuplicateHeaderParameter) {
		t.Fatalf("ParseEncryptedJSON() error = %v, want ErrDuplicateHeaderParameter", err)
	}

	warned := withDuplicateCompat(t)
	parsed, err := ParseEncryptedJSON(msg, []KeyAlgorithm{RSA_OAEP}, []ContentEncryption{A128GCM})
	if err != nil {
		t.Fatalf("ParseEncryptedJSON() in compatibility mode: %v", err)
	}
	if parsed.Header.KeyID != "trusted" {
		t.Errorf("KeyID = %q, want authenticated protected value %q", parsed.Header.KeyID, "trusted")
	}
	if len(*warned) != 1 || (*warned)[0] != headerKeyID {
		t.Errorf("warning = %v, want [%s]", *warned, headerKeyID)
	}
}

func TestJWERejectsDuplicateProtectedPerRecipient(t *testing.T) {
	// "enc" is a protected parameter but is also placed in the recipient
	// header, where it is not authenticated.
	protected := protectedHeader(t, `{"alg":"RSA-OAEP","enc":"A128GCM"}`)
	msg := `{
		"protected":"` + protected + `",
		"recipients":[{"header":{"enc":"A256GCM"},"encrypted_key":"dGVzdA"}],
		"iv":"dGVzdA",
		"ciphertext":"dGVzdA",
		"tag":"dGVzdA"
	}`

	_, err := ParseEncryptedJSON(msg, []KeyAlgorithm{RSA_OAEP},
		[]ContentEncryption{A128GCM, A256GCM})
	if !errors.Is(err, ErrDuplicateHeaderParameter) {
		t.Fatalf("ParseEncryptedJSON() error = %v, want ErrDuplicateHeaderParameter", err)
	}
}

func TestJWERejectsDuplicateUnprotectedPerRecipient(t *testing.T) {
	// The shared unprotected header and the recipient header share "kid".
	protected := protectedHeader(t, `{"alg":"RSA-OAEP","enc":"A128GCM"}`)
	msg := `{
		"protected":"` + protected + `",
		"unprotected":{"kid":"shared"},
		"recipients":[{"header":{"kid":"recipient"},"encrypted_key":"dGVzdA"}],
		"iv":"dGVzdA",
		"ciphertext":"dGVzdA",
		"tag":"dGVzdA"
	}`

	_, err := ParseEncryptedJSON(msg, []KeyAlgorithm{RSA_OAEP}, []ContentEncryption{A128GCM})
	if !errors.Is(err, ErrDuplicateHeaderParameter) {
		t.Fatalf("ParseEncryptedJSON() error = %v, want ErrDuplicateHeaderParameter", err)
	}
}

func TestJWEDuplicateWarningFiresEvenWhenRejecting(t *testing.T) {
	protected := protectedHeader(t, `{"alg":"RSA-OAEP","enc":"A128GCM","kid":"trusted"}`)
	msg := `{
		"protected":"` + protected + `",
		"unprotected":{"kid":"attacker"},
		"encrypted_key":"dGVzdA",
		"iv":"dGVzdA",
		"ciphertext":"dGVzdA",
		"tag":"dGVzdA"
	}`

	prevWarn := DuplicateHeaderWarning
	var warned []HeaderKey
	DuplicateHeaderWarning = func(duplicates []HeaderKey) {
		warned = append(warned, duplicates...)
	}
	t.Cleanup(func() { DuplicateHeaderWarning = prevWarn })

	if AllowDuplicateHeaderParameters {
		t.Fatal("test requires the default strict parsing mode")
	}
	_, err := ParseEncryptedJSON(msg, []KeyAlgorithm{RSA_OAEP}, []ContentEncryption{A128GCM})
	if !errors.Is(err, ErrDuplicateHeaderParameter) {
		t.Fatalf("ParseEncryptedJSON() error = %v, want ErrDuplicateHeaderParameter", err)
	}
	if len(warned) != 1 || warned[0] != headerKeyID {
		t.Errorf("warning = %v, want [%s] even when the message is rejected", warned, headerKeyID)
	}
}

func TestJWEAllowsSameParameterAcrossDistinctRecipients(t *testing.T) {
	// Each recipient header is merged independently with the shared headers,
	// so the same parameter name in distinct recipients is legitimate and
	// must not be rejected (RFC 7516 general JSON serialization).
	protected := protectedHeader(t, `{"enc":"A128GCM"}`)
	msg := `{
		"protected":"` + protected + `",
		"recipients":[
			{"header":{"alg":"RSA-OAEP"},"encrypted_key":"dGVzdA"},
			{"header":{"alg":"RSA-OAEP"},"encrypted_key":"dGVzdA"}
		],
		"iv":"dGVzdA",
		"ciphertext":"dGVzdA",
		"tag":"dGVzdA"
	}`

	obj, err := ParseEncryptedJSON(msg, []KeyAlgorithm{RSA_OAEP}, []ContentEncryption{A128GCM})
	if err != nil {
		t.Fatalf("ParseEncryptedJSON() rejected distinct recipients sharing alg: %v", err)
	}
	if len(obj.recipients) != 2 {
		t.Fatalf("recipients = %d, want 2", len(obj.recipients))
	}
}

func TestJWEAcceptsDisjointHeaders(t *testing.T) {
	// Parameters spread across all three header objects without overlap must
	// continue to parse.
	protected := protectedHeader(t, `{"enc":"A128GCM"}`)
	msg := `{
		"protected":"` + protected + `",
		"unprotected":{"kid":"shared"},
		"recipients":[{"header":{"alg":"RSA-OAEP"},"encrypted_key":"dGVzdA"}],
		"iv":"dGVzdA",
		"ciphertext":"dGVzdA",
		"tag":"dGVzdA"
	}`

	parsed, err := ParseEncryptedJSON(msg, []KeyAlgorithm{RSA_OAEP}, []ContentEncryption{A128GCM})
	if err != nil {
		t.Fatalf("ParseEncryptedJSON() rejected disjoint headers: %v", err)
	}
	if parsed.Header.KeyID != "shared" {
		t.Errorf("global merged header kid = %q, want %q", parsed.Header.KeyID, "shared")
	}
	recipientMerged := parsed.mergedHeaders(&parsed.recipients[0])
	if recipientMerged.getAlgorithm() != RSA_OAEP {
		t.Errorf("recipient merged header alg = %q, want %q", recipientMerged.getAlgorithm(), RSA_OAEP)
	}
}

func TestJWSRejectsDuplicateProtectedUnprotected(t *testing.T) {
	// "alg" is signed in the protected header but repeated unsigned in the
	// header field of the flattened JWS JSON serialization.
	protected := protectedHeader(t, `{"alg":"HS256"}`)
	msg := `{
		"payload":"dGVzdA",
		"protected":"` + protected + `",
		"header":{"alg":"none"},
		"signature":"dGVzdA"
	}`

	_, err := ParseSignedJSON(msg, []SignatureAlgorithm{HS256})
	if !errors.Is(err, ErrDuplicateHeaderParameter) {
		t.Fatalf("ParseSignedJSON() error = %v, want ErrDuplicateHeaderParameter", err)
	}

	withDuplicateCompat(t)
	if _, err := ParseSignedJSON(msg, []SignatureAlgorithm{HS256, SignatureAlgorithm("none")}); err != nil {
		t.Fatalf("ParseSignedJSON() in compatibility mode: %v", err)
	}
}

func TestJWSGeneralRejectsDuplicatePerSignature(t *testing.T) {
	protected := protectedHeader(t, `{"alg":"HS256"}`)
	msg := `{
		"payload":"dGVzdA",
		"signatures":[{
			"protected":"` + protected + `",
			"header":{"kid":"unsigned"},
			"signature":"dGVzdA"
		}]
	}`

	// No duplicate here yet; add one by also placing kid in the protected header.
	protectedWithKid := protectedHeader(t, `{"alg":"HS256","kid":"signed"}`)
	msgWithDup := `{
		"payload":"dGVzdA",
		"signatures":[{
			"protected":"` + protectedWithKid + `",
			"header":{"kid":"unsigned"},
			"signature":"dGVzdA"
		}]
	}`

	if _, err := ParseSignedJSON(msg, []SignatureAlgorithm{HS256}); err != nil {
		t.Fatalf("disjoint JWS headers rejected: %v", err)
	}
	if _, err := ParseSignedJSON(msgWithDup, []SignatureAlgorithm{HS256}); !errors.Is(err, ErrDuplicateHeaderParameter) {
		t.Fatalf("ParseSignedJSON() error = %v, want ErrDuplicateHeaderParameter", err)
	}
}
