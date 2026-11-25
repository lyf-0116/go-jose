package jose

import (
	"errors"
	"testing"
)

func TestStrictB64CriticalConsistency(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	payload := []byte("payload")

	validSigner, err := NewSigner(SigningKey{
		Algorithm: HS256,
		Key:       key,
	}, new(SignerOptions).WithBase64(false))
	if err != nil {
		t.Fatal(err)
	}
	valid, err := validSigner.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := valid.Verify(key); err != nil {
		t.Fatalf("valid b64/crit token was rejected: %v", err)
	}

	for name, options := range map[string]*SignerOptions{
		"b64 without crit":      new(SignerOptions).WithHeader(headerB64, false),
		"crit without b64":      new(SignerOptions).WithCritical(headerB64),
		"b64 true without crit": new(SignerOptions).WithHeader(headerB64, true),
	} {
		t.Run(name, func(t *testing.T) {
			signer, err := NewSigner(SigningKey{Algorithm: HS256, Key: key}, options)
			if err != nil {
				t.Fatal(err)
			}
			signed, err := signer.Sign(payload)
			if err != nil {
				t.Fatal(err)
			}

			_, verifyErr := signed.Verify(key)
			if !errors.Is(verifyErr, ErrUnsupportedCriticalHeader) {
				t.Fatalf("Verify error = %v, want ErrUnsupportedCriticalHeader", verifyErr)
			}
			if _, _, _, multiErr := signed.VerifyMulti(key); multiErr == nil {
				t.Fatal("VerifyMulti accepted inconsistent b64/crit header")
			}
		})
	}
}

func TestStrictB64HeaderParsing(t *testing.T) {
	invalid := rawHeader{}
	if err := invalid.set(headerB64, 0); err != nil {
		t.Fatal(err)
	}
	if b64, err := invalid.getB64(); err == nil {
		t.Fatal("getB64 accepted a numeric value")
	} else if b64 {
		t.Fatal("getB64 returned true with a parse error")
	}

	missingB64 := rawHeader{}
	if err := missingB64.set(headerCritical, []string{headerB64}); err != nil {
		t.Fatal(err)
	}
	if _, err := missingB64.checkB64(); !errors.Is(err, ErrUnsupportedCriticalHeader) {
		t.Fatalf("checkB64 with crit but no field error = %v", err)
	}

	missingCrit := rawHeader{}
	if err := missingCrit.set(headerB64, false); err != nil {
		t.Fatal(err)
	}
	if _, err := missingCrit.checkB64(); !errors.Is(err, ErrUnsupportedCriticalHeader) {
		t.Fatalf("checkB64 with field but no crit error = %v", err)
	}
}

func TestStrictUnprotectedB64Rejected(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	signer, err := NewSigner(SigningKey{Algorithm: HS256, Key: key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}

	signed.Signatures[0].header = &rawHeader{}
	if err := signed.Signatures[0].header.set(headerB64, false); err != nil {
		t.Fatal(err)
	}

	if _, err := signed.Verify(key); !errors.Is(err, ErrUnsupportedCriticalHeader) {
		t.Fatalf("Verify error = %v, want ErrUnsupportedCriticalHeader", err)
	}
}
