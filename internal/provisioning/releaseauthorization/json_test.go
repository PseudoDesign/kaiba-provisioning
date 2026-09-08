package releaseauthorization

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestStrictParsersRejectAmbiguousJSON(t *testing.T) {
	fixture := newAuthorityFixture(t, 20*time.Second, 10*time.Second, 8)
	if err := fixture.authority.RegisterBootstrapKey(fixture.binding.LogicalIdentity, fixture.bootstrapPublic); err != nil {
		t.Fatal(err)
	}
	challenge, err := fixture.authority.IssueChallenge()
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := challenge.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	duplicate := append([]byte(`{"schema_version":"`+ChallengeSchemaVersion+`",`), canonical[1:]...)
	unknown := append(append([]byte(nil), canonical[:len(canonical)-1]...), []byte(`,"unknown":true}`)...)
	nullSignature := []byte(strings.Replace(string(canonical), `"signature":"`+challenge.Signature+`"`, `"signature":null`, 1))
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"leading whitespace", append([]byte(" "), canonical...)},
		{"trailing newline", append(append([]byte(nil), canonical...), '\n')},
		{"duplicate key", duplicate},
		{"unknown field", unknown},
		{"null", nullSignature},
		{"trailing value", append(append([]byte(nil), canonical...), []byte(`{}`)...)},
		{"oversize", bytes.Repeat([]byte("x"), MaxDocumentBytes+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseChallenge(test.data); !errors.Is(err, ErrInvalid) {
				t.Fatalf("ParseChallenge() error = %v", err)
			}
		})
	}
}

func TestRequestParserVerifiesBootstrapProof(t *testing.T) {
	fixture := newAuthorityFixture(t, 20*time.Second, 10*time.Second, 8)
	challenge, err := fixture.authority.IssueChallenge()
	if err != nil {
		t.Fatal(err)
	}
	request := fixture.request(t, challenge)
	request.BootstrapProof = flipLastHex(request.BootstrapProof)
	encoded, err := marshalBounded(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseAuthorizationRequest(encoded); !errors.Is(err, ErrSignature) {
		t.Fatalf("ParseAuthorizationRequest() error = %v, want ErrSignature", err)
	}
}

func TestChallengeSignatureCoversEveryClaimAndUsesDomainSeparation(t *testing.T) {
	fixture := newAuthorityFixture(t, 20*time.Second, 10*time.Second, 8)
	challenge, err := fixture.authority.IssueChallenge()
	if err != nil {
		t.Fatal(err)
	}
	mutations := []func(*Challenge){
		func(value *Challenge) { value.ChallengeID = "challenge:" + strings.Repeat("a", 64) },
		func(value *Challenge) { value.Nonce = "hex:" + strings.Repeat("a", 64) },
		func(value *Challenge) { value.IssuedAtUnixSeconds++ },
		func(value *Challenge) { value.MaxAgeSeconds++ },
		func(value *Challenge) { value.AuthorityKeyID = "test-authority-2" },
	}
	for index, mutate := range mutations {
		mutated := challenge
		mutate(&mutated)
		if err := VerifyChallenge(mutated, fixture.authority.PublicKey(), 0); !errors.Is(err, ErrSignature) {
			t.Fatalf("mutation %d error = %v, want ErrSignature", index, err)
		}
	}

	if err := VerifyChallenge(challenge, fixture.authority.PublicKey(), -time.Nanosecond); !errors.Is(err, ErrInvalid) {
		t.Fatalf("negative elapsed error = %v", err)
	}
	request := fixture.request(t, challenge)
	if err := fixture.authority.RegisterBootstrapKey(fixture.binding.LogicalIdentity, fixture.bootstrapPublic); err != nil {
		t.Fatal(err)
	}
	authorization, err := fixture.authority.Authorize(request)
	if err != nil {
		t.Fatal(err)
	}
	authorization.Signature = challenge.Signature
	if err := VerifyAuthorization(authorization, request, fixture.authority.PublicKey(), 0); !errors.Is(err, ErrSignature) {
		t.Fatalf("cross-domain signature error = %v", err)
	}
}
