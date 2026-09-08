package releaseauthorization

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNonProductionAuthorizationHappyPathBindsEveryInput(t *testing.T) {
	fixture := newAuthorityFixture(t, 10*time.Second, 7*time.Second, 8)
	if err := fixture.authority.RegisterBootstrapKey(fixture.binding.LogicalIdentity, fixture.bootstrapPublic); err != nil {
		t.Fatal(err)
	}
	challenge, err := fixture.authority.IssueChallenge()
	if err != nil {
		t.Fatal(err)
	}
	if challenge.SchemaVersion != ChallengeSchemaVersion || challenge.MaxAgeSeconds != 10 || challenge.IssuedAtUnixSeconds != fixture.clock.now().Unix() {
		t.Fatalf("challenge = %#v", challenge)
	}
	if err := VerifyChallenge(challenge, fixture.authority.PublicKey(), 5*time.Second); err != nil {
		t.Fatalf("VerifyChallenge: %v", err)
	}
	request, err := NewAuthorizationRequest(
		challenge, fixture.binding, clonePrivateKey(fixture.bootstrapPrivate), fixture.oneBootPublic,
		fixture.authority.PublicKey(), time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := fixture.authority.Authorize(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAuthorization(authorization, request, fixture.authority.PublicKey(), 6*time.Second); err != nil {
		t.Fatalf("VerifyAuthorization: %v", err)
	}
	wantChallengeDigest, err := challenge.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if authorization.ChallengeID != challenge.ChallengeID ||
		authorization.ChallengeNonce != challenge.Nonce ||
		authorization.ChallengeDigest != wantChallengeDigest ||
		authorization.Binding != fixture.binding ||
		authorization.BootstrapPublicKey != request.BootstrapPublicKey ||
		authorization.OneBootPublicKey != request.OneBootPublicKey ||
		authorization.AuthorityKeyID != challenge.AuthorityKeyID ||
		authorization.Decision != DecisionAuthorized || authorization.MaxAgeSeconds != 7 {
		t.Fatalf("authorization did not preserve request binding: %#v", authorization)
	}

	challengeJSON, err := challenge.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	parsedChallenge, err := ParseChallenge(challengeJSON)
	if err != nil || parsedChallenge != challenge {
		t.Fatalf("ParseChallenge() = %#v, %v", parsedChallenge, err)
	}
	requestJSON, err := request.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	parsedRequest, err := ParseAuthorizationRequest(requestJSON)
	if err != nil || parsedRequest != request {
		t.Fatalf("ParseAuthorizationRequest() = %#v, %v", parsedRequest, err)
	}
	authorizationJSON, err := authorization.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	parsedAuthorization, err := ParseAuthorization(authorizationJSON)
	if err != nil || parsedAuthorization != authorization {
		t.Fatalf("ParseAuthorization() = %#v, %v", parsedAuthorization, err)
	}
}

func TestAuthorityRejectsEveryUnregisteredBindingMutation(t *testing.T) {
	fixture := newAuthorityFixture(t, 20*time.Second, 10*time.Second, 16)
	tests := []struct {
		name   string
		mutate func(*BootBinding)
	}{
		{"logical identity", func(value *BootBinding) { value.LogicalIdentity = "pi-spike-2" }},
		{"audience", func(value *BootBinding) { value.Audience = "other-initramfs" }},
		{"verifier version", func(value *BootBinding) { value.VerifierVersion++ }},
		{"policy digest", func(value *BootBinding) { value.PolicyDigest = testDigest('c') }},
		{"manifest digest", func(value *BootBinding) { value.ManifestDigest = testDigest('d') }},
		{"security epoch", func(value *BootBinding) { value.SecurityEpoch++ }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			binding := fixture.binding
			test.mutate(&binding)
			if err := fixture.authority.RegisterBootstrapKey(binding.LogicalIdentity, fixture.bootstrapPublic); err != nil {
				t.Fatal(err)
			}
			challenge, err := fixture.authority.IssueChallenge()
			if err != nil {
				t.Fatal(err)
			}
			request, err := NewAuthorizationRequest(
				challenge, binding, clonePrivateKey(fixture.bootstrapPrivate), fixture.oneBootPublic,
				fixture.authority.PublicKey(), 0,
			)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fixture.authority.Authorize(request); !errors.Is(err, ErrUnauthorizedBinding) {
				t.Fatalf("Authorize() error = %v, want ErrUnauthorizedBinding", err)
			}
			if _, err := fixture.authority.Authorize(request); !errors.Is(err, ErrReplay) {
				t.Fatalf("second Authorize() error = %v, want ErrReplay", err)
			}
		})
	}

	if err := fixture.authority.RegisterBootstrapKey(fixture.binding.LogicalIdentity, fixture.bootstrapPublic); err != nil {
		t.Fatal(err)
	}
	challenge, err := fixture.authority.IssueChallenge()
	if err != nil {
		t.Fatal(err)
	}
	request := fixture.request(t, challenge)
	if _, err := fixture.authority.Authorize(request); err != nil {
		t.Fatalf("approved binding was rejected: %v", err)
	}
}

func TestAuthorityRequiresRegisteredBootstrapProof(t *testing.T) {
	fixture := newAuthorityFixture(t, 20*time.Second, 10*time.Second, 8)
	if err := fixture.authority.RegisterBootstrapKey(fixture.binding.LogicalIdentity, fixture.bootstrapPublic); err != nil {
		t.Fatal(err)
	}
	challenge, err := fixture.authority.IssueChallenge()
	if err != nil {
		t.Fatal(err)
	}
	untrustedPrivate := testPrivateKey(9)
	untrustedRequest, err := NewAuthorizationRequest(
		challenge, fixture.binding, untrustedPrivate, fixture.oneBootPublic,
		fixture.authority.PublicKey(), 0,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.authority.Authorize(untrustedRequest); !errors.Is(err, ErrUntrustedBootstrap) {
		t.Fatalf("untrusted bootstrap error = %v", err)
	}

	request := fixture.request(t, challenge)
	tampered := request
	tampered.BootstrapProof = flipLastHex(tampered.BootstrapProof)
	if _, err := fixture.authority.Authorize(tampered); !errors.Is(err, ErrSignature) {
		t.Fatalf("tampered proof error = %v", err)
	}
	if _, err := fixture.authority.Authorize(request); err != nil {
		t.Fatalf("rejected proofs consumed challenge: %v", err)
	}
	secondChallenge, err := fixture.authority.IssueChallenge()
	if err != nil {
		t.Fatal(err)
	}
	secondRequest := fixture.request(t, secondChallenge)
	if _, err := fixture.authority.Authorize(secondRequest); !errors.Is(err, ErrUntrustedBootstrap) {
		t.Fatalf("consumed bootstrap registration error = %v", err)
	}
}

func TestChallengeCanBeConsumedOnlyOnceConcurrently(t *testing.T) {
	fixture := newAuthorityFixture(t, 20*time.Second, 10*time.Second, 8)
	if err := fixture.authority.RegisterBootstrapKey(fixture.binding.LogicalIdentity, fixture.bootstrapPublic); err != nil {
		t.Fatal(err)
	}
	challenge, err := fixture.authority.IssueChallenge()
	if err != nil {
		t.Fatal(err)
	}
	request := fixture.request(t, challenge)

	const workers = 32
	start := make(chan struct{})
	errorsFound := make(chan error, workers)
	var wait sync.WaitGroup
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, err := fixture.authority.Authorize(request)
			errorsFound <- err
		}()
	}
	close(start)
	wait.Wait()
	close(errorsFound)
	succeeded := 0
	replayed := 0
	for err := range errorsFound {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrReplay):
			replayed++
		default:
			t.Fatalf("unexpected concurrent authorization error: %v", err)
		}
	}
	if succeeded != 1 || replayed != workers-1 {
		t.Fatalf("successes=%d replays=%d", succeeded, replayed)
	}
}

func TestOneBootProofIsBoundAndAcceptedOnlyOnce(t *testing.T) {
	fixture := newAuthorityFixture(t, 20*time.Second, 10*time.Second, 8)
	if err := fixture.authority.RegisterBootstrapKey(fixture.binding.LogicalIdentity, fixture.bootstrapPublic); err != nil {
		t.Fatal(err)
	}
	challenge, err := fixture.authority.IssueChallenge()
	if err != nil {
		t.Fatal(err)
	}
	request := fixture.request(t, challenge)
	authorization, err := fixture.authority.Authorize(request)
	if err != nil {
		t.Fatal(err)
	}
	oneBootPrivate := testPrivateKey(3)
	proof, err := NewOneBootProof(authorization, oneBootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(oneBootPrivate, make([]byte, ed25519.PrivateKeySize)) {
		t.Fatal("NewOneBootProof did not clear the supplied private-key buffer")
	}
	wrongPrivate := testPrivateKey(4)
	if _, err := NewOneBootProof(authorization, wrongPrivate); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("wrong one-boot key error = %v", err)
	}
	if !bytes.Equal(wrongPrivate, make([]byte, ed25519.PrivateKeySize)) {
		t.Fatal("NewOneBootProof did not clear the private-key buffer after failure")
	}
	encoded, err := proof.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseOneBootProof(encoded)
	if err != nil || parsed != proof {
		t.Fatalf("ParseOneBootProof() = %#v, %v", parsed, err)
	}
	if err := fixture.authority.ProveOneBoot(proof); err != nil {
		t.Fatal(err)
	}
	if err := fixture.authority.ProveOneBoot(proof); !errors.Is(err, ErrOneBootReplay) {
		t.Fatalf("second ProveOneBoot() error = %v", err)
	}
}

func TestOneBootProofRejectsWrongKeyMutationAndExpiry(t *testing.T) {
	fixture := newAuthorityFixture(t, 20*time.Second, 4*time.Second, 8)
	if err := fixture.authority.RegisterBootstrapKey(fixture.binding.LogicalIdentity, fixture.bootstrapPublic); err != nil {
		t.Fatal(err)
	}
	challenge, err := fixture.authority.IssueChallenge()
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := fixture.authority.Authorize(fixture.request(t, challenge))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewOneBootProof(authorization, testPrivateKey(4)); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("wrong one-boot key error = %v", err)
	}
	proof, err := NewOneBootProof(authorization, testPrivateKey(3))
	if err != nil {
		t.Fatal(err)
	}
	tampered := proof
	tampered.AuthorizationDigest = testDigest('f')
	if err := VerifyOneBootProof(tampered); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("tampered authorization digest error = %v", err)
	}
	tampered = proof
	tampered.Proof = flipLastHex(tampered.Proof)
	if err := VerifyOneBootProof(tampered); !errors.Is(err, ErrSignature) {
		t.Fatalf("tampered one-boot signature error = %v", err)
	}
	fixture.clock.advance(4*time.Second + time.Nanosecond)
	if err := fixture.authority.ProveOneBoot(proof); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired one-boot proof error = %v", err)
	}
}

func TestOneBootProofConcurrentReplayProtection(t *testing.T) {
	fixture := newAuthorityFixture(t, 20*time.Second, 10*time.Second, 8)
	if err := fixture.authority.RegisterBootstrapKey(fixture.binding.LogicalIdentity, fixture.bootstrapPublic); err != nil {
		t.Fatal(err)
	}
	challenge, err := fixture.authority.IssueChallenge()
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := fixture.authority.Authorize(fixture.request(t, challenge))
	if err != nil {
		t.Fatal(err)
	}
	proof, err := NewOneBootProof(authorization, testPrivateKey(3))
	if err != nil {
		t.Fatal(err)
	}
	const workers = 16
	results := make(chan error, workers)
	var wait sync.WaitGroup
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			results <- fixture.authority.ProveOneBoot(proof)
		}()
	}
	wait.Wait()
	close(results)
	succeeded, replayed := 0, 0
	for err := range results {
		if err == nil {
			succeeded++
		} else if errors.Is(err, ErrOneBootReplay) {
			replayed++
		} else {
			t.Fatalf("unexpected proof error: %v", err)
		}
	}
	if succeeded != 1 || replayed != workers-1 {
		t.Fatalf("successes=%d replays=%d", succeeded, replayed)
	}
}

func TestChallengeAndAuthorizationRelativeExpiry(t *testing.T) {
	fixture := newAuthorityFixture(t, 5*time.Second, 4*time.Second, 8)
	if err := fixture.authority.RegisterBootstrapKey(fixture.binding.LogicalIdentity, fixture.bootstrapPublic); err != nil {
		t.Fatal(err)
	}
	challenge, err := fixture.authority.IssueChallenge()
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyChallenge(challenge, fixture.authority.PublicKey(), 5*time.Second); err != nil {
		t.Fatalf("challenge at inclusive deadline: %v", err)
	}
	if err := VerifyChallenge(challenge, fixture.authority.PublicKey(), 5*time.Second+time.Nanosecond); !errors.Is(err, ErrExpired) {
		t.Fatalf("challenge past deadline error = %v", err)
	}
	request := fixture.request(t, challenge)
	fixture.clock.advance(5*time.Second + time.Nanosecond)
	if _, err := fixture.authority.Authorize(request); !errors.Is(err, ErrExpired) {
		t.Fatalf("server challenge expiry error = %v", err)
	}

	second := newAuthorityFixture(t, 20*time.Second, 4*time.Second, 8)
	if err := second.authority.RegisterBootstrapKey(second.binding.LogicalIdentity, second.bootstrapPublic); err != nil {
		t.Fatal(err)
	}
	secondChallenge, err := second.authority.IssueChallenge()
	if err != nil {
		t.Fatal(err)
	}
	secondRequest := second.request(t, secondChallenge)
	authorization, err := second.authority.Authorize(secondRequest)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAuthorization(authorization, secondRequest, second.authority.PublicKey(), 4*time.Second); err != nil {
		t.Fatalf("authorization at inclusive deadline: %v", err)
	}
	if err := VerifyAuthorization(authorization, secondRequest, second.authority.PublicKey(), 4*time.Second+time.Nanosecond); !errors.Is(err, ErrExpired) {
		t.Fatalf("authorization past deadline error = %v", err)
	}
}

func TestAuthorizationVerificationRejectsEveryResponseSubstitution(t *testing.T) {
	fixture := newAuthorityFixture(t, 20*time.Second, 10*time.Second, 8)
	if err := fixture.authority.RegisterBootstrapKey(fixture.binding.LogicalIdentity, fixture.bootstrapPublic); err != nil {
		t.Fatal(err)
	}
	challenge, err := fixture.authority.IssueChallenge()
	if err != nil {
		t.Fatal(err)
	}
	request := fixture.request(t, challenge)
	authorization, err := fixture.authority.Authorize(request)
	if err != nil {
		t.Fatal(err)
	}
	alternatePublic := testPrivateKey(8).Public().(ed25519.PublicKey)
	tests := []struct {
		name   string
		mutate func(*Authorization)
	}{
		{"challenge id", func(value *Authorization) { value.ChallengeID = "challenge:" + strings.Repeat("e", 64) }},
		{"challenge nonce", func(value *Authorization) { value.ChallengeNonce = "hex:" + strings.Repeat("e", 64) }},
		{"challenge digest", func(value *Authorization) { value.ChallengeDigest = testDigest('e') }},
		{"logical identity", func(value *Authorization) { value.Binding.LogicalIdentity = "pi-spike-2" }},
		{"audience", func(value *Authorization) { value.Binding.Audience = "other-initramfs" }},
		{"storage generation", func(value *Authorization) { value.Binding.StorageGeneration = 1 }},
		{"verifier version", func(value *Authorization) { value.Binding.VerifierVersion++ }},
		{"policy digest", func(value *Authorization) { value.Binding.PolicyDigest = testDigest('e') }},
		{"manifest digest", func(value *Authorization) { value.Binding.ManifestDigest = testDigest('f') }},
		{"security epoch", func(value *Authorization) { value.Binding.SecurityEpoch++ }},
		{"bootstrap key", func(value *Authorization) { value.BootstrapPublicKey, _ = EncodePublicKey(alternatePublic) }},
		{"one boot key", func(value *Authorization) { value.OneBootPublicKey, _ = EncodePublicKey(alternatePublic) }},
		{"authority key id", func(value *Authorization) { value.AuthorityKeyID = "test-authority-2" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutated := authorization
			test.mutate(&mutated)
			err := VerifyAuthorization(mutated, request, fixture.authority.PublicKey(), 0)
			if !errors.Is(err, ErrBindingMismatch) && !errors.Is(err, ErrInvalid) {
				t.Fatalf("VerifyAuthorization() error = %v, want binding/validation failure", err)
			}
		})
	}

	tamperedSignature := authorization
	tamperedSignature.Signature = flipLastHex(tamperedSignature.Signature)
	if err := VerifyAuthorization(tamperedSignature, request, fixture.authority.PublicKey(), 0); !errors.Is(err, ErrSignature) {
		t.Fatalf("tampered authorization signature error = %v", err)
	}
	if err := VerifyAuthorization(authorization, request, testPrivateKey(11).Public().(ed25519.PublicKey), 0); !errors.Is(err, ErrSignature) {
		t.Fatalf("wrong authority key error = %v", err)
	}
}

func TestOneBootKeyMustBeDistinctAndStorageGenerationMustBeZero(t *testing.T) {
	fixture := newAuthorityFixture(t, 20*time.Second, 10*time.Second, 8)
	challenge, err := fixture.authority.IssueChallenge()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewAuthorizationRequest(
		challenge, fixture.binding, clonePrivateKey(fixture.bootstrapPrivate), fixture.bootstrapPublic,
		fixture.authority.PublicKey(), 0,
	); !errors.Is(err, ErrInvalid) {
		t.Fatalf("same bootstrap and one-boot key error = %v", err)
	}
	invalidBinding := fixture.binding
	invalidBinding.StorageGeneration = 1
	if _, err := NewAuthorizationRequest(
		challenge, invalidBinding, clonePrivateKey(fixture.bootstrapPrivate), fixture.oneBootPublic,
		fixture.authority.PublicKey(), 0,
	); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nonzero storage generation error = %v", err)
	}
}

func TestNewAuthorizationRequestZeroesBootstrapPrivateKey(t *testing.T) {
	fixture := newAuthorityFixture(t, 20*time.Second, 10*time.Second, 8)
	challenge, err := fixture.authority.IssueChallenge()
	if err != nil {
		t.Fatal(err)
	}
	privateKey := clonePrivateKey(fixture.bootstrapPrivate)
	if _, err := NewAuthorizationRequest(
		challenge, fixture.binding, privateKey, fixture.oneBootPublic, fixture.authority.PublicKey(), 0,
	); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(privateKey, make([]byte, ed25519.PrivateKeySize)) {
		t.Fatal("bootstrap private key was not zeroed")
	}
}

func TestUnregisterBootstrapBindingRevokesPendingRequest(t *testing.T) {
	fixture := newAuthorityFixture(t, 20*time.Second, 10*time.Second, 8)
	if err := fixture.authority.RegisterBootstrapKey(fixture.binding.LogicalIdentity, fixture.bootstrapPublic); err != nil {
		t.Fatal(err)
	}
	challenge, err := fixture.authority.IssueChallenge()
	if err != nil {
		t.Fatal(err)
	}
	request := fixture.request(t, challenge)
	if !fixture.authority.UnregisterBootstrapKey(fixture.binding.LogicalIdentity, fixture.bootstrapPublic) {
		t.Fatal("registered binding was not removed")
	}
	if _, err := fixture.authority.Authorize(request); !errors.Is(err, ErrUntrustedBootstrap) {
		t.Fatalf("authorization after unregister error = %v", err)
	}
	if fixture.authority.UnregisterBootstrapKey(fixture.binding.LogicalIdentity, fixture.bootstrapPublic) {
		t.Fatal("second unregister unexpectedly succeeded")
	}
}

func TestAuthorityCapacityCannotBeExhaustedByChallengeIssuance(t *testing.T) {
	fixture := newAuthorityFixture(t, time.Second, 4*time.Second, 1)
	for index := 0; index < 32; index++ {
		if _, err := fixture.authority.IssueChallenge(); err != nil {
			t.Fatalf("stateless IssueChallenge() %d: %v", index, err)
		}
	}
	if err := fixture.authority.RegisterBootstrapKey(fixture.binding.LogicalIdentity, fixture.bootstrapPublic); err != nil {
		t.Fatal(err)
	}
	challenge, err := fixture.authority.IssueChallenge()
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := fixture.authority.Authorize(fixture.request(t, challenge))
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.authority.RegisterBootstrapKey(fixture.binding.LogicalIdentity, fixture.bootstrapPublic); !errors.Is(err, ErrCapacity) {
		t.Fatalf("registration beyond retained state capacity error = %v", err)
	}
	proof, err := NewOneBootProof(authorization, testPrivateKey(3))
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.authority.ProveOneBoot(proof); err != nil {
		t.Fatal(err)
	}
	fixture.clock.advance(4*time.Second + time.Nanosecond)
	if err := fixture.authority.RegisterBootstrapKey(fixture.binding.LogicalIdentity, fixture.bootstrapPublic); err != nil {
		t.Fatalf("RegisterBootstrapKey() after retained state expiry: %v", err)
	}
	thirdChallenge, err := fixture.authority.IssueChallenge()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.authority.Authorize(fixture.request(t, thirdChallenge)); err != nil {
		t.Fatalf("Authorize() after retained state expiry: %v", err)
	}
}

func TestBootstrapRegistrationCapacityIsBounded(t *testing.T) {
	fixture := newAuthorityFixture(t, time.Second, time.Second, 1)
	if err := fixture.authority.RegisterBootstrapKey(fixture.binding.LogicalIdentity, fixture.bootstrapPublic); err != nil {
		t.Fatal(err)
	}
	if err := fixture.authority.RegisterBootstrapKey(fixture.binding.LogicalIdentity, fixture.bootstrapPublic); err != nil {
		t.Fatalf("idempotent duplicate registration: %v", err)
	}
	second := testPrivateKey(9).Public().(ed25519.PublicKey)
	if err := fixture.authority.RegisterBootstrapKey(fixture.binding.LogicalIdentity, second); !errors.Is(err, ErrCapacity) {
		t.Fatalf("second distinct registration error = %v, want ErrCapacity", err)
	}
	if !fixture.authority.UnregisterBootstrapKey(fixture.binding.LogicalIdentity, fixture.bootstrapPublic) {
		t.Fatal("could not free registered bootstrap capacity")
	}
	if err := fixture.authority.RegisterBootstrapKey(fixture.binding.LogicalIdentity, second); err != nil {
		t.Fatalf("registration after capacity was freed: %v", err)
	}
}

func TestPendingPolicyDecisionRetainsItsCapacityReservation(t *testing.T) {
	clock := &mutableClock{value: time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)}
	binding := BootBinding{
		LogicalIdentity: "pi-spike-1", Audience: "kaiba-rpi5-initramfs",
		VerifierVersion: 1, PolicyDigest: testDigest('a'), ManifestDigest: testDigest('b'), SecurityEpoch: 1,
	}
	policyEntered := make(chan struct{})
	releasePolicy := make(chan struct{})
	authority, err := NewNonProductionAuthority(NonProductionAuthorityConfig{
		AuthorityKeyID: "test-authority-1", SigningKey: testPrivateKey(1),
		ChallengeMaxAge: time.Second, AuthorizationMaxAge: time.Second,
		MaxOutstandingChallenges: 1, Clock: clock.now,
		BindingPolicy: BindingPolicyFunc(func(actual BootBinding) error {
			if actual != binding {
				return ErrUnauthorizedBinding
			}
			close(policyEntered)
			<-releasePolicy
			return nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	bootstrapPrivate := testPrivateKey(2)
	bootstrapPublic := bootstrapPrivate.Public().(ed25519.PublicKey)
	oneBootPublic := testPrivateKey(3).Public().(ed25519.PublicKey)
	if err := authority.RegisterBootstrapKey(binding.LogicalIdentity, bootstrapPublic); err != nil {
		t.Fatal(err)
	}
	challenge, err := authority.IssueChallenge()
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewAuthorizationRequest(
		challenge, binding, clonePrivateKey(bootstrapPrivate), oneBootPublic, authority.PublicKey(), 0,
	)
	if err != nil {
		t.Fatal(err)
	}
	authorizationResult := make(chan error, 1)
	go func() {
		_, err := authority.Authorize(request)
		authorizationResult <- err
	}()
	<-policyEntered
	clock.advance(time.Second + time.Nanosecond)
	if err := authority.RegisterBootstrapKey(
		binding.LogicalIdentity, testPrivateKey(9).Public().(ed25519.PublicKey),
	); !errors.Is(err, ErrCapacity) {
		t.Fatalf("pending authorization lost its capacity reservation: %v", err)
	}
	close(releasePolicy)
	if err := <-authorizationResult; !errors.Is(err, ErrExpired) {
		t.Fatalf("authorization completed after challenge expiry: %v", err)
	}
	if err := authority.RegisterBootstrapKey(
		binding.LogicalIdentity, testPrivateKey(9).Public().(ed25519.PublicKey),
	); err != nil {
		t.Fatalf("expired completed attempt did not release capacity: %v", err)
	}
}

func TestAuthorityRejectsClockRegressionAndEntropyFailure(t *testing.T) {
	fixture := newAuthorityFixture(t, 5*time.Second, 5*time.Second, 8)
	if err := fixture.authority.RegisterBootstrapKey(fixture.binding.LogicalIdentity, fixture.bootstrapPublic); err != nil {
		t.Fatal(err)
	}
	challenge, err := fixture.authority.IssueChallenge()
	if err != nil {
		t.Fatal(err)
	}
	request := fixture.request(t, challenge)
	fixture.clock.advance(-time.Second)
	if _, err := fixture.authority.Authorize(request); !errors.Is(err, ErrInvalid) {
		t.Fatalf("clock regression error = %v", err)
	}

	badEntropy, err := NewNonProductionAuthority(NonProductionAuthorityConfig{
		AuthorityKeyID: "test-authority", SigningKey: testPrivateKey(1),
		ChallengeMaxAge: time.Second, AuthorizationMaxAge: time.Second,
		BindingPolicy: BindingPolicyFunc(func(BootBinding) error { return nil }),
		Entropy:       bytes.NewReader(make([]byte, 12)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := badEntropy.IssueChallenge(); err == nil {
		t.Fatal("short entropy source was accepted")
	}
}

func TestConstructorRejectsUnsafeConfiguration(t *testing.T) {
	valid := NonProductionAuthorityConfig{
		AuthorityKeyID: "test-authority", SigningKey: testPrivateKey(1),
		ChallengeMaxAge: time.Second, AuthorizationMaxAge: time.Second,
		BindingPolicy: BindingPolicyFunc(func(BootBinding) error { return nil }),
	}
	tests := []struct {
		name   string
		mutate func(*NonProductionAuthorityConfig)
	}{
		{"invalid key id", func(value *NonProductionAuthorityConfig) { value.AuthorityKeyID = "Test Authority" }},
		{"short private key", func(value *NonProductionAuthorityConfig) { value.SigningKey = []byte("short") }},
		{"fractional challenge age", func(value *NonProductionAuthorityConfig) { value.ChallengeMaxAge = 1500 * time.Millisecond }},
		{"zero authorization age", func(value *NonProductionAuthorityConfig) { value.AuthorizationMaxAge = 0 }},
		{"long challenge age", func(value *NonProductionAuthorityConfig) { value.ChallengeMaxAge = 301 * time.Second }},
		{"excess capacity", func(value *NonProductionAuthorityConfig) { value.MaxOutstandingChallenges = 65537 }},
		{"missing binding policy", func(value *NonProductionAuthorityConfig) { value.BindingPolicy = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			test.mutate(&config)
			if _, err := NewNonProductionAuthority(config); !errors.Is(err, ErrInvalid) {
				t.Fatalf("NewNonProductionAuthority() error = %v", err)
			}
		})
	}

	inconsistent := append(ed25519.PrivateKey(nil), testPrivateKey(1)...)
	inconsistent[len(inconsistent)-1] ^= 1
	valid.SigningKey = inconsistent
	if _, err := NewNonProductionAuthority(valid); !errors.Is(err, ErrInvalid) {
		t.Fatalf("inconsistent private key error = %v", err)
	}
}

type authorityFixture struct {
	authority        *NonProductionAuthority
	clock            *mutableClock
	binding          BootBinding
	bootstrapPrivate ed25519.PrivateKey
	bootstrapPublic  ed25519.PublicKey
	oneBootPublic    ed25519.PublicKey
}

func newAuthorityFixture(t *testing.T, challengeAge, authorizationAge time.Duration, capacity int) authorityFixture {
	t.Helper()
	clock := &mutableClock{value: time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)}
	binding := BootBinding{
		LogicalIdentity: "pi-spike-1", Audience: "kaiba-rpi5-initramfs", StorageGeneration: 0, VerifierVersion: 1,
		PolicyDigest: testDigest('a'), ManifestDigest: testDigest('b'), SecurityEpoch: 7,
	}
	entropy := make([]byte, 64*128)
	for block := 0; block < 128; block++ {
		for offset := 0; offset < 64; offset++ {
			entropy[block*64+offset] = byte(offset + 17)
		}
		entropy[block*64] = byte(block)
		entropy[block*64+32] = byte(block + 128)
	}
	authority, err := NewNonProductionAuthority(NonProductionAuthorityConfig{
		AuthorityKeyID: "test-authority-1", SigningKey: testPrivateKey(1),
		ChallengeMaxAge: challengeAge, AuthorizationMaxAge: authorizationAge,
		MaxOutstandingChallenges: capacity, Clock: clock.now,
		BindingPolicy: BindingPolicyFunc(func(actual BootBinding) error {
			if actual != binding {
				return errors.New("binding is not selected by test policy")
			}
			return nil
		}),
		Entropy: bytes.NewReader(entropy),
	})
	if err != nil {
		t.Fatal(err)
	}
	bootstrapPrivate := testPrivateKey(2)
	return authorityFixture{
		authority: authority, clock: clock,
		binding:          binding,
		bootstrapPrivate: bootstrapPrivate,
		bootstrapPublic:  bootstrapPrivate.Public().(ed25519.PublicKey),
		oneBootPublic:    testPrivateKey(3).Public().(ed25519.PublicKey),
	}
}

func (fixture authorityFixture) request(t *testing.T, challenge Challenge) AuthorizationRequest {
	t.Helper()
	request, err := NewAuthorizationRequest(
		challenge, fixture.binding, clonePrivateKey(fixture.bootstrapPrivate), fixture.oneBootPublic,
		fixture.authority.PublicKey(), 0,
	)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

type mutableClock struct {
	mu    sync.Mutex
	value time.Time
}

func (clock *mutableClock) now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.value
}

func (clock *mutableClock) advance(duration time.Duration) {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.value = clock.value.Add(duration)
}

func testPrivateKey(fill byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{fill}, ed25519.SeedSize))
}

func clonePrivateKey(privateKey ed25519.PrivateKey) ed25519.PrivateKey {
	return append(ed25519.PrivateKey(nil), privateKey...)
}

func testDigest(fill byte) string {
	return "sha256:" + strings.Repeat(string([]byte{fill}), 64)
}

func flipLastHex(value string) string {
	if value[len(value)-1] == '0' {
		return value[:len(value)-1] + "1"
	}
	return value[:len(value)-1] + "0"
}
