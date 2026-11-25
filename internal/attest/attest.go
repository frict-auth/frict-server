// Package attest verifies Android Keystore key attestation chains
// (source.android.com/docs/security/features/keystore/attestation): that a
// key was made in a phone's secure hardware, for this enrollment, by the
// Frict app, with the properties the protocol relies on.
package attest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"
)

// Mode is how much of an attestation must hold.
type Mode string

const (
	// Strict requires a chain to a pinned root, in TEE or StrongBox,
	// every certificate below the root valid now, and none revoked.
	Strict Mode = "strict"
	// Emulator accepts any root and software keys, as an emulator makes,
	// and skips validity periods and revocation. Everything else holds.
	Emulator Mode = "emulator"
)

// ParseMode reads FRICT_ATTESTATION. Anything but "emulator" is Strict;
// known is false for a value that is neither empty nor a mode's name.
func ParseMode(s string) (m Mode, known bool) {
	switch s {
	case "", string(Strict):
		return Strict, true
	case string(Emulator):
		return Emulator, true
	}
	return Strict, false
}

// GoogleRoots are the SHA-256 digests of the SubjectPublicKeyInfo of
// Google's hardware attestation roots, from
// https://developer.android.com/privacy-and-security/security-key-attestation#root_certificate
// and https://android.googleapis.com/attestation/root.
var GoogleRoots = []string{
	// RSA-4096, subject serialNumber=f92009e853b6b045. Its current
	// certificate (2022–2042) and the three previously issued ones share
	// this key.
	"feb2ea7551ee316ed4bb443c8293b884dbfdea40b603ee3e4f4a897e4580fbae",
	// ECDSA P-384, CN=Key Attestation CA1 (2025–2035), signing chains
	// since 2026-02-01.
	"3ee44512a1af2beb39c889490c60ea3f82e43f5d5a5532f5ab9419f676cd07ec",
}

// Digests decodes hex SHA-256 digests.
func Digests(hexes ...string) ([][32]byte, error) {
	var out [][32]byte
	for _, h := range hexes {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != sha256.Size {
			return nil, fmt.Errorf("%q is not a hex SHA-256 digest", h)
		}
		out = append(out, [32]byte(b))
	}
	return out, nil
}

// Key is one key's submission. UserAuth says the key must require the
// user on every use; otherwise it must not require the user at all.
type Key struct {
	Name     string
	SPKI     []byte
	Chain    [][]byte // DER, leaf first
	UserAuth bool
}

// Rejection is an attestation that doesn't hold. Reason is a stable code
// for the security log.
type Rejection struct {
	Key    string
	Reason string
	Detail string
}

func (r *Rejection) Error() string {
	return fmt.Sprintf("%s attestation: %s: %s", r.Key, r.Reason, r.Detail)
}

// Rejection reasons.
const (
	ReasonMalformed         = "malformed"
	ReasonChainSignature    = "chain_signature"
	ReasonUntrustedRoot     = "untrusted_root"
	ReasonOutsideValidity   = "outside_validity"
	ReasonRevoked           = "revoked"
	ReasonKeyMismatch       = "key_mismatch"
	ReasonChallengeMismatch = "challenge_mismatch"
	ReasonSecurityLevel     = "security_level"
	ReasonKeyProperties     = "key_properties"
	ReasonUserAuth          = "user_auth"
	ReasonPackage           = "package"
	ReasonSigningCert       = "signing_cert"
)

// ErrStatusUnavailable means the revocation list couldn't be had, so a
// chain that passed every other check can't be accepted yet.
var ErrStatusUnavailable = errors.New("attestation status list unavailable")

// StatusSource gives the revocation list: lowercase hex serial number,
// without leading zeros, to status.
type StatusSource interface {
	Load(ctx context.Context) (map[string]string, error)
}

// Verifier checks attestations. In Strict mode a chain's root must have
// a public key whose SHA-256 is in Roots.
type Verifier struct {
	Mode         Mode
	Roots        [][32]byte
	Packages     []string
	SigningCerts [][32]byte
	Status       StatusSource
}

// Verify checks every key's chain at now against challenge. A failed
// check is a *Rejection. The revocation list is loaded only once every
// chain has passed every other check; failing to load it is
// ErrStatusUnavailable.
func (v *Verifier) Verify(ctx context.Context, now time.Time, challenge []byte, keys ...Key) error {
	chains := make([][]*x509.Certificate, len(keys))
	for i, k := range keys {
		certs, err := v.offline(now, challenge, k)
		if err != nil {
			return err
		}
		chains[i] = certs
	}
	if v.Mode == Emulator {
		return nil
	}
	revoked, err := v.Status.Load(ctx)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStatusUnavailable, err)
	}
	for i, certs := range chains {
		for _, c := range certs {
			if st, ok := revoked[c.SerialNumber.Text(16)]; ok {
				return &Rejection{keys[i].Name, ReasonRevoked, fmt.Sprintf("serial %x is %s", c.SerialNumber, st)}
			}
		}
	}
	return nil
}

func (v *Verifier) offline(now time.Time, challenge []byte, k Key) ([]*x509.Certificate, error) {
	reject := func(reason, format string, a ...any) error {
		return &Rejection{k.Name, reason, fmt.Sprintf(format, a...)}
	}
	if len(k.Chain) < 2 {
		return nil, reject(ReasonMalformed, "chain has %d certificates", len(k.Chain))
	}
	certs := make([]*x509.Certificate, len(k.Chain))
	for i, der := range k.Chain {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, reject(ReasonMalformed, "certificate %d: %v", i, err)
		}
		certs[i] = c
	}
	for i := range len(certs) - 1 {
		if err := certs[i].CheckSignatureFrom(certs[i+1]); err != nil {
			return nil, reject(ReasonChainSignature, "certificate %d: %v", i, err)
		}
	}
	root := certs[len(certs)-1]
	if v.Mode != Emulator {
		if !slices.Contains(v.Roots, sha256.Sum256(root.RawSubjectPublicKeyInfo)) {
			return nil, reject(ReasonUntrustedRoot, "root %q", root.Subject)
		}
		for i, c := range certs[:len(certs)-1] {
			if now.Before(c.NotBefore) || now.After(c.NotAfter) {
				return nil, reject(ReasonOutsideValidity, "certificate %d is valid %s to %s", i, c.NotBefore, c.NotAfter)
			}
		}
	}
	leaf := certs[0]
	if !bytes.Equal(leaf.RawSubjectPublicKeyInfo, k.SPKI) {
		return nil, reject(ReasonKeyMismatch, "the leaf certifies another key")
	}
	kd, err := parseKeyDescription(leaf)
	if err != nil {
		return nil, reject(ReasonMalformed, "key description: %v", err)
	}
	if !bytes.Equal(kd.challenge, challenge) {
		return nil, reject(ReasonChallengeMismatch, "the key was made for another enrollment")
	}
	if v.Mode != Emulator && (!hardware(kd.attestationLevel) || !hardware(kd.keyMintLevel)) {
		return nil, reject(ReasonSecurityLevel, "attestation level %d, KeyMint level %d", kd.attestationLevel, kd.keyMintLevel)
	}
	auth := kd.hardware
	if kd.keyMintLevel == levelSoftware {
		auth = kd.software
	}
	if err := checkProperties(auth); err != nil {
		return nil, reject(ReasonKeyProperties, "%v", err)
	}
	if err := checkUserAuth(auth, k.UserAuth); err != nil {
		return nil, reject(ReasonUserAuth, "%v", err)
	}
	app, ok := kd.software[tagAttestationApplicationID]
	if !ok {
		app, ok = kd.hardware[tagAttestationApplicationID]
	}
	if !ok {
		return nil, reject(ReasonPackage, "no attestationApplicationId")
	}
	pkgs, digests, err := parseApplicationID(app)
	if err != nil {
		return nil, reject(ReasonMalformed, "attestationApplicationId: %v", err)
	}
	if len(pkgs) == 0 {
		return nil, reject(ReasonPackage, "no package")
	}
	for _, p := range pkgs {
		if !slices.Contains(v.Packages, p) {
			return nil, reject(ReasonPackage, "package %q is not allowed", p)
		}
	}
	if !slices.ContainsFunc(digests, func(d [32]byte) bool { return slices.Contains(v.SigningCerts, d) }) {
		return nil, reject(ReasonSigningCert, "no allowed signing certificate among %d", len(digests))
	}
	return certs, nil
}

func hardware(level int) bool { return level == levelTEE || level == levelStrongBox }

// KeyMint values: hardware/interfaces/security/keymint/aidl.
const (
	levelSoftware  = 0
	levelTEE       = 1
	levelStrongBox = 2

	purposeSign   = 2
	purposeVerify = 3
	algorithmEC   = 3
	curveP256     = 1

	// HardwareAuthenticatorType bits.
	authPassword    = 1
	authFingerprint = 2
)

func checkProperties(auth authList) error {
	purposes, err := auth.intSet(tagPurpose)
	if err != nil || !slices.Contains(purposes, purposeSign) ||
		slices.ContainsFunc(purposes, func(p int64) bool { return p != purposeSign && p != purposeVerify }) {
		return fmt.Errorf("purpose %v, want SIGN, and VERIFY at most besides", purposes)
	}
	for _, want := range []struct {
		tag   int
		name  string
		value int64
	}{
		{tagAlgorithm, "algorithm", algorithmEC},
		{tagKeySize, "keySize", 256},
		{tagECCurve, "ecCurve", curveP256},
	} {
		if got, err := auth.int(want.tag); err != nil || got != want.value {
			return fmt.Errorf("%s %d (%v), want %d", want.name, got, err, want.value)
		}
	}
	return nil
}

// checkUserAuth requires, for a user-auth key, a fingerprint, alone or
// with the screen lock, on every use (no authTimeout); for any other key,
// noAuthRequired.
func checkUserAuth(auth authList, userAuth bool) error {
	_, noAuth := auth[tagNoAuthRequired]
	types, typesErr := auth.int(tagUserAuthType)
	_, timeout := auth[tagAuthTimeout]
	if !userAuth {
		if !noAuth || typesErr == nil {
			return errors.New("the key requires user authentication")
		}
		return nil
	}
	switch {
	case noAuth:
		return errors.New("the key has noAuthRequired")
	case typesErr != nil || (types != authFingerprint && types != authFingerprint|authPassword):
		return fmt.Errorf("userAuthType %d (%v), want fingerprint, alone or with the screen lock", types, typesErr)
	case timeout:
		return errors.New("the key has an authTimeout: user authentication isn't required on every use")
	}
	return nil
}
