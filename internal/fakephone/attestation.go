package fakephone

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"sync"
	"time"
)

// DebugSigningCert is the SHA-256 of frict-android's public debug signing
// certificate (frict-android README, Debug keystore).
const DebugSigningCert = "216dcf50a300a0406a2ca01484d299701c70bffa3c2c666c6c60443cf1e859bb"

// DebugPackage is frict-android's debug application ID.
const DebugPackage = "app.frict.android.dev"

// Security levels and user authenticator types, as KeyMint numbers them.
const (
	Software  = 0
	TEE       = 1
	StrongBox = 2

	AuthFingerprintOrScreenLock = 3
	AuthFingerprintOnly         = 2
)

// CA stands in for a phone's attestation certificate issuers: a root and
// the intermediate that signs key attestations.
type CA struct {
	Root, Intermediate *x509.Certificate
	interKey           *ecdsa.PrivateKey
}

// NewCA makes a root and intermediate, both valid from 2020 until their
// notAfter.
func NewCA(rootNotAfter, interNotAfter time.Time) (*CA, error) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	from := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	rootTmpl := caTemplate("fakephone attestation root", from, rootNotAfter)
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return nil, err
	}
	interDER, err := x509.CreateCertificate(rand.Reader, caTemplate("fakephone attestation intermediate", from, interNotAfter), root, &interKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}
	inter, err := x509.ParseCertificate(interDER)
	if err != nil {
		return nil, err
	}
	return &CA{Root: root, Intermediate: inter, interKey: interKey}, nil
}

// RootSPKIHash is the hex SHA-256 of the root's public key, as a
// verifier pins it.
func (ca *CA) RootSPKIHash() string {
	h := sha256.Sum256(ca.Root.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(h[:])
}

func caTemplate(cn string, from, until time.Time) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             from,
		NotAfter:              until,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
}

func randomSerial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	return n.Add(n, big.NewInt(1))
}

// SharedCA is one CA for every phone in a process.
var SharedCA = sync.OnceValues(func() (*CA, error) {
	return NewCA(time.Date(2045, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC))
})

// Attestation says what a phone's key attestations claim. The zero
// value is not useful: start from DefaultAttestation.
type Attestation struct {
	CA            *CA
	SecurityLevel int
	Package       string
	SigningCert   string // hex SHA-256
	// ApprovalAuth is the approval_key's userAuthType; 0 makes it a key
	// that needs no user, like the device_key.
	ApprovalAuth int
	// Challenge, when set, replaces the activation code.
	Challenge string
}

// DefaultAttestation is a debug build's keys in the TEE under SharedCA,
// unlocked by fingerprint or screen lock.
func DefaultAttestation() (Attestation, error) {
	ca, err := SharedCA()
	return Attestation{
		CA:            ca,
		SecurityLevel: TEE,
		Package:       DebugPackage,
		SigningCert:   DebugSigningCert,
		ApprovalAuth:  AuthFingerprintOrScreenLock,
	}, err
}

// Chain returns pub's attestation chain, leaf first, as Android Keystore
// builds it for a P-256 signing key generated with challenge. userAuth
// is the key's userAuthType, 0 for none.
func (a Attestation) Chain(pub *ecdsa.PublicKey, challenge []byte, userAuth int) ([][]byte, error) {
	ext, err := a.keyDescription(challenge, userAuth)
	if err != nil {
		return nil, err
	}
	leaf := &x509.Certificate{
		SerialNumber:    big.NewInt(1),
		Subject:         pkix.Name{CommonName: "Android Keystore Key"},
		NotBefore:       time.Unix(0, 0),
		NotAfter:        time.Date(2048, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}, Value: ext}},
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, a.CA.Intermediate, pub, a.CA.interKey)
	if err != nil {
		return nil, err
	}
	return [][]byte{der, a.CA.Intermediate.Raw, a.CA.Root.Raw}, nil
}

// keyDescription is the attestation extension's KeyDescription, version
// 300 (KeyMint 3), with the key's authorizations in the list its
// security level enforces.
func (a Attestation) keyDescription(challenge []byte, userAuth int) ([]byte, error) {
	digest, err := hex.DecodeString(a.SigningCert)
	if err != nil {
		return nil, err
	}
	appID, err := asn1.Marshal(struct {
		PackageInfos     []packageInfo `asn1:"set"`
		SignatureDigests [][]byte      `asn1:"set"`
	}{[]packageInfo{{[]byte(a.Package), 1000}}, [][]byte{digest}})
	if err != nil {
		return nil, err
	}
	key := []asn1.RawValue{
		tagged(1, set(integer(2))), // purpose SIGN
		tagged(2, integer(3)),      // algorithm EC
		tagged(3, integer(256)),    // keySize
		tagged(5, set(integer(4))), // digest SHA-256
		tagged(10, integer(1)),     // ecCurve P-256
	}
	if userAuth == 0 {
		key = append(key, tagged(503, asn1.NullBytes)) // noAuthRequired
	} else {
		key = append(key, tagged(504, integer(int64(userAuth)))) // userAuthType
	}
	key = append(key, tagged(702, integer(0))) // origin GENERATED
	software := []asn1.RawValue{
		tagged(701, integer(time.Now().UnixMilli())), // creationDateTime
		tagged(709, octets(appID)),                   // attestationApplicationId
	}
	hardware := []asn1.RawValue{}
	if a.SecurityLevel == Software {
		software = append(key, software...)
	} else {
		hardware = key
	}
	return asn1.Marshal(struct {
		AttestationVersion       int
		AttestationSecurityLevel asn1.Enumerated
		KeyMintVersion           int
		KeyMintSecurityLevel     asn1.Enumerated
		AttestationChallenge     []byte
		UniqueID                 []byte
		SoftwareEnforced         []asn1.RawValue
		HardwareEnforced         []asn1.RawValue
	}{300, asn1.Enumerated(a.SecurityLevel), 300, asn1.Enumerated(a.SecurityLevel), challenge, []byte{}, software, hardware})
}

type packageInfo struct {
	PackageName []byte
	Version     int64
}

func tagged(tag int, inner []byte) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, IsCompound: true, Bytes: inner}
}

func integer(v int64) []byte {
	b, _ := asn1.Marshal(v)
	return b
}

func octets(v []byte) []byte {
	b, _ := asn1.Marshal(v)
	return b
}

func set(members ...[]byte) []byte {
	var body []byte
	for _, m := range members {
		body = append(body, m...)
	}
	b, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: body})
	return b
}
