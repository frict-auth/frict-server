package attest

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
)

// OID is the key attestation extension's.
var OID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

// AuthorizationList tags.
const (
	tagPurpose                  = 1
	tagAlgorithm                = 2
	tagKeySize                  = 3
	tagECCurve                  = 10
	tagNoAuthRequired           = 503
	tagUserAuthType             = 504
	tagAuthTimeout              = 505
	tagAttestationApplicationID = 709
)

type keyDescription struct {
	attestationLevel int
	keyMintLevel     int
	challenge        []byte
	software         authList
	hardware         authList
}

// authList maps a tag to the DER of its explicitly tagged value.
type authList map[int][]byte

func parseKeyDescription(leaf *x509.Certificate) (keyDescription, error) {
	var ext []byte
	for _, e := range leaf.Extensions {
		if e.Id.Equal(OID) {
			if ext != nil {
				return keyDescription{}, errors.New("two attestation extensions")
			}
			ext = e.Value
		}
	}
	if ext == nil {
		return keyDescription{}, errors.New("no attestation extension")
	}
	var raw struct {
		AttestationVersion       int64
		AttestationSecurityLevel asn1.Enumerated
		KeyMintVersion           int64
		KeyMintSecurityLevel     asn1.Enumerated
		AttestationChallenge     []byte
		UniqueID                 []byte
		SoftwareEnforced         asn1.RawValue
		HardwareEnforced         asn1.RawValue
	}
	if rest, err := asn1.Unmarshal(ext, &raw); err != nil || len(rest) != 0 {
		return keyDescription{}, fmt.Errorf("KeyDescription: %v (%d trailing bytes)", err, len(rest))
	}
	sw, err := parseAuthList(raw.SoftwareEnforced)
	if err != nil {
		return keyDescription{}, fmt.Errorf("softwareEnforced: %w", err)
	}
	hw, err := parseAuthList(raw.HardwareEnforced)
	if err != nil {
		return keyDescription{}, fmt.Errorf("hardwareEnforced: %w", err)
	}
	return keyDescription{
		attestationLevel: int(raw.AttestationSecurityLevel),
		keyMintLevel:     int(raw.KeyMintSecurityLevel),
		challenge:        raw.AttestationChallenge,
		software:         sw,
		hardware:         hw,
	}, nil
}

func parseAuthList(seq asn1.RawValue) (authList, error) {
	if seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence || !seq.IsCompound {
		return nil, errors.New("not a SEQUENCE")
	}
	l := authList{}
	for in := seq.Bytes; len(in) > 0; {
		var e asn1.RawValue
		var err error
		if in, err = asn1.Unmarshal(in, &e); err != nil {
			return nil, err
		}
		if e.Class != asn1.ClassContextSpecific || !e.IsCompound {
			return nil, fmt.Errorf("tag %d is not explicitly tagged", e.Tag)
		}
		if _, dup := l[e.Tag]; dup {
			return nil, fmt.Errorf("tag %d twice", e.Tag)
		}
		l[e.Tag] = e.Bytes
	}
	return l, nil
}

func (l authList) int(tag int) (int64, error) {
	der, ok := l[tag]
	if !ok {
		return 0, errors.New("absent")
	}
	var v int64
	if rest, err := asn1.Unmarshal(der, &v); err != nil || len(rest) != 0 {
		return 0, fmt.Errorf("tag %d: not one INTEGER", tag)
	}
	return v, nil
}

func (l authList) intSet(tag int) ([]int64, error) {
	der, ok := l[tag]
	if !ok {
		return nil, errors.New("absent")
	}
	var v []int64
	if rest, err := asn1.UnmarshalWithParams(der, &v, "set"); err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("tag %d: not one SET OF INTEGER", tag)
	}
	return v, nil
}

// parseApplicationID reads the OCTET STRING holding an
// AttestationApplicationId: its package names and signing certificate
// digests.
func parseApplicationID(der []byte) ([]string, [][32]byte, error) {
	var inner []byte
	if rest, err := asn1.Unmarshal(der, &inner); err != nil || len(rest) != 0 {
		return nil, nil, errors.New("not one OCTET STRING")
	}
	var id struct {
		PackageInfos []struct {
			PackageName []byte
			Version     int64
		} `asn1:"set"`
		SignatureDigests [][]byte `asn1:"set"`
	}
	if rest, err := asn1.Unmarshal(inner, &id); err != nil || len(rest) != 0 {
		return nil, nil, fmt.Errorf("AttestationApplicationId: %v", err)
	}
	var pkgs []string
	for _, p := range id.PackageInfos {
		pkgs = append(pkgs, string(p.PackageName))
	}
	var digests [][32]byte
	for _, d := range id.SignatureDigests {
		if len(d) == 32 {
			digests = append(digests, [32]byte(d))
		}
	}
	return pkgs, digests, nil
}
