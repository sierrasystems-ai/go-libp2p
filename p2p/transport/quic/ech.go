package libp2pquic

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"

	ma "github.com/multiformats/go-multiaddr"
	"github.com/multiformats/go-multibase"
	"golang.org/x/crypto/cryptobyte"
)

// TLS Encrypted Client Hello (ECH) constants.
//
// See the TLS ECH draft (draft-ietf-tls-esni). Go's crypto/tls implements
// draft-ietf-tls-esni-18, whose ECHConfig version is 0xfe0d.
const (
	echConfigVersion = 0xfe0d

	// HPKE identifiers. Go's crypto/tls only supports the
	// DHKEM(X25519, HKDF-SHA256) KEM and the HKDF-SHA256 KDF on the server side.
	echKEMX25519HKDFSHA256 = 0x0020
	echKDFHKDFSHA256       = 0x0001
	echAEADAES128GCM       = 0x0001
	echAEADAES256GCM       = 0x0002
	echAEADChaCha20Poly1305 = 0x0003
)

// DefaultECHPublicName is the public (cover) server name used when generating
// an ECH config without an explicit public name. It is sent in the cleartext
// outer ClientHello, so it should not leak the real destination. libp2p does
// not use SNI, so the exact value is not important as long as it is a
// syntactically valid DNS name.
const DefaultECHPublicName = "libp2p.local"

// GenerateECHConfig generates a fresh ECH keypair for use by a QUIC server.
//
// The returned [tls.EncryptedClientHelloKey] contains a marshalled ECHConfig
// (Config) and its associated HPKE private key (PrivateKey). The Config can be
// advertised to clients (e.g. via a multiaddr /ech component or via DNS), while
// the key must be kept private and passed to the server via [WithServerECH].
//
// publicName is the cover server name embedded in the config. If empty,
// [DefaultECHPublicName] is used.
func GenerateECHConfig(publicName string) (tls.EncryptedClientHelloKey, error) {
	if publicName == "" {
		publicName = DefaultECHPublicName
	}
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return tls.EncryptedClientHelloKey{}, err
	}
	var id [1]byte
	if _, err := rand.Read(id[:]); err != nil {
		return tls.EncryptedClientHelloKey{}, err
	}
	config := marshalECHConfig(id[0], priv.PublicKey().Bytes(), publicName)
	return tls.EncryptedClientHelloKey{
		Config:      config,
		PrivateKey:  priv.Bytes(),
		SendAsRetry: true,
	}, nil
}

// marshalECHConfig marshals a single ECHConfig entry (without the outer
// ECHConfigList framing).
func marshalECHConfig(id uint8, pubKey []byte, publicName string) []byte {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(echConfigVersion)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(id)
		b.AddUint16(echKEMX25519HKDFSHA256)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(pubKey) })
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, aead := range []uint16{echAEADAES128GCM, echAEADAES256GCM, echAEADChaCha20Poly1305} {
				b.AddUint16(echKDFHKDFSHA256)
				b.AddUint16(aead)
			}
		})
		// maximum_name_length: an upper bound on the length of a backend server
		// name. libp2p does not use inner SNI, so a small fixed value used for
		// padding is sufficient.
		b.AddUint8(64)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte(publicName)) })
		b.AddUint16(0) // no extensions
	})
	return b.BytesOrPanic()
}

// MarshalECHConfigList marshals the given ECH keys into an ECHConfigList, the
// wire format expected by clients (tls.Config.EncryptedClientHelloConfigList
// and the /ech multiaddr component).
func MarshalECHConfigList(keys ...tls.EncryptedClientHelloKey) []byte {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, k := range keys {
			b.AddBytes(k.Config)
		}
	})
	return b.BytesOrPanic()
}

// echMultiaddrComponent returns the /ech multiaddr component encoding the given
// ECHConfigList.
func echMultiaddrComponent(configList []byte) (*ma.Component, error) {
	val, err := multibase.Encode(multibase.Base64url, configList)
	if err != nil {
		return nil, err
	}
	return ma.NewComponent("ech", val)
}

// encapsulateECH appends the /ech component encoding configList to addr.
func encapsulateECH(addr ma.Multiaddr, configList []byte) (ma.Multiaddr, error) {
	comp, err := echMultiaddrComponent(configList)
	if err != nil {
		return nil, err
	}
	return addr.Encapsulate(comp), nil
}

// popECHConfigList removes the /ech component (if any) from addr, returning the
// remaining multiaddr and the decoded ECHConfigList. If addr has no /ech
// component, it is returned unchanged with a nil config list.
func popECHConfigList(addr ma.Multiaddr) (ma.Multiaddr, []byte, error) {
	var (
		configList []byte
		found      bool
		rest       ma.Multiaddr
	)
	for _, c := range addr {
		if c.Protocol().Code == ma.P_ECH {
			configList = append([]byte(nil), c.RawValue()...)
			found = true
			continue
		}
		comp := c
		rest = rest.Encapsulate(&comp)
	}
	if !found {
		return addr, nil, nil
	}
	if len(configList) == 0 {
		return rest, nil, errors.New("empty ech config in multiaddr")
	}
	return rest, configList, nil
}

// validateECHConfigList performs a lightweight sanity check on an ECHConfigList,
// verifying the outer length framing.
func validateECHConfigList(b []byte) error {
	if len(b) < 2 {
		return fmt.Errorf("ech config list too short")
	}
	l := int(b[0])<<8 | int(b[1])
	if l != len(b)-2 {
		return fmt.Errorf("ech config list length mismatch: header says %d, have %d", l, len(b)-2)
	}
	return nil
}
