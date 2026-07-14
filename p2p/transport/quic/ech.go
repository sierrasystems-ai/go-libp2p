package libp2pquic

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"

	ic "github.com/libp2p/go-libp2p/core/crypto"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/multiformats/go-multibase"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/hkdf"
)

// TLS Encrypted Client Hello (ECH) constants.
//
// See the TLS ECH draft (draft-ietf-tls-esni). Go's crypto/tls implements
// draft-ietf-tls-esni-18, whose ECHConfig version is 0xfe0d.
const (
	echConfigVersion = 0xfe0d

	// HPKE identifiers. Go's crypto/tls only supports the
	// DHKEM(X25519, HKDF-SHA256) KEM and the HKDF-SHA256 KDF on the server side.
	echKEMX25519HKDFSHA256  = 0x0020
	echKDFHKDFSHA256        = 0x0001
	echAEADAES128GCM        = 0x0001
	echAEADAES256GCM        = 0x0002
	echAEADChaCha20Poly1305 = 0x0003
)

// DefaultECHPublicName is the public (cover) server name used when generating
// an ECH config without an explicit public name. It is sent in the cleartext
// outer ClientHello, so it should not leak the real destination. libp2p does
// not use SNI, so the exact value is not important as long as it is a
// syntactically valid DNS name.
const DefaultECHPublicName = "libp2p.local"

const deterministicECHInfo = "libp2p quic ech key"

// GenerateECHConfig generates a fresh, random ECH keypair for use by a QUIC
// server.
//
// The returned [tls.EncryptedClientHelloKey] contains a marshalled ECHConfig
// (Config) and its associated HPKE private key (PrivateKey). The Config can be
// advertised to clients (e.g. via a multiaddr /ech component or via DNS), while
// the key must be kept private and passed to the server via [WithServerECH].
//
// publicName is the cover server name embedded in the config. If empty,
// [DefaultECHPublicName] is used. Note that [WithServerECH] without explicit
// keys derives a deterministic key from the host's private key instead, so
// that the advertised config is stable across restarts.
func GenerateECHConfig(publicName string) (tls.EncryptedClientHelloKey, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return tls.EncryptedClientHelloKey{}, err
	}
	var id [1]byte
	if _, err := rand.Read(id[:]); err != nil {
		return tls.EncryptedClientHelloKey{}, err
	}
	return newECHKey(id[0], priv, publicName)
}

// deriveECHConfig deterministically derives an ECH keypair from the given
// libp2p private key, so that a server advertises the same ECH config across
// restarts and previously shared multiaddrs remain dialable. This mirrors how
// the WebTransport transport derives deterministic certificates.
func deriveECHConfig(key ic.PrivKey, publicName string) (tls.EncryptedClientHelloKey, error) {
	keyBytes, err := key.Raw()
	if err != nil {
		return tls.EncryptedClientHelloKey{}, err
	}
	r := hkdf.New(sha256.New, keyBytes, nil, []byte(deterministicECHInfo))
	seed := make([]byte, 32+1) // X25519 private key material plus a config id byte
	if _, err := io.ReadFull(r, seed); err != nil {
		return tls.EncryptedClientHelloKey{}, err
	}
	priv, err := ecdh.X25519().NewPrivateKey(seed[:32])
	if err != nil {
		return tls.EncryptedClientHelloKey{}, err
	}
	return newECHKey(seed[32], priv, publicName)
}

func newECHKey(id uint8, priv *ecdh.PrivateKey, publicName string) (tls.EncryptedClientHelloKey, error) {
	if publicName == "" {
		publicName = DefaultECHPublicName
	}
	config, err := marshalECHConfig(id, priv.PublicKey().Bytes(), publicName)
	if err != nil {
		return tls.EncryptedClientHelloKey{}, err
	}
	return tls.EncryptedClientHelloKey{
		Config:      config,
		PrivateKey:  priv.Bytes(),
		SendAsRetry: true,
	}, nil
}

// marshalECHConfig marshals a single ECHConfig entry (without the outer
// ECHConfigList framing).
func marshalECHConfig(id uint8, pubKey []byte, publicName string) ([]byte, error) {
	// public_name is a uint8-length-prefixed field (public_name<1..255>).
	if len(publicName) == 0 || len(publicName) > 255 {
		return nil, fmt.Errorf("ech public name length %d out of range [1, 255]", len(publicName))
	}
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
	return b.Bytes()
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

// EncapsulateECHConfig returns addr with an /ech component carrying the given
// ECHConfigList appended. Use it to dial a specific server whose ECH config was
// obtained out of band (e.g. from a DNS HTTPS/SVCB record): the QUIC transport
// uses the config embedded in the dialed multiaddr to encrypt the ClientHello
// of that dial only.
func EncapsulateECHConfig(addr ma.Multiaddr, configList []byte) (ma.Multiaddr, error) {
	if err := validateECHConfigList(configList); err != nil {
		return nil, fmt.Errorf("invalid ech config list: %w", err)
	}
	return encapsulateECH(addr, configList)
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

// popECHConfigList removes the trailing /ech component (if any) from addr,
// returning the remaining multiaddr and the raw ECHConfigList. dialMatcher only
// admits addresses with /ech as the final component, so only the last component
// is inspected. If addr has no /ech component, it is returned unchanged with a
// nil config list.
func popECHConfigList(addr ma.Multiaddr) (ma.Multiaddr, []byte) {
	rest, c := ma.SplitLast(addr)
	if c == nil || c.Protocol().Code != echProtocolCode {
		return addr, nil
	}
	return rest, c.RawValue()
}

// validateECHConfigList performs a lightweight sanity check on an ECHConfigList,
// verifying the outer length framing. The TLS stack validates the individual
// configs.
func validateECHConfigList(b []byte) error {
	// An ECHConfigList is a uint16-length-prefixed, non-empty list of ECHConfig
	// entries, each at least 4 bytes (a uint16 version and a uint16 length).
	if len(b) < 2 {
		return fmt.Errorf("ech config list too short")
	}
	l := int(b[0])<<8 | int(b[1])
	if l != len(b)-2 {
		return fmt.Errorf("ech config list length mismatch: header says %d, have %d", l, len(b)-2)
	}
	if l < 4 {
		return fmt.Errorf("ech config list too short: %d bytes", l)
	}
	return nil
}
