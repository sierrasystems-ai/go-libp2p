package multiaddr

import (
	"bytes"
	"testing"

	"github.com/multiformats/go-multibase"
)

func TestECHProtocolRoundtrip(t *testing.T) {
	// A minimal, well-formed ECHConfigList: a uint16 length prefix followed by
	// that many bytes.
	body := []byte{0xde, 0xad, 0xbe, 0xef}
	configList := append([]byte{0x00, byte(len(body))}, body...)

	val, err := multibase.Encode(multibase.Base64url, configList)
	if err != nil {
		t.Fatal(err)
	}

	c, err := NewComponent("ech", val)
	if err != nil {
		t.Fatalf("NewComponent(ech): %v", err)
	}
	if c.Protocol().Code != P_ECH {
		t.Fatalf("unexpected protocol code %d", c.Protocol().Code)
	}
	if !bytes.Equal(c.RawValue(), configList) {
		t.Fatalf("raw value mismatch: %x != %x", c.RawValue(), configList)
	}

	m := StringCast("/ip4/1.2.3.4/udp/1234/quic-v1").Encapsulate(c)
	reparsed, err := NewMultiaddr(m.String())
	if err != nil {
		t.Fatalf("reparse: %v", err)
	}
	got, err := reparsed.ValueForProtocol(P_ECH)
	if err != nil {
		t.Fatalf("ValueForProtocol(ech): %v", err)
	}
	if got != val {
		t.Fatalf("value mismatch after reparse: %q != %q", got, val)
	}
}

func TestECHProtocolRejectsMalformed(t *testing.T) {
	// length header claims 4 bytes but only 2 are present
	bad := []byte{0x00, 0x04, 0x01, 0x02}
	val, err := multibase.Encode(multibase.Base64url, bad)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewComponent("ech", val); err == nil {
		t.Fatal("expected error for malformed ech config list")
	}
}
