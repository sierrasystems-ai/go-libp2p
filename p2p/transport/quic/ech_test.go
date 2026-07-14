package libp2pquic

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	tpt "github.com/libp2p/go-libp2p/core/transport"

	ma "github.com/multiformats/go-multiaddr"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

// echAccepted reports whether ECH was negotiated on the given capable conn.
func echAccepted(t *testing.T, c tpt.CapableConn) bool {
	t.Helper()
	var qc *quic.Conn
	require.True(t, c.(interface{ As(any) bool }).As(&qc), "expected to extract *quic.Conn")
	return qc.ConnectionState().TLS.ECHAccepted
}

func TestECHConfigMultiaddrRoundtrip(t *testing.T) {
	require.Equal(t, echProtocolCode, ma.ProtocolWithName("ech").Code)

	key, err := GenerateECHConfig("example.com")
	require.NoError(t, err)
	require.NotEmpty(t, key.Config)
	require.NotEmpty(t, key.PrivateKey)

	configList := MarshalECHConfigList(key)
	require.NoError(t, validateECHConfigList(configList))

	base := ma.StringCast("/ip4/1.2.3.4/udp/1234/quic-v1")
	withECH, err := EncapsulateECHConfig(base, configList)
	require.NoError(t, err)
	require.Contains(t, withECH.String(), "/ech/")

	// Round-trip through the string representation to exercise the transcoder.
	reparsed := ma.StringCast(withECH.String())
	rest, gotConfigList := popECHConfigList(reparsed)
	require.Equal(t, base.String(), rest.String())
	require.Equal(t, configList, gotConfigList)

	// A multiaddr without an /ech component is returned unchanged.
	rest, gotConfigList = popECHConfigList(base)
	require.Nil(t, gotConfigList)
	require.Equal(t, base.String(), rest.String())
}

func TestECHConfigValidation(t *testing.T) {
	// An empty (but correctly framed) ECHConfigList is rejected.
	require.Error(t, validateECHConfigList([]byte{0x00, 0x00}))
	_, err := EncapsulateECHConfig(ma.StringCast("/ip4/1.2.3.4/udp/1234/quic-v1"), []byte{0x00, 0x00})
	require.Error(t, err)

	_, err = GenerateECHConfig("")
	require.ErrorContains(t, err, "public name")

	// A public name longer than 255 bytes returns an error instead of panicking.
	_, err = GenerateECHConfig(strings.Repeat("a", 300))
	require.ErrorContains(t, err, "public name")
}

func TestECHCanDial(t *testing.T) {
	_, priv := createPeer(t)
	tr, err := NewTransport(priv, newConnManager(t), nil, nil, nil)
	require.NoError(t, err)
	defer tr.(io.Closer).Close()

	echKey, err := GenerateECHConfig("cover.example")
	require.NoError(t, err)
	withECH, err := EncapsulateECHConfig(ma.StringCast("/ip4/1.2.3.4/udp/1234/quic-v1"), MarshalECHConfigList(echKey))
	require.NoError(t, err)

	require.True(t, tr.CanDial(ma.StringCast("/ip4/1.2.3.4/udp/1234/quic-v1")))
	require.True(t, tr.CanDial(withECH))
}

func TestECHClientRejectsCleartextOuterALPN(t *testing.T) {
	serverID, _ := createPeer(t)
	_, clientPriv := createPeer(t)
	tr, err := NewTransport(clientPriv, newConnManager(t), nil, nil, nil)
	require.NoError(t, err)
	defer tr.(io.Closer).Close()

	echKey, err := GenerateECHConfig("cover.example")
	require.NoError(t, err)
	withECH, err := EncapsulateECHConfig(
		ma.StringCast("/ip4/127.0.0.1/udp/1/quic-v1"),
		MarshalECHConfigList(echKey),
	)
	require.NoError(t, err)

	_, err = tr.Dial(context.Background(), withECH, serverID)
	require.ErrorIs(t, err, ErrECHOuterALPNUnsupported)
}

// TestECHDeterministicKeys verifies that WithServerECH without explicit keys
// derives the same ECH config from the same host key across transport
// instances (i.e. across restarts), and different configs for different hosts.
func TestECHDeterministicKeys(t *testing.T) {
	_, priv := createPeer(t)
	_, otherPriv := createPeer(t)

	key1, err := deriveECHConfig(priv, "cover.example", 42)
	require.NoError(t, err)
	key2, err := deriveECHConfig(priv, "cover.example", 42)
	require.NoError(t, err)
	require.Equal(t, key1, key2, "same host key must derive the same ECH key")

	otherKey, err := deriveECHConfig(otherPriv, "cover.example", 42)
	require.NoError(t, err)
	require.NotEqual(t, key1.Config, otherKey.Config, "different host keys must derive different ECH keys")
	require.NotEqual(t, key1.PrivateKey, otherKey.PrivateKey)
	nextPeriodKey, err := deriveECHConfig(priv, "cover.example", 43)
	require.NoError(t, err)
	require.NotEqual(t, key1.Config, nextPeriodKey.Config, "rotation periods must derive different ECH keys")

	// The transport option wires the derived key through to the advertised
	// config list.
	now := time.Date(2026, time.July, 14, 0, 0, 0, 0, time.UTC)
	tr1, err := NewTransport(priv, newConnManager(t), nil, nil, nil, WithServerECH(), WithECHPublicName("cover.example"), withECHClock(func() time.Time { return now }))
	require.NoError(t, err)
	defer tr1.(io.Closer).Close()
	tr2, err := NewTransport(priv, newConnManager(t), nil, nil, nil, WithServerECH(), WithECHPublicName("cover.example"), withECHClock(func() time.Time { return now }))
	require.NoError(t, err)
	defer tr2.(io.Closer).Close()
	config1, err := tr1.(*transport).currentECHConfigList()
	require.NoError(t, err)
	config2, err := tr2.(*transport).currentECHConfigList()
	require.NoError(t, err)
	require.Equal(t,
		config1,
		config2,
		"restarted transport must advertise the same ECH config list")
}

func TestECHManagedKeyRotation(t *testing.T) {
	_, priv := createPeer(t)
	now := time.Date(2026, time.January, 15, 0, 0, 0, 0, time.UTC)
	trRaw, err := NewTransport(
		priv,
		newConnManager(t),
		nil,
		nil,
		nil,
		WithServerECH(),
		WithECHPublicName("cover.example"),
		withECHClock(func() time.Time { return now }),
	)
	require.NoError(t, err)
	tr := trRaw.(*transport)

	januaryConfig, err := tr.currentECHConfigList()
	require.NoError(t, err)
	januaryKeys, err := tr.currentECHKeys()
	require.NoError(t, err)
	require.Len(t, januaryKeys, 1)

	now = time.Date(2026, time.February, 1, 0, 0, 0, 0, time.UTC)
	februaryConfig, err := tr.currentECHConfigList()
	require.NoError(t, err)
	require.NotEqual(t, januaryConfig, februaryConfig)
	februaryKeys, err := tr.currentECHKeys()
	require.NoError(t, err)
	require.Len(t, februaryKeys, 2)
	require.Equal(t, januaryKeys[0].Config, februaryKeys[1].Config)

	now = time.Date(2026, time.February, 8, 0, 0, 0, 0, time.UTC)
	afterOverlapKeys, err := tr.currentECHKeys()
	require.NoError(t, err)
	require.Len(t, afterOverlapKeys, 1)
	require.Equal(t, februaryKeys[0].Config, afterOverlapKeys[0].Config)
}

func TestECHPreviousConfigAcceptedDuringRotationOverlap(t *testing.T) {
	serverID, serverKey := createPeer(t)
	_, clientKey := createPeer(t)
	now := time.Date(2026, time.January, 15, 0, 0, 0, 0, time.UTC)
	published := make(chan []byte, 2)
	receivePublished := func() []byte {
		select {
		case config := <-published:
			return config
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for ECH config publication")
			return nil
		}
	}

	serverTransport, err := NewTransport(
		serverKey,
		newConnManager(t),
		nil,
		nil,
		nil,
		WithServerECH(),
		WithECHPublicName("cover.example"),
		withECHClock(func() time.Time { return now }),
		WithECHDNSPublisher(func(config []byte) error {
			published <- append([]byte(nil), config...)
			return nil
		}),
	)
	require.NoError(t, err)
	defer serverTransport.(io.Closer).Close()

	januaryConfig, err := serverTransport.(*transport).currentECHConfigList()
	require.NoError(t, err)
	ln := runServer(t, serverTransport, "/ip4/127.0.0.1/udp/0/quic-v1")
	defer ln.Close()
	require.Equal(t, januaryConfig, receivePublished())

	// Rotate to February. The listener must advertise the new config while its
	// TLS callback retains January's key for the first week.
	now = time.Date(2026, time.February, 1, 0, 0, 0, 0, time.UTC)
	var advertisedConfig []byte
	for _, addr := range ln.(interface{ Multiaddrs() []ma.Multiaddr }).Multiaddrs() {
		_, config := popECHConfigList(addr)
		if config != nil {
			advertisedConfig = config
		}
	}
	require.NotEmpty(t, advertisedConfig)
	require.NotEqual(t, januaryConfig, advertisedConfig)
	require.Equal(t, advertisedConfig, receivePublished())

	clientTransport, err := NewTransport(clientKey, newConnManager(t), nil, nil, nil, withInsecureECHClientForTesting())
	require.NoError(t, err)
	defer clientTransport.(io.Closer).Close()
	staleAddr, err := EncapsulateECHConfig(ln.Multiaddr(), januaryConfig)
	require.NoError(t, err)
	conn, err := clientTransport.Dial(context.Background(), staleAddr, serverID)
	require.NoError(t, err)
	defer conn.Close()
	serverConn, err := ln.Accept()
	require.NoError(t, err)
	defer serverConn.Close()
	require.True(t, echAccepted(t, conn))
}

// TestECHOptionOrder verifies that DisableECHMultiaddrAdvertisement takes
// effect regardless of its position relative to WithServerECH.
func TestECHOptionOrder(t *testing.T) {
	_, priv := createPeer(t)
	for _, opts := range [][]Option{
		{DisableECHMultiaddrAdvertisement(), WithServerECH(), WithECHPublicName("cover.example")},
		{WithECHPublicName("cover.example"), WithServerECH(), DisableECHMultiaddrAdvertisement()},
	} {
		tr, err := NewTransport(priv, newConnManager(t), nil, nil, nil, opts...)
		require.NoError(t, err)
		ln := runServer(t, tr, "/ip4/127.0.0.1/udp/0/quic-v1")
		require.NotContains(t, ln.Multiaddr().String(), "/ech/")
		ln.Close()
		tr.(io.Closer).Close()
	}
}

func TestECHDerivedKeyRequiresPublicName(t *testing.T) {
	_, priv := createPeer(t)
	_, err := NewTransport(priv, newConnManager(t), nil, nil, nil, WithServerECH())
	require.ErrorContains(t, err, "WithECHPublicName")
}

// TestECHViaMultiaddr verifies that a server advertising its ECH config via its
// listen multiaddr can be dialed with ECH negotiated end-to-end, and that the
// plain address is advertised alongside the /ech one.
func TestECHViaMultiaddr(t *testing.T) {
	serverID, serverKey := createPeer(t)
	_, clientKey := createPeer(t)

	serverTransport, err := NewTransport(serverKey, newConnManager(t), nil, nil, nil, WithServerECH(), WithECHPublicName("cover.example"))
	require.NoError(t, err)
	defer serverTransport.(io.Closer).Close()

	ln := runServer(t, serverTransport, "/ip4/127.0.0.1/udp/0/quic-v1")
	defer ln.Close()

	// Multiaddr reports the actual local transport address, without metadata.
	require.NotContains(t, ln.Multiaddr().String(), "/ech/")
	// The listener must additionally advertise the plain address, so that
	// peers that don't understand the /ech protocol can still dial.
	addrs := ln.(interface{ Multiaddrs() []ma.Multiaddr }).Multiaddrs()
	require.Len(t, addrs, 2)
	var plain, withECH bool
	var echAddr ma.Multiaddr
	for _, a := range addrs {
		if _, err := a.ValueForProtocol(ma.P_ECH); err == nil {
			withECH = true
			echAddr = a
		} else {
			plain = true
		}
	}
	require.True(t, plain, "expected a plain listen address to be advertised")
	require.True(t, withECH, "expected an /ech listen address to be advertised")

	clientTransport, err := NewTransport(clientKey, newConnManager(t), nil, nil, nil, withInsecureECHClientForTesting())
	require.NoError(t, err)
	defer clientTransport.(io.Closer).Close()

	conn, err := clientTransport.Dial(context.Background(), echAddr, serverID)
	require.NoError(t, err)
	defer conn.Close()
	serverConn, err := ln.Accept()
	require.NoError(t, err)
	defer serverConn.Close()

	require.True(t, echAccepted(t, conn), "expected ECH to be accepted on the client connection")
	// The connection's remote multiaddr should not leak the /ech component.
	require.NotContains(t, conn.RemoteMultiaddr().String(), "/ech/")
	// The server's local multiaddr describes the transport endpoint, not the
	// metadata used by this particular client to dial it.
	require.NotContains(t, serverConn.LocalMultiaddr().String(), "/ech/")
}

// TestECHViaManualClientConfig verifies that a server advertising its ECH config
// exclusively via a DNS callback (not the multiaddr) can be dialed by a client
// that attaches the out-of-band config to the dialed multiaddr.
func TestECHViaManualClientConfig(t *testing.T) {
	serverID, serverKey := createPeer(t)
	_, clientKey := createPeer(t)

	echKey, err := GenerateECHConfig("server.example")
	require.NoError(t, err)
	configList := MarshalECHConfigList(echKey)

	published := make(chan []byte, 1)
	serverTransport, err := NewTransport(serverKey, newConnManager(t), nil, nil, nil,
		WithServerECH(echKey),
		DisableECHMultiaddrAdvertisement(),
		WithECHDNSPublisher(func(cl []byte) error {
			published <- cl
			return nil
		}),
	)
	require.NoError(t, err)
	defer serverTransport.(io.Closer).Close()
	require.False(t, serverTransport.(*transport).ech.serverKeys[0].SendAsRetry)

	ln := runServer(t, serverTransport, "/ip4/127.0.0.1/udp/0/quic-v1")
	defer ln.Close()

	// The multiaddr must NOT carry the /ech component when advertisement is disabled.
	require.NotContains(t, ln.Multiaddr().String(), "/ech/")
	// The DNS publisher must be invoked (asynchronously) with the config list.
	select {
	case cl := <-published:
		require.Equal(t, configList, cl)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the DNS publisher to be invoked")
	}

	clientTransport, err := NewTransport(clientKey, newConnManager(t), nil, nil, nil, withInsecureECHClientForTesting())
	require.NoError(t, err)
	defer clientTransport.(io.Closer).Close()

	// The client obtained the config out of band (here: from the test setup)
	// and attaches it to this specific dial.
	dialAddr, err := EncapsulateECHConfig(ln.Multiaddr(), configList)
	require.NoError(t, err)

	conn, err := clientTransport.Dial(context.Background(), dialAddr, serverID)
	require.NoError(t, err)
	defer conn.Close()
	serverConn, err := ln.Accept()
	require.NoError(t, err)
	defer serverConn.Close()

	require.True(t, echAccepted(t, conn), "expected ECH to be accepted on the client connection")
}

// TestECHDNSPublisherFailureRetries verifies that a transient publisher
// failure doesn't prevent listening and is retried on the next address refresh.
func TestECHDNSPublisherFailureRetries(t *testing.T) {
	_, serverKey := createPeer(t)

	results := make(chan error, 2)
	var calls int
	serverTransport, err := NewTransport(serverKey, newConnManager(t), nil, nil, nil,
		WithServerECH(),
		WithECHPublicName("cover.example"),
		DisableECHMultiaddrAdvertisement(),
		WithECHDNSPublisher(func([]byte) error {
			calls++
			if calls == 1 {
				results <- io.ErrUnexpectedEOF
				return io.ErrUnexpectedEOF
			}
			results <- nil
			return nil
		}),
	)
	require.NoError(t, err)
	defer serverTransport.(io.Closer).Close()

	ln := runServer(t, serverTransport, "/ip4/127.0.0.1/udp/0/quic-v1")
	defer ln.Close()
	select {
	case err := <-results:
		require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the DNS publisher to be invoked")
	}
	require.Eventually(t, func() bool {
		_ = ln.(interface{ Multiaddrs() []ma.Multiaddr }).Multiaddrs()
		select {
		case err := <-results:
			return err == nil
		default:
			return false
		}
	}, 5*time.Second, 10*time.Millisecond)
}

// TestNoECHByDefault verifies that connections do not negotiate ECH unless it is
// explicitly configured.
func TestNoECHByDefault(t *testing.T) {
	serverID, serverKey := createPeer(t)
	_, clientKey := createPeer(t)

	serverTransport, err := NewTransport(serverKey, newConnManager(t), nil, nil, nil)
	require.NoError(t, err)
	defer serverTransport.(io.Closer).Close()

	ln := runServer(t, serverTransport, "/ip4/127.0.0.1/udp/0/quic-v1")
	defer ln.Close()
	require.NotContains(t, ln.Multiaddr().String(), "/ech/")

	clientTransport, err := NewTransport(clientKey, newConnManager(t), nil, nil, nil)
	require.NoError(t, err)
	defer clientTransport.(io.Closer).Close()

	conn, err := clientTransport.Dial(context.Background(), ln.Multiaddr(), serverID)
	require.NoError(t, err)
	defer conn.Close()
	serverConn, err := ln.Accept()
	require.NoError(t, err)
	defer serverConn.Close()

	require.False(t, echAccepted(t, conn), "did not expect ECH to be negotiated")
}
