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

	// A public name longer than 255 bytes returns an error instead of panicking.
	_, err = GenerateECHConfig(strings.Repeat("a", 300))
	require.ErrorContains(t, err, "public name")
}

func TestECHCanDial(t *testing.T) {
	_, priv := createPeer(t)
	tr, err := NewTransport(priv, newConnManager(t), nil, nil, nil)
	require.NoError(t, err)
	defer tr.(io.Closer).Close()

	echKey, err := GenerateECHConfig("")
	require.NoError(t, err)
	withECH, err := EncapsulateECHConfig(ma.StringCast("/ip4/1.2.3.4/udp/1234/quic-v1"), MarshalECHConfigList(echKey))
	require.NoError(t, err)

	require.True(t, tr.CanDial(ma.StringCast("/ip4/1.2.3.4/udp/1234/quic-v1")))
	require.True(t, tr.CanDial(withECH))
}

// TestECHDeterministicKeys verifies that WithServerECH without explicit keys
// derives the same ECH config from the same host key across transport
// instances (i.e. across restarts), and different configs for different hosts.
func TestECHDeterministicKeys(t *testing.T) {
	_, priv := createPeer(t)
	_, otherPriv := createPeer(t)

	key1, err := deriveECHConfig(priv, DefaultECHPublicName)
	require.NoError(t, err)
	key2, err := deriveECHConfig(priv, DefaultECHPublicName)
	require.NoError(t, err)
	require.Equal(t, key1, key2, "same host key must derive the same ECH key")

	otherKey, err := deriveECHConfig(otherPriv, DefaultECHPublicName)
	require.NoError(t, err)
	require.NotEqual(t, key1.Config, otherKey.Config, "different host keys must derive different ECH keys")
	require.NotEqual(t, key1.PrivateKey, otherKey.PrivateKey)

	// The transport option wires the derived key through to the advertised
	// config list.
	tr1, err := NewTransport(priv, newConnManager(t), nil, nil, nil, WithServerECH())
	require.NoError(t, err)
	defer tr1.(io.Closer).Close()
	tr2, err := NewTransport(priv, newConnManager(t), nil, nil, nil, WithServerECH())
	require.NoError(t, err)
	defer tr2.(io.Closer).Close()
	require.Equal(t,
		tr1.(*transport).ech.serverConfigList,
		tr2.(*transport).ech.serverConfigList,
		"restarted transport must advertise the same ECH config list")
}

// TestECHOptionOrder verifies that DisableECHMultiaddrAdvertisement takes
// effect regardless of its position relative to WithServerECH.
func TestECHOptionOrder(t *testing.T) {
	_, priv := createPeer(t)
	for _, opts := range [][]Option{
		{DisableECHMultiaddrAdvertisement(), WithServerECH()},
		{WithServerECH(), DisableECHMultiaddrAdvertisement()},
	} {
		tr, err := NewTransport(priv, newConnManager(t), nil, nil, nil, opts...)
		require.NoError(t, err)
		ln := runServer(t, tr, "/ip4/127.0.0.1/udp/0/quic-v1")
		require.NotContains(t, ln.Multiaddr().String(), "/ech/")
		ln.Close()
		tr.(io.Closer).Close()
	}
}

// TestECHViaMultiaddr verifies that a server advertising its ECH config via its
// listen multiaddr can be dialed with ECH negotiated end-to-end, and that the
// plain address is advertised alongside the /ech one.
func TestECHViaMultiaddr(t *testing.T) {
	serverID, serverKey := createPeer(t)
	_, clientKey := createPeer(t)

	serverTransport, err := NewTransport(serverKey, newConnManager(t), nil, nil, nil, WithServerECH())
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

	clientTransport, err := NewTransport(clientKey, newConnManager(t), nil, nil, nil)
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

	clientTransport, err := NewTransport(clientKey, newConnManager(t), nil, nil, nil)
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

// TestECHDNSPublisherFailureDoesNotBreakListen verifies that a failing DNS
// publisher doesn't prevent the node from listening.
func TestECHDNSPublisherFailureDoesNotBreakListen(t *testing.T) {
	_, serverKey := createPeer(t)

	called := make(chan struct{}, 1)
	serverTransport, err := NewTransport(serverKey, newConnManager(t), nil, nil, nil,
		WithServerECH(),
		WithECHDNSPublisher(func([]byte) error {
			called <- struct{}{}
			return io.ErrUnexpectedEOF
		}),
	)
	require.NoError(t, err)
	defer serverTransport.(io.Closer).Close()

	ln := runServer(t, serverTransport, "/ip4/127.0.0.1/udp/0/quic-v1")
	defer ln.Close()
	select {
	case <-called:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the DNS publisher to be invoked")
	}
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
