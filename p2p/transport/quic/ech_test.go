package libp2pquic

import (
	"context"
	"io"
	"testing"

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
	key, err := GenerateECHConfig("example.com")
	require.NoError(t, err)
	require.NotEmpty(t, key.Config)
	require.NotEmpty(t, key.PrivateKey)

	configList := MarshalECHConfigList(key)
	require.NoError(t, validateECHConfigList(configList))

	base := ma.StringCast("/ip4/1.2.3.4/udp/1234/quic-v1")
	withECH, err := encapsulateECH(base, configList)
	require.NoError(t, err)
	require.Contains(t, withECH.String(), "/ech/")

	// Round-trip through the string representation to exercise the transcoder.
	reparsed := ma.StringCast(withECH.String())
	rest, gotConfigList, err := popECHConfigList(reparsed)
	require.NoError(t, err)
	require.Equal(t, base.String(), rest.String())
	require.Equal(t, configList, gotConfigList)

	// A multiaddr without an /ech component is returned unchanged.
	rest, gotConfigList, err = popECHConfigList(base)
	require.NoError(t, err)
	require.Nil(t, gotConfigList)
	require.Equal(t, base.String(), rest.String())
}

func TestECHCanDial(t *testing.T) {
	_, priv := createPeer(t)
	tr, err := NewTransport(priv, newConnManager(t), nil, nil, nil)
	require.NoError(t, err)
	defer tr.(io.Closer).Close()

	echKey, err := GenerateECHConfig("")
	require.NoError(t, err)
	withECH, err := encapsulateECH(ma.StringCast("/ip4/1.2.3.4/udp/1234/quic-v1"), MarshalECHConfigList(echKey))
	require.NoError(t, err)

	require.True(t, tr.CanDial(ma.StringCast("/ip4/1.2.3.4/udp/1234/quic-v1")))
	require.True(t, tr.CanDial(withECH))
}

// TestECHViaMultiaddr verifies that a server advertising its ECH config via its
// listen multiaddr can be dialed with ECH negotiated end-to-end.
func TestECHViaMultiaddr(t *testing.T) {
	serverID, serverKey := createPeer(t)
	_, clientKey := createPeer(t)

	serverTransport, err := NewTransport(serverKey, newConnManager(t), nil, nil, nil, WithServerECH())
	require.NoError(t, err)
	defer serverTransport.(io.Closer).Close()

	ln := runServer(t, serverTransport, "/ip4/127.0.0.1/udp/0/quic-v1")
	defer ln.Close()

	// The advertised multiaddr must carry the /ech component.
	require.Contains(t, ln.Multiaddr().String(), "/ech/")

	clientTransport, err := NewTransport(clientKey, newConnManager(t), nil, nil, nil)
	require.NoError(t, err)
	defer clientTransport.(io.Closer).Close()

	conn, err := clientTransport.Dial(context.Background(), ln.Multiaddr(), serverID)
	require.NoError(t, err)
	defer conn.Close()
	serverConn, err := ln.Accept()
	require.NoError(t, err)
	defer serverConn.Close()

	require.True(t, echAccepted(t, conn), "expected ECH to be accepted on the client connection")
	// The connection's remote multiaddr should not leak the /ech component.
	require.NotContains(t, conn.RemoteMultiaddr().String(), "/ech/")
}

// TestECHViaManualClientConfig verifies that a server advertising its ECH config
// exclusively via a DNS callback (not the multiaddr) can be dialed by a client
// that was manually supplied the config.
func TestECHViaManualClientConfig(t *testing.T) {
	serverID, serverKey := createPeer(t)
	_, clientKey := createPeer(t)

	echKey, err := GenerateECHConfig("server.example")
	require.NoError(t, err)
	configList := MarshalECHConfigList(echKey)

	var published [][]byte
	serverTransport, err := NewTransport(serverKey, newConnManager(t), nil, nil, nil,
		WithServerECH(echKey),
		DisableECHMultiaddrAdvertisement(),
		WithECHDNSPublisher(func(cl []byte) error {
			published = append(published, cl)
			return nil
		}),
	)
	require.NoError(t, err)
	defer serverTransport.(io.Closer).Close()

	ln := runServer(t, serverTransport, "/ip4/127.0.0.1/udp/0/quic-v1")
	defer ln.Close()

	// The multiaddr must NOT carry the /ech component when advertisement is disabled.
	require.NotContains(t, ln.Multiaddr().String(), "/ech/")
	// The DNS publisher must have been invoked with the config list.
	require.Len(t, published, 1)
	require.Equal(t, configList, published[0])

	clientTransport, err := NewTransport(clientKey, newConnManager(t), nil, nil, nil,
		WithClientECHConfig(configList),
	)
	require.NoError(t, err)
	defer clientTransport.(io.Closer).Close()

	conn, err := clientTransport.Dial(context.Background(), ln.Multiaddr(), serverID)
	require.NoError(t, err)
	defer conn.Close()
	serverConn, err := ln.Accept()
	require.NoError(t, err)
	defer serverConn.Close()

	require.True(t, echAccepted(t, conn), "expected ECH to be accepted on the client connection")
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
