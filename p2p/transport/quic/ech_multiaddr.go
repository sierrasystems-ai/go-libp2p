package libp2pquic

import (
	"errors"
	"fmt"

	ma "github.com/multiformats/go-multiaddr"
	"github.com/multiformats/go-multibase"
)

const echProtocolCode = 9849

func init() {
	if protocol := ma.ProtocolWithCode(echProtocolCode); protocol.Code != 0 {
		if protocol.Name != "ech" {
			panic(fmt.Sprintf("multiaddr protocol code %d registered as %q, expected %q", echProtocolCode, protocol.Name, "ech"))
		}
		return
	}
	if protocol := ma.ProtocolWithName("ech"); protocol.Code != 0 {
		panic(fmt.Sprintf("multiaddr protocol %q registered with code %d, expected %d", "ech", protocol.Code, echProtocolCode))
	}

	err := ma.AddProtocol(ma.Protocol{
		Name:       "ech",
		Code:       echProtocolCode,
		VCode:      ma.CodeToVarint(echProtocolCode),
		Size:       ma.LengthPrefixedVarSize,
		Transcoder: ma.NewTranscoderFromFunctions(echStringToBytes, echBytesToString, validateECHMultiaddrValue),
	})
	if err != nil {
		panic(fmt.Sprintf("registering /ech multiaddr protocol: %v", err))
	}
}

func echStringToBytes(value string) ([]byte, error) {
	_, data, err := multibase.Decode(value)
	if err != nil {
		return nil, err
	}
	if err := validateECHMultiaddrValue(data); err != nil {
		return nil, err
	}
	return data, nil
}

func echBytesToString(data []byte) (string, error) {
	if err := validateECHMultiaddrValue(data); err != nil {
		return "", err
	}
	return multibase.Encode(multibase.Base64url, data)
}

func validateECHMultiaddrValue(data []byte) error {
	if len(data) == 0 {
		return errors.New("empty ECHConfigList")
	}
	return nil
}
