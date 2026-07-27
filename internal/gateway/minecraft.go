package gateway

import (
	"errors"
	"io"
)

type MinecraftInfo struct {
	RequestedHost   string
	RequestedPort   uint16
	ProtocolState   int
	ProtocolVersion int
	Username        string
	IsLoginStart    bool
}

func decodeVarInt(data []byte) (value int, length int, err error) {
	if len(data) == 0 {
		return 0, 0, io.EOF
	}

	for i := range data {
		b := data[i]
		value |= int(b&0x7F) << (7 * i)
		length = i + 1
		if (b & 0x80) == 0 {
			return value, length, nil
		}
		if length >= 5 {
			return 0, 0, errors.New("varint too large")
		}
	}
	return 0, 0, errors.New("incomplete varint")
}
func (c *tcpConn) getMinecraftInfo() (*MinecraftInfo, error) {
	if c.minecraftChecked {
		return c.minecraftInfo, nil
	}

	result := &MinecraftInfo{}

	const maxVarIntSize = 5
	const defensiveMaxPacketSize = 8192

	data, err := c.Peek(maxVarIntSize)
	if err != nil && err != io.EOF {
		return nil, err
	}

	if len(data) < maxVarIntSize {
		return nil, nil
	}

	handshakePayloadLen, prefixLen, err := decodeVarInt(data)
	if err != nil {
		return nil, errors.New("malformed handshake length prefix")
	}

	totalHandshakeLen := prefixLen + handshakePayloadLen

	if totalHandshakeLen > defensiveMaxPacketSize {
		c.minecraftChecked = true
		return nil, nil
	}

	// Fast Minecraft detection:
	// The first packet after the length prefix must be the Handshake packet (0x00)
	packetHeader, err := c.Peek(prefixLen + 1)
	if err != nil && err != io.EOF {
		return nil, err
	}

	if len(packetHeader) <= prefixLen {
		return nil, nil
	}

	packetID, _, err := decodeVarInt(packetHeader[prefixLen:])
	if err != nil {
		return nil, nil
	}

	if packetID != 0 {
		c.minecraftChecked = true
		c.minecraftInfo = nil
		return nil, nil
	}

	// Now we know this is very likely Minecraft.
	data, err = c.Peek(totalHandshakeLen)
	if err != nil && err != io.EOF {
		return nil, err
	}

	if len(data) < totalHandshakeLen {
		return nil, nil
	}

	offset := prefixLen

	// Packet ID (already checked above)
	_, idLen, err := decodeVarInt(data[offset:])
	if err != nil {
		return nil, errors.New("malformed handshake ID")
	}
	offset += idLen

	// Protocol version
	version, versionLen, err := decodeVarInt(data[offset:])
	if err != nil {
		return nil, errors.New("malformed protocol version")
	}

	result.ProtocolVersion = version
	offset += versionLen

	// Host
	hostLen, hostLenBytes, err := decodeVarInt(data[offset:])
	if err != nil {
		return nil, errors.New("malformed host length")
	}

	offset += hostLenBytes

	if offset+hostLen > len(data) {
		return nil, errors.New("invalid host length")
	}

	result.RequestedHost = string(data[offset : offset+hostLen])
	offset += hostLen

	// Port
	if offset+2 > len(data) {
		return nil, errors.New("missing port")
	}

	result.RequestedPort = uint16(data[offset])<<8 | uint16(data[offset+1])
	offset += 2

	// Next state
	nextState, stateLen, err := decodeVarInt(data[offset:])
	if err != nil {
		return nil, errors.New("malformed next state")
	}

	result.ProtocolState = nextState
	offset += stateLen

	// Status request doesn't have username
	if result.ProtocolState != 2 {
		c.minecraftInfo = result
		c.minecraftChecked = true
		return result, nil
	}

	// Login Start parsing
	const loginPrefixCheck = 15

	extendedData, err := c.Peek(offset + loginPrefixCheck)
	if err != nil && err != io.EOF {
		return nil, err
	}

	loginData := extendedData[offset:]

	if len(loginData) < loginPrefixCheck {
		return nil, nil
	}

	loginOffset := 0

	// Packet length
	_, loginLen, err := decodeVarInt(loginData[loginOffset:])
	if err != nil {
		return nil, nil
	}
	loginOffset += loginLen

	// Packet ID
	packetID, packetIDLen, err := decodeVarInt(loginData[loginOffset:])
	if err != nil {
		return nil, nil
	}
	loginOffset += packetIDLen

	if packetID != 0 {
		c.minecraftInfo = result
		c.minecraftChecked = true
		return result, nil
	}

	result.IsLoginStart = true

	// Username length
	userLen, userLenBytes, err := decodeVarInt(loginData[loginOffset:])
	if err != nil {
		return nil, errors.New("malformed username length")
	}
	loginOffset += userLenBytes

	totalUsernameBytesNeeded := offset + loginOffset + userLen

	finalData, err := c.Peek(totalUsernameBytesNeeded)
	if err != nil && err != io.EOF {
		return nil, err
	}

	if len(finalData) < totalUsernameBytesNeeded {
		return nil, nil
	}

	usernameStart := offset + loginOffset
	result.Username = string(finalData[usernameStart : usernameStart+userLen])

	c.minecraftInfo = result
	c.minecraftChecked = true

	return result, nil
}
