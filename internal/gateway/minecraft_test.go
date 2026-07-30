package gateway

import (
	"net"
	"testing"
)

// encodeVarInt encodes an integer into Minecraft VarInt bytes
func encodeVarInt(val int) []byte {
	var buf []byte
	uval := uint32(val)
	for {
		b := byte(uval & 0x7F)
		uval >>= 7
		if uval != 0 {
			b |= 0x80
		}
		buf = append(buf, b)
		if uval == 0 {
			break
		}
	}
	return buf
}

func TestDecodeVarInt(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantVal int
		wantLen int
		wantErr bool
	}{
		{"zero", []byte{0x00}, 0, 1, false},
		{"one byte 1", []byte{0x01}, 1, 1, false},
		{"one byte 127", []byte{0x7F}, 127, 1, false},
		{"two bytes 128", []byte{0x80, 0x01}, 128, 2, false},
		{"two bytes 255", []byte{0xFF, 0x01}, 255, 2, false},
		{"three bytes 25565", encodeVarInt(25565), 25565, 3, false},
		{"empty slice", []byte{}, 0, 0, true},
		{"incomplete varint", []byte{0x80, 0x80}, 0, 0, true},
		{"varint overflow 6 bytes", []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x01}, 0, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, length, err := decodeVarInt(tt.data)
			if (err != nil) != tt.wantErr {
				t.Fatalf("decodeVarInt() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if val != tt.wantVal {
					t.Errorf("decodeVarInt() val = %d, want %d", val, tt.wantVal)
				}
				if length != tt.wantLen {
					t.Errorf("decodeVarInt() length = %d, want %d", length, tt.wantLen)
				}
			}
		})
	}
}

func buildMinecraftHandshake(version int, host string, port uint16, nextState int) []byte {
	var payload []byte
	payload = append(payload, encodeVarInt(0)...) // Packet ID 0
	payload = append(payload, encodeVarInt(version)...)
	payload = append(payload, encodeVarInt(len(host))...)
	payload = append(payload, []byte(host)...)
	payload = append(payload, byte(port>>8), byte(port&0xFF))
	payload = append(payload, encodeVarInt(nextState)...)

	var packet []byte
	packet = append(packet, encodeVarInt(len(payload))...)
	packet = append(packet, payload...)
	return packet
}

func buildMinecraftLoginStart(username string) []byte {
	var payload []byte
	payload = append(payload, encodeVarInt(0)...) // Packet ID 0 for Login Start
	payload = append(payload, encodeVarInt(len(username))...)
	payload = append(payload, []byte(username)...)

	var packet []byte
	packet = append(packet, encodeVarInt(len(payload))...)
	packet = append(packet, payload...)
	return packet
}

func TestGetMinecraftInfo(t *testing.T) {
	t.Run("Valid Status Request Handshake", func(t *testing.T) {
		pkt := buildMinecraftHandshake(754, "mc.example.com", 25565, 1)

		serverConn, clientConn := net.Pipe()
		defer serverConn.Close()

		go func() {
			defer clientConn.Close()
			clientConn.Write(pkt)
		}()

		tcp := newTCPConn(serverConn)
		info, err := tcp.getMinecraftInfo()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if info == nil {
			t.Fatalf("expected non-nil MinecraftInfo")
		}

		if info.RequestedHost != "mc.example.com" {
			t.Errorf("RequestedHost = %q, want %q", info.RequestedHost, "mc.example.com")
		}
		if info.RequestedPort != 25565 {
			t.Errorf("RequestedPort = %d, want %d", info.RequestedPort, 25565)
		}
		if info.ProtocolVersion != 754 {
			t.Errorf("ProtocolVersion = %d, want %d", info.ProtocolVersion, 754)
		}
		if info.ProtocolState != 1 {
			t.Errorf("ProtocolState = %d, want %d", info.ProtocolState, 1)
		}
		if info.IsLoginStart {
			t.Errorf("IsLoginStart should be false for status packet")
		}

		// Verify cached result
		infoCached, errCached := tcp.getMinecraftInfo()
		if infoCached != info || errCached != err {
			t.Errorf("cached getMinecraftInfo returned different result")
		}
	})

	t.Run("Valid Login Start Handshake with Username", func(t *testing.T) {
		pktHandshake := buildMinecraftHandshake(754, "mc.example.com", 25565, 2)
		pktLoginStart := buildMinecraftLoginStart("SteveCraftPlayer1")
		fullData := append(pktHandshake, pktLoginStart...)

		serverConn, clientConn := net.Pipe()
		defer serverConn.Close()

		go func() {
			defer clientConn.Close()
			clientConn.Write(fullData)
		}()

		tcp := newTCPConn(serverConn)
		info, err := tcp.getMinecraftInfo()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if info == nil {
			t.Fatalf("expected non-nil MinecraftInfo")
		}

		if info.ProtocolState != 2 {
			t.Errorf("ProtocolState = %d, want 2", info.ProtocolState)
		}
		if !info.IsLoginStart {
			t.Errorf("IsLoginStart should be true")
		}
		if info.Username != "SteveCraftPlayer1" {
			t.Errorf("Username = %q, want %q", info.Username, "SteveCraftPlayer1")
		}
	})

	t.Run("Non-Minecraft TCP Packet (HTTP Request)", func(t *testing.T) {
		serverConn, clientConn := net.Pipe()
		defer serverConn.Close()

		go func() {
			defer clientConn.Close()
			clientConn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
		}()

		tcp := newTCPConn(serverConn)
		info, err := tcp.getMinecraftInfo()
		if err != nil {
			t.Fatalf("expected nil error for non-minecraft traffic, got %v", err)
		}
		if info != nil {
			t.Errorf("expected nil MinecraftInfo for HTTP request, got %+v", info)
		}
	})

	t.Run("Oversized Handshake Packet Prefix", func(t *testing.T) {
		serverConn, clientConn := net.Pipe()
		defer serverConn.Close()

		go func() {
			defer clientConn.Close()
			// Length prefix > 8192 (defensiveMaxPacketSize)
			clientConn.Write(encodeVarInt(9000))
		}()

		tcp := newTCPConn(serverConn)
		info, err := tcp.getMinecraftInfo()
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
		if info != nil {
			t.Errorf("expected nil info for oversized handshake prefix")
		}
	})

	t.Run("Short / Truncated Packet Data", func(t *testing.T) {
		serverConn, clientConn := net.Pipe()
		defer serverConn.Close()

		// Write only 2 bytes and close client connection
		go func() {
			defer clientConn.Close()
			clientConn.Write([]byte{0x02, 0x00})
		}()

		tcp := newTCPConn(serverConn)
		info, _ := tcp.getMinecraftInfo()
		if info != nil {
			t.Errorf("expected nil info for truncated data")
		}
	})
}
