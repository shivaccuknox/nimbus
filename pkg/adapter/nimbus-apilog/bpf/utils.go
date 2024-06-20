package bpf

import (
	"BeeCol/types"
	"encoding/binary"
	"net"
)

// processEvent Function
func processEvent(event bpfEvent) types.UdpPacket {
	addrPair := event.AddrPair
	portPair := event.PortPair

	// Convert and assign values directly
	srcIpBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(srcIpBytes, uint32(addrPair&0xFFFFFFFF))

	dstIpBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(dstIpBytes, uint32((addrPair>>32)&0xFFFFFFFF))

	// Big endian to litten endian
	srcPortBytes := []byte{byte((portPair >> 8) & 0xFF), byte(portPair & 0xFF)}
	dstPortBytes := []byte{byte((portPair >> 24) & 0xFF), byte((portPair >> 16) & 0xFF)}

	srcPort := binary.LittleEndian.Uint16(srcPortBytes)
	dstPort := binary.LittleEndian.Uint16(dstPortBytes)

	// Create UdpPacket with the converted values
	ret := types.UdpPacket{
		SrcIP:     net.IP(srcIpBytes).String(),
		DstIP:     net.IP(dstIpBytes).String(),
		SrcPort:   uint(srcPort),
		DstPort:   uint(dstPort),
		Len:       uint(event.Len),
		ProtoType: uint(event.Type),
		Payload:   make([]byte, len(event.Buff)),
		Direction: uint(event.Direction),
	}

	for i, val := range event.Buff {
		ret.Payload[i] = val
	}

	return ret
}
