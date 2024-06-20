package types

import (
	"fmt"
	"strings"
)

type UdpPacket struct {
	SrcIP     string `json:"src_ip" bson:"src_ip"`
	DstIP     string `json:"dst_ip" bson:"dst_ip"`
	SrcPort   uint   `json:"src_port" bson:"src_port"`
	DstPort   uint   `json:"dst_port" bson:"dst_port"`
	Len       uint   `json:"len" bson:"len"`
	Payload   []byte `json:"payload" bson:"payload"`
	ProtoType uint   `json:"proto_type" bson:"proto_type"`
	Direction uint   `json:"direction" bson:"direction"`
}

// ToString method for UdpPacket
func (up UdpPacket) ToString() string {
	// Convert byte slice to string, ensuring length doesn't exceed Len
	strPayload := string(up.Payload[:up.Len])
	strProto := "Unknown"
	strDirection := "Unknown"

	switch up.ProtoType {
	case 1:
		strProto = "TCP"
	case 2:
		strProto = "UDP"
	case 3:
		strProto = "SCTP"
	default:
		strProto = "Unknown"
	}

	switch up.Direction {
	case 1:
		strDirection = "Ingress"
	case 2:
		strDirection = "Egress"
	}

	// Replace null bytes with whitespace
	return fmt.Sprintf("[%s]%s:%d -> %s:%d (%s), len=%d, buff=%v",
		strProto, up.SrcIP, up.SrcPort, up.DstIP, up.DstPort, strDirection, up.Len, strings.ReplaceAll(strPayload, "\x00", " "))
}
