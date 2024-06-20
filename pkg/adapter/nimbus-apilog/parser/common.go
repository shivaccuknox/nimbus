package parser

import (
	"github.com/5GSEC/nimbus/pkg/adapter/nimbus-apilog/types"
)

// parseCommon Function
// returns src, dst
func parseCommon(packet types.UdpPacket) (types.NetworkDevice, types.NetworkDevice) {
	// srcResource := k8s.LookupK8sResource(packet.SrcIP)
	// dstResource := k8s.LookupK8sResource(packet.DstIP)

	src := types.NetworkDevice{
		IPAddr:        packet.SrcIP,
		Port:          packet.SrcPort,
		IsK8sResource: false,
	}

	dst := types.NetworkDevice{
		IPAddr:        packet.DstIP,
		Port:          packet.DstPort,
		IsK8sResource: false,
	}

	return src, dst
}
