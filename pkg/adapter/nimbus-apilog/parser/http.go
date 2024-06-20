package parser

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/5GSEC/nimbus/pkg/adapter/nimbus-apilog/types"
)

// ParseHTTPRequest Function
func ParseHTTPRequest(packet types.UdpPacket) (*types.HTTPRequest, error) {
	reader := bufio.NewReader(bytes.NewReader(packet.Payload))

	requestLine, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read request line: %w", err)
	}

	requestLine = strings.TrimSpace(requestLine)
	parts := strings.Split(requestLine, " ")
	if len(parts) != 3 {
		return nil, errors.New("malformed request line")
	}

	method, path, version := parts[0], parts[1], parts[2]

	if strings.Contains(version, "HTTP") {
		src, dst := parseCommon(packet)
		return &types.HTTPRequest{
			Src:     src,
			Dst:     dst,
			Method:  method,
			Path:    path,
			Version: version,
		}, nil
	} else {
		return nil, errors.New("invalid HTTP packet")
	}
}

// ParseHTTPResponse Function
func ParseHTTPResponse(packet types.UdpPacket) (*types.HTTPResponse, error) {
	reader := bufio.NewReader(bytes.NewReader(packet.Payload))

	responseLine, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read response line: %w", err)
	}

	responseLine = strings.TrimSpace(responseLine)
	parts := strings.Split(responseLine, " ")
	if len(parts) != 3 {
		return nil, errors.New("malformed response line")
	}

	version, strResponseCode, _ := parts[0], parts[1], parts[2]
	responseCode, err := strconv.Atoi(strResponseCode)
	if err != nil {
		msg := fmt.Sprintf("unable to parse response code %s: %v", strResponseCode, err)
		return nil, errors.New(msg)
	}

	if strings.Contains(version, "HTTP") {
		src, dst := parseCommon(packet)
		return &types.HTTPResponse{
			Src:          src,
			Dst:          dst,
			Version:      version,
			ResponseCode: responseCode,
		}, nil
	} else {
		return nil, errors.New("invalid HTTP packet")
	}
}
