package ebpf

import (
	"encoding/binary"
	"net"
	"net/url"
	"strings"
)

const (
	ARecord              = 1
	INClass              = 1
	MaxDNSNameByteLength = 256
)

type DnsQuery struct {
	Name [MaxDNSNameByteLength]uint8 // Fixed-size array for correct struct alignment
}

func returnHostName(urlInput string) (string, error) {
	urlInput = strings.TrimSpace(urlInput)

	parsedURL, err := url.Parse(urlInput)
	if err != nil || parsedURL.Hostname() == "" {
		return "", err

	}

	hostName := string(append([]byte(parsedURL.Hostname()), '.'))

	return hostName, nil
}
func createDnsQuery(url string) (DnsQuery, error) {
	var query DnsQuery
	domain, err := returnHostName(url)
	if err != nil {
		return DnsQuery{}, err
	}

	copy(query.Name[:], domain)
	//Reverse byte order to make it little endian

	/*for i, j := 0, len(domain)-1; i < j; i, j = i+1, j-1 {
		query.Name[i], query.Name[j] = query.Name[j], query.Name[i]
	}*/
	query.Name[len(domain)] = 0x00

	return query, nil
}

func convertToUint32(ipStr string) (uint32, error) {
	ip := net.ParseIP(ipStr)
	ip = ip.To4() // Ensure it's an IPv4 address
	return binary.LittleEndian.Uint32(ip), nil
}
