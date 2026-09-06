package httputil

import (
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// ParseURI accepts absolute HTTP(S) URLs and scheme-less DNS/IP hosts (HTTPS).
// Paths, escaped components, host spelling, and queries retain their case.
// Userinfo, fragments (even empty), zone IDs, Unicode hostnames, ambiguous IPs,
// and empty/out-of-range ports are rejected. Use ASCII punycode for IDNs.
// DNS names may be single-label or end in a dot; underscores are not DNS labels.
func ParseURI(uri string) (*url.URL, error) {
	if uri == "" || strings.TrimSpace(uri) != uri || strings.Contains(uri, "#") {
		return nil, fmt.Errorf("URL is empty, padded, or contains a fragment")
	}
	schemeEnd := strings.Index(uri, "://")
	if schemeEnd < 0 || strings.ContainsAny(uri[:schemeEnd], "/?") {
		uri = "https://" + uri
	}
	parsed, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Opaque != "" || parsed.Host == "" || parsed.User != nil {
		return nil, fmt.Errorf("URL requires an HTTP(S) host without userinfo")
	}
	host := parsed.Hostname()
	if host == "" {
		return nil, fmt.Errorf("URL host is empty")
	}
	if strings.HasPrefix(parsed.Host, "[") {
		ip, err := netip.ParseAddr(host)
		if err != nil || !ip.Is6() || ip.Zone() != "" {
			return nil, fmt.Errorf("invalid bracketed IPv6 host")
		}
	} else if strings.Contains(host, ":") {
		return nil, fmt.Errorf("IPv6 hosts require brackets")
	} else if ip, err := netip.ParseAddr(host); err == nil {
		if !ip.Is4() {
			return nil, fmt.Errorf("invalid IP host")
		}
	} else {
		dns := strings.TrimSuffix(host, ".")
		if len(dns) == 0 || len(dns) > 253 || strings.Trim(dns, "0123456789.") == "" {
			return nil, fmt.Errorf("invalid DNS or IPv4 host")
		}
		for _, label := range strings.Split(dns, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return nil, fmt.Errorf("invalid DNS label")
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
					return nil, fmt.Errorf("DNS host must use ASCII letters, digits, and hyphens")
				}
			}
		}
	}
	if strings.HasSuffix(parsed.Host, ":") {
		return nil, fmt.Errorf("URL port is empty")
	}
	if port := parsed.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("URL port must be between 1 and 65535")
		}
	}
	if _, err := url.QueryUnescape(parsed.RawQuery); err != nil {
		return nil, fmt.Errorf("invalid URL query: %w", err)
	}
	return parsed, nil
}
