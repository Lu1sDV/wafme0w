package httputil

import (
	strutils "github.com/Lu1sDV/wafme0w/pkg/utils/strings"
	"net/http"
	"net/url"
	"strings"
)

func ParseURI(uri string) (*url.URL, error) {

	lowerUri := strings.ToLower(uri)
	hasScheme := strings.HasPrefix(lowerUri, "http://") || strings.HasPrefix(lowerUri, "https://")
	if !hasScheme {
		lowerUri = "https://" + lowerUri
	}

	parsed, err := url.ParseRequestURI(lowerUri)
	if err != nil {
		return &url.URL{}, err
	}
	return parsed, nil
}

func IsValidHTTPURL(uri string) bool {
	var allowedSchemes = []string{"http", "https"}

	if uri == "" {
		return false
	}

	splitScheme := strings.Split(uri, "://")
	if len(splitScheme) > 1 {
		scheme := splitScheme[0]
		if !strutils.StringInSlice(scheme, allowedSchemes) {
			return false
		}
	} else {
		uri = "https://" + uri
	}

	_, err := url.ParseRequestURI(uri)
	return err == nil
}

// GetHTTPHeaderByName returns the value of provided header.
// It accepts headers list (http.Header) and header's name
// It returns the value if header is found. Otherwise, returns an empty string
func GetHTTPHeaderByName(headers http.Header, headerName string) string {
	if headerName == "" {
		return ""
	}
	for header, headerValue := range headers {
		if strings.EqualFold(header, headerName) {
			return headerValue[0]
		}
	}
	return ""
}
