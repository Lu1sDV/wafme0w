package httputil

import (
	strutils "github.com/Lu1sDV/wafme0w/pkg/utils/strings"
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
