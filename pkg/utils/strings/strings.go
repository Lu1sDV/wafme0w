package strutil

import "strings"

func SubStringBetweenDelimiters(s string, firstDelimiter string, secondDelimiter string) string {
	i := strings.Index(s, firstDelimiter)
	if i >= 0 {
		j := strings.Index(s, secondDelimiter)
		if j >= 0 {
			return s[i+1 : j]
		}
	}
	return ""
}

func StringInSlice(str string, list []string) bool {
	for _, b := range list {
		if b == str {
			return true
		}
	}
	return false
}
