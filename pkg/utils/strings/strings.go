package strutil

import (
	"strings"
	"unicode"
)

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

// SplitAtUpperCases splits a string every time it finds an uppercase
func SplitAtUpperCases(str string) []string {
	var words []string
	l := 0
	for s := str; s != ""; s = s[l:] {
		l = strings.IndexFunc(s[1:], unicode.IsUpper) + 1
		if l <= 0 {
			l = len(s)
		}
		words = append(words, s[:l])
	}
	return words
}
