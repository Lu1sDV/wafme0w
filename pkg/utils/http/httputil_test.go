package httputil

import (
	"testing"
)

func TestIsValidURI(t *testing.T) {

	tests := []struct {
		name string
		args string
		want bool
	}{
		{"Valid www.google.it", "google.it", true},
		{"Valid localhost", "localhost", true},
		{"Invalid scheme", "wisjj://localhost", false},
		{"Invalid scheme", "ftp://localhost", false},
		{"Invalid empty", "", false},
		//{"InValid url", "!", false},              TODO
		//	{"InValid url", "http:::/not.valid/a//a", false}, TODO
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidHTTPURL(tt.args); got != tt.want {
				t.Errorf("IsValidURI() = %v, want %v", got, tt.want)
			}
		})
	}
}
