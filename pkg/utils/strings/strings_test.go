package strutil

import (
	"reflect"
	"testing"
)

func TestStringInSlice(t *testing.T) {
	type args struct {
		str  string
		list []string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{name: "Match", args: args{str: "foo", list: []string{"foo", "bar"}}, want: true},
		{name: "No match", args: args{str: "foo", list: []string{"ez", "bar"}}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := StringInSlice(tt.args.str, tt.args.list); got != tt.want {
				t.Errorf("StringInSlice() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSubStringBetweenDelimiters(t *testing.T) {
	type args struct {
		s               string
		firstDelimiter  string
		secondDelimiter string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{name: "Get \"Bar\" substring", args: args{s: "Foo(Bar)", firstDelimiter: "(", secondDelimiter: ")"}, want: "Bar"},
		{name: "No substring found", args: args{s: "Foo[Bar]", firstDelimiter: "(", secondDelimiter: ")"}, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SubStringBetweenDelimiters(tt.args.s, tt.args.firstDelimiter, tt.args.secondDelimiter); got != tt.want {
				t.Errorf("SubStringBetweenDelimiters() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSplitAtUpperCases(t *testing.T) {
	type args struct {
		str string
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{name: "Split MyString", args: args{str: "MyString"}, want: []string{"My", "String"}},
		{name: "Nothing to split", args: args{str: "alllowercase"}, want: []string{"alllowercase"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SplitAtUpperCases(tt.args.str); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SplitAtUpperCases() = %v, want %v", got, tt.want)
			}
		})
	}
}
