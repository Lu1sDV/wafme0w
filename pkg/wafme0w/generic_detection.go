package wafme0w

import (
	"fmt"
	strutil "github.com/Lu1sDV/wafme0w/pkg/utils/strings"
	"strings"
)

var genericWAFHeaders = []string{"X-WAF-Protection",
	"X-Web-Application-Firewall"}

type GenericDetection struct {
	Reason                string
	Mode                  GenericDetectionMode
	BeforeStatus          int
	AfterStatus           int
	BeforeHeader          string
	AfterHeader           string
	RequestType           string
	GenericWAFHeader      string
	GenericWAFHeaderValue string
}

type GenericDetectionMode int

const (
	ChangeInHeader GenericDetectionMode = iota
	ChangeInStatus
	WAFHeaderDetected
)

func (g GenericDetectionMode) String() string {
	return [...]string{"header changed",
		"status changed",
		"generic WAF header detected"}[g]
}

func (g *GenericDetection) generateReason() {

	var tmplTxt string

	//prettify RequestType for output
	//eg. From XssAttack to Xss Attack
	splitRequestType := strutil.SplitAtUpperCases(g.RequestType)
	prettyRequestType := strings.Join(splitRequestType, " ")

	switch g.Mode {
	case ChangeInHeader:
		tmplTxt = fmt.Sprintf(`The server header is different when the following request was tried: %s
Normal Server header is: "%s" while response's header is: "%s"`, prettyRequestType, g.BeforeHeader, g.AfterHeader)

	case ChangeInStatus:
		tmplTxt = fmt.Sprintf(`Server returned a different response when the following request was tried: %s
Normal response code is "%d" while response's status code is "%d"`, prettyRequestType, g.BeforeStatus, g.AfterStatus)

	case WAFHeaderDetected:
		tmplTxt = fmt.Sprintf(`The Web Application has a Generic WAF header when the following request was tried: %s
The header is: "%s" and its value is: "%s"`, prettyRequestType, g.GenericWAFHeader, g.GenericWAFHeaderValue)

	}
	g.Reason = tmplTxt
}
