package wafme0w

import "fmt"

var genericWAFHeaders = []string{"X-WAF-Protection", "X-Web-Application-Firewall"}

type GenericDetection struct {
	Reason                string               `json:"reason,omitempty"`
	Mode                  GenericDetectionMode `json:"mode"`
	BeforeStatus          int                  `json:"before_status,omitempty"`
	AfterStatus           int                  `json:"after_status,omitempty"`
	BeforeHeader          string               `json:"before_header,omitempty"`
	AfterHeader           string               `json:"after_header,omitempty"`
	RequestType           string               `json:"request_type,omitempty"`
	GenericWAFHeader      string               `json:"generic_waf_header,omitempty"`
	GenericWAFHeaderValue string               `json:"generic_waf_header_value,omitempty"`
}

// An empty mode means no generic anomaly was observed.
type GenericDetectionMode string

const (
	ChangeInHeader    GenericDetectionMode = "change_in_header"
	ChangeInStatus    GenericDetectionMode = "change_in_status"
	WAFHeaderDetected GenericDetectionMode = "waf_header_detected"
)

func (g GenericDetectionMode) String() string {
	switch g {
	case "":
		return "none"
	case ChangeInHeader:
		return "header changed"
	case ChangeInStatus:
		return "status changed"
	case WAFHeaderDetected:
		return "generic WAF header detected"
	default:
		return "unknown"
	}
}

func (g *GenericDetection) generateReason() {
	switch g.Mode {
	case ChangeInHeader:
		g.Reason = fmt.Sprintf("Server header changed from %q to %q for %q", g.BeforeHeader, g.AfterHeader, g.RequestType)
	case ChangeInStatus:
		g.Reason = fmt.Sprintf("status changed from %d to %d for %q", g.BeforeStatus, g.AfterStatus, g.RequestType)
	case WAFHeaderDetected:
		g.Reason = fmt.Sprintf("generic marker %q=%q observed for %q", g.GenericWAFHeader, g.GenericWAFHeaderValue, g.RequestType)
	default:
		g.Reason = ""
	}
}
