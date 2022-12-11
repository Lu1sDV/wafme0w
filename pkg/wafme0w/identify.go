package wafme0w

import (
	httputil "github.com/Lu1sDV/wafme0w/pkg/utils/http"
	"regexp"
	"strconv"
)

type WAF struct {
	Name    string   `json:"name"` //WAF NAME
	Schemas []Scheme `json:"schemas"`
}

type Scheme struct {
	FingerPrints []FingerPrint `json:"fingerprints,omitempty"`
	Any          bool          `json:"any,omitempty"` //If any fingerprint should be present or if all of them
}

type FingerPrint struct {
	Type        string `json:"type,omitempty"`         // Header or Content or Cookie or Status or Reason
	HeaderKey   string `json:"header_key,omitempty"`   // Only for header type
	HeaderValue string `json:"header_value,omitempty"` // Only for header type
	Pattern     string `json:"pattern,omitempty"`      // Fingerprint for other types
	Attack      bool   `json:"attack,omitempty"`
}

type FingerPrintDetection struct {
	WafName string
}

type Identify struct {
	Responses []RequestResponse
	Wafs      []WAF
}

func NewIdentifier(responses []RequestResponse, wafs []WAF) *Identify {
	return &Identify{Responses: responses, Wafs: wafs}
}

// DoAll does WAF fingerprint on all received http responses
func (i *Identify) DoAll() []FingerPrintDetection {
	var fingerPrintPattern string
	var responseHeader string
	var responses = i.Responses
	emptyRequest := &RequestResponse{}
	var results []FingerPrintDetection

WAFSLOOP:
	for _, waf := range i.Wafs {
		for _, schema := range waf.Schemas {
			matchingFingerPrints := 0
			fingerPrintsCount := len(schema.FingerPrints)
		FINGERLOOP:
			for _, fingerPrint := range schema.FingerPrints {
				for _, r := range responses {
					requestName := r.Type
					response := getResponseByType(&responses, requestName)

					if response == emptyRequest {
						continue
					}

					if response.Data == nil {
						continue
					}
					switch fingerPrint.Type {
					case "Cookie":
						fingerPrintPattern = fingerPrint.Pattern
						for _, cookie := range response.Data.Cookies() {
							if matched, _ := regexp.MatchString(fingerPrintPattern, cookie.String()); matched {
								//add to waf
								matchingFingerPrints++
								continue FINGERLOOP
							}
						}

					case "Header":
						fingerPrintPattern = fingerPrint.HeaderValue
						responseHeader = response.Data.Header.Get(fingerPrint.HeaderKey)
						if matched, _ := regexp.MatchString(fingerPrintPattern, responseHeader); matched {
							//add to waf
							matchingFingerPrints++
							continue FINGERLOOP
						}
					case "Content":
						if matched, _ := regexp.MatchString(fingerPrint.Pattern, string(response.Body)); matched {
							//add to waf
							matchingFingerPrints++
							continue FINGERLOOP
						}
					case "Status":
						responseStatusCode := response.Data.StatusCode
						fingerPrintStatusCode, err := strconv.Atoi(fingerPrint.Pattern)
						if err != nil {
							continue
						}
						if responseStatusCode == fingerPrintStatusCode {
							matchingFingerPrints++
							continue FINGERLOOP
						}
					case "Reason":
						//TODO
					}
				}
			}

			if matchingFingerPrints != 0 {
				if !schema.Any {
					//All fingerprints in schema must match
					if matchingFingerPrints != fingerPrintsCount {
						continue
					}
				}
				results = append(results, FingerPrintDetection{WafName: waf.Name})
				continue WAFSLOOP
			}
		}
	}
	return results
}

// GenericDetect detects generic firewall activities
func (i *Identify) GenericDetect() GenericDetection {
	responses := i.Responses
	var detection GenericDetection
	emptyDetection := GenericDetection{}

	normalResponse := getResponseByType(&responses, "Normal")
	if normalResponse.Data == nil {
		return emptyDetection
	}
	normalStatusCode := normalResponse.Data.StatusCode
	normalServerHeader := normalResponse.Data.Header.Get("Server")

OUTERLOOP:
	for _, resp := range responses {
		if resp.Type == "Normal" || resp.Data == nil {
			continue
		}
		responseServerHeader := resp.Data.Header.Get("Server")
		responseStatusCode := resp.Data.StatusCode
		//check if any generic WAF header is thrown
		for _, wafHeader := range genericWAFHeaders {
			headerValue := httputil.GetHTTPHeaderByName(resp.Data.Header, wafHeader)
			if headerValue == "" {
				//header not found
				continue
			}
			detection = GenericDetection{Mode: WAFHeaderDetected,
				GenericWAFHeader:      wafHeader,
				GenericWAFHeaderValue: headerValue,
				RequestType:           resp.Type,
			}
			break OUTERLOOP
		}
		//check if any different status code is thrown
		if normalStatusCode != responseStatusCode {
			//skip not found
			if responseStatusCode == 404 {
				continue
			}
			detection = GenericDetection{Mode: ChangeInStatus,
				BeforeStatus: normalStatusCode,
				AfterStatus:  responseStatusCode,
				RequestType:  resp.Type,
			}
			break OUTERLOOP
		}
		//check any change in Server Header
		if normalServerHeader != responseServerHeader {
			//skip not found
			detection = GenericDetection{Mode: ChangeInHeader,
				BeforeHeader: normalServerHeader,
				AfterHeader:  responseServerHeader,
				RequestType:  resp.Type,
			}
			break OUTERLOOP
		}
	}

	if detection != emptyDetection {
		detection.generateReason()
		return detection
	}
	return emptyDetection
}
