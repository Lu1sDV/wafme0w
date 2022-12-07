package wafme0w

import (
	"fmt"
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

type GenericDetection struct {
	Reason string
}

type Identify struct {
	Responses []RequestResponse
	Wafs      []WAF
}

func NewIdentifier(responses []RequestResponse, wafs []WAF) *Identify {
	return &Identify{Responses: responses, Wafs: wafs}
}

func (i *Identify) Do() []FingerPrintDetection {
	var fingerPrintPattern string
	var responseHeader string
	var responses = i.Responses
	emptyResponse := &RequestResponse{}
	var results []FingerPrintDetection

	normalResponse := GetResponseByType(&responses, "Normal")
	attackResponse := GetResponseByType(&responses, "CentralAttack")

	if normalResponse.Data == nil || attackResponse.Data == nil {
		return results
	}

WAFSLOOP:
	for _, waf := range i.Wafs {
		for _, schema := range waf.Schemas {
			matchingFingerPrints := 0
			fingerPrintsCount := len(schema.FingerPrints)
			for _, fingerPrint := range schema.FingerPrints {
				response := normalResponse
				if fingerPrint.Attack {
					response = attackResponse
				}

				if response == emptyResponse {
					continue
				}
				switch fingerPrint.Type {
				case "Cookie":
					fingerPrintPattern = fingerPrint.Pattern
					for _, cookie := range response.Data.Cookies() {
						if matched, _ := regexp.MatchString(fingerPrintPattern, cookie.String()); matched {
							//add to waf
							matchingFingerPrints++
							break
						}
					}
				case "Header":
					fingerPrintPattern = fingerPrint.HeaderValue
					responseHeader = response.Data.Header.Get(fingerPrint.HeaderKey)
					if matched, _ := regexp.MatchString(fingerPrintPattern, responseHeader); matched {
						//add to waf
						matchingFingerPrints++
					}
				case "Content":
					if matched, _ := regexp.MatchString(fingerPrint.Pattern, string(response.Body)); matched {
						//add to waf
						matchingFingerPrints++
					}
				case "Status":
					responseStatusCode := response.Data.StatusCode
					fingerPrintStatusCode, err := strconv.Atoi(fingerPrint.Pattern)
					if err != nil {
						continue
					}
					if responseStatusCode == fingerPrintStatusCode {
						matchingFingerPrints++
					}
				case "Reason":
					//TODO
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

func (i *Identify) DoAll() []FingerPrintDetection {
	var fingerPrintPattern string
	var responseHeader string
	var responses = i.Responses
	emptyRequest := &RequestResponse{}
	var results []FingerPrintDetection

	normalResponse := GetResponseByType(&responses, "Normal")
	attackResponse := GetResponseByType(&responses, "CentralAttack")

	if normalResponse.Data == nil || attackResponse.Data == nil {
		return results
	}

WAFSLOOP:
	for _, waf := range i.Wafs {
		for _, schema := range waf.Schemas {
			matchingFingerPrints := 0
			fingerPrintsCount := len(schema.FingerPrints)
		FINGERLOOP:
			for _, fingerPrint := range schema.FingerPrints {
				for _, r := range responses {
					requestName := r.Type
					response := GetResponseByType(&responses, requestName)

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

func (i *Identify) GenericDetect() GenericDetection {

	requests := i.Responses

	normalResponse := GetResponseByType(&requests, "Normal")
	noUAResponse := GetResponseByType(&requests, "NoUserAgent") //no user agent
	xssResponse := GetResponseByType(&requests, "XssAttack")
	sqliResponse := GetResponseByType(&requests, "SqliAttack")
	lfiResponse := GetResponseByType(&requests, "LfiAttack")
	attackResponse := GetResponseByType(&requests, "CentralAttack")

	if normalResponse.Data == nil {
		return GenericDetection{}
	}

	normalStatusCode := normalResponse.Data.StatusCode
	normalServerHeader := normalResponse.Data.Header.Get("Server")

	//detect waf when no User Agent provided
	if noUAResponse.Data != nil {
		noUAStatusCode := noUAResponse.Data.StatusCode
		if normalStatusCode != noUAStatusCode {
			reason := "Server returned a different response when request didn't contain the User-Agent header\n"
			reason = reason + fmt.Sprintf("Normal response code is \"%s\"", strconv.Itoa(normalStatusCode))
			reason = reason + fmt.Sprintf(" while the response code to a modified request is \"%s\"", strconv.Itoa(noUAStatusCode))
			return GenericDetection{Reason: reason}
		}
	}

	if xssResponse.Data != nil {
		xssStatusCode := xssResponse.Data.StatusCode
		if normalStatusCode != xssStatusCode {
			reason := "Server returned a different response when a XSS Attack was tried\n"
			reason = reason + fmt.Sprintf("Normal response code is \"%s\"", strconv.Itoa(normalStatusCode))
			reason = reason + fmt.Sprintf(" while the response code to a Xss attack is \"%s\"", strconv.Itoa(xssStatusCode))
			return GenericDetection{Reason: reason}
		}
	}

	if sqliResponse.Data != nil {
		sqliStatusCode := sqliResponse.Data.StatusCode
		if normalStatusCode != sqliStatusCode {
			reason := "Server returned a different response when a SQLI Attack was tried\n"
			reason = reason + fmt.Sprintf("Normal response code is \"%s\"", strconv.Itoa(normalStatusCode))
			reason = reason + fmt.Sprintf(" while the response code to a SQLI attack is \"%s\"", strconv.Itoa(sqliStatusCode))
			return GenericDetection{Reason: reason}
		}
	}

	if lfiResponse.Data != nil {
		lfiStatusCode := lfiResponse.Data.StatusCode
		if normalStatusCode != lfiStatusCode && lfiStatusCode != 404 {
			reason := "Server returned a different response when a LFI Attack was tried\n"
			reason = reason + fmt.Sprintf("Normal response code is \"%s\"", strconv.Itoa(normalStatusCode))
			reason = reason + fmt.Sprintf(" while the response code to a LFI attack is \"%s\"", strconv.Itoa(lfiStatusCode))
			return GenericDetection{Reason: reason}
		}
	}

	//detect changes in Server header
	if attackResponse.Data != nil {
		attackServerHeader := attackResponse.Data.Header.Get("Server")
		if attackServerHeader != normalServerHeader {
			reason := "The server header is different when an attack is detected.\n"
			reason = reason + fmt.Sprintf("Normal Server header is: \"%s\"", normalServerHeader)
			reason = reason + fmt.Sprintf(" while attack's Server header is: \"%s\"", attackServerHeader)
			return GenericDetection{Reason: reason}
		}
	}

	return GenericDetection{}
}
