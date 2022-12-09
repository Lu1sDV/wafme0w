package wafme0w

import (
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"reflect"
	"strconv"
	"sync"
	"time"
)

const (
	xssString  = "<script>alert(\"XSS\");</script>"
	sqliString = "UNION SELECT ALL FROM information_schema AND ' or SLEEP(5) or '"
	lfiString  = "../../../../etc/passwd"
	rceString  = "/bin/cat /etc/passwd; ping 127.0.0.1; curl google.com"
	xxeString  = "<!ENTITY xxe SYSTEM \"file:///etc/shadow\">]><pwn>&hack;</pwn>"
)

const requestsDelay = 50 * time.Millisecond

var basicRequestsTypes = []string{"Normal", "NoUserAgent", "CentralAttack"}

type RequestOpts struct {
	Method   string
	Target   string
	Path     string
	Headers  map[string]string
	Params   map[string]string
	Type     string
	PostBody io.Reader
}

type RequestTypes struct {
	Normal        RequestOpts
	NoUserAgent   RequestOpts
	NonExistent   RequestOpts
	XssAttack     RequestOpts
	XxeAttack     RequestOpts
	LfiAttack     RequestOpts
	CentralAttack RequestOpts
	SqliAttack    RequestOpts
	RceAttack     RequestOpts
}

func newTypeOptions(target string) RequestTypes {

	//create random path
	rand.Seed(time.Now().UnixNano())
	minInt := 100000
	maxInt := 1000000
	randomInt := rand.Intn(maxInt-minInt+1) + minInt
	randomPath := "/" + strconv.Itoa(randomInt) + ".html"

	headersNoUA := make(map[string]string, 5)
	for key, value := range defaultHeaders {
		if key == "User-Agent" {
			continue
		}
		headersNoUA[key] = value
	}

	var normal = RequestOpts{
		Method:  "GET",
		Target:  target,
		Path:    "/",
		Headers: defaultHeaders,
	}

	var noUserAgent = RequestOpts{
		Method:  "GET",
		Target:  target,
		Path:    "/",
		Headers: headersNoUA,
	}

	var nonExistent = RequestOpts{
		Method:  "GET",
		Target:  target,
		Path:    randomPath,
		Headers: defaultHeaders,
	}
	var xssAttack = RequestOpts{
		Method:  "GET",
		Target:  target,
		Path:    "/",
		Params:  map[string]string{"p": xssString},
		Headers: defaultHeaders,
	}
	var xxeAttack = RequestOpts{
		Method:  "GET",
		Target:  target,
		Path:    "/",
		Params:  map[string]string{"p": xxeString},
		Headers: defaultHeaders,
	}
	var sqliAttack = RequestOpts{
		Method:  "GET",
		Target:  target,
		Path:    "/",
		Params:  map[string]string{"p": sqliString},
		Headers: defaultHeaders,
	}
	var centralAttack = RequestOpts{
		Method: "GET",
		Target: target,
		Path:   "/",
		Params: map[string]string{
			"l": lfiString,
			"d": xssString,
			"v": sqliString,
		},
		Headers: defaultHeaders,
	}
	var lfiAttack = RequestOpts{
		Method:  "GET",
		Target:  target,
		Path:    "/" + lfiString,
		Headers: defaultHeaders,
	}
	var rceAttack = RequestOpts{
		Method:  "GET",
		Target:  target,
		Path:    "/",
		Params:  map[string]string{"p": rceString},
		Headers: defaultHeaders,
	}

	return RequestTypes{
		Normal:        normal,
		NoUserAgent:   noUserAgent,
		NonExistent:   nonExistent,
		XssAttack:     xssAttack,
		XxeAttack:     xxeAttack,
		LfiAttack:     lfiAttack,
		CentralAttack: centralAttack,
		SqliAttack:    sqliAttack,
		RceAttack:     rceAttack,
	}
}

func (t RequestTypes) GetByType(requestType string) (*RequestOpts, error) {
	reqOpts := &RequestOpts{}

	s := reflect.ValueOf(&t).Elem()
	typeField := s.FieldByName(requestType).Addr()

	rv := reflect.ValueOf(&reqOpts).Elem()
	rv.Set(typeField)

	reqOpts.Type = requestType

	return reqOpts, nil
}

func getResponseByType(responses *[]RequestResponse, requestType string) *RequestResponse {
	for _, request := range *responses {
		if request.Type == requestType {
			return &request
		}
	}
	return &RequestResponse{}
}

func sendBasicRequests(target string) []RequestResponse {
	var wg sync.WaitGroup

	client := NewHTTPClient()

	basicRequestsLen := len(basicRequestsTypes)
	responses := make([]RequestResponse, basicRequestsLen)
	wg.Add(basicRequestsLen)

	for i, requestType := range basicRequestsTypes {
		if i != 0 {
			time.Sleep(requestsDelay)
		}
		go func(i int, requestType string) {
			defer wg.Done()
			resp := sendRequest(target, requestType, client)
			if requestType == "Normal" && resp.Data == nil {
				errText := target + " does not seem to be alive"
				err := errors.New(errText)
				resp.Error = err
			}
			responses[i] = resp
		}(i, requestType)
	}

	wg.Wait()
	return responses
}

func sendAllTypesRequests(target string) []RequestResponse {
	var responses []RequestResponse

	client := NewHTTPClient()
	typeOpts := newTypeOptions(target)

	val := reflect.ValueOf(&typeOpts).Elem()

	for i := 0; i < val.NumField(); i++ {
		typeName := val.Type().Field(i).Name
		resp := sendRequest(target, typeName, client)
		if typeName == "Normal" && resp.Data == nil {
			errText := target + " does not seem to be alive"
			err := errors.New(errText)
			resp.Error = err
			responses = []RequestResponse{resp}
			break
		}
		responses = append(responses, resp)
	}

	return responses
}

func sendRequest(target string, requestType string, client http.Client) RequestResponse {
	typeOpts := newTypeOptions(target)
	requestOpts, err := typeOpts.GetByType(requestType)
	if err != nil {
		return RequestResponse{Error: err}
	}
	httpRequest := NewHTTPRequest(*requestOpts, client)

	resp, err := httpRequest.Send()
	if err != nil {
		return RequestResponse{Error: err}
	}
	resp.Type = requestType

	return resp
}

// ConcurrentSendAllTypesRequests TODO may be implemented, very fast, very intrusive
func concurrentSendAllTypesRequests(target string) []RequestResponse {
	var responses []RequestResponse
	var wg sync.WaitGroup

	client := NewHTTPClient()
	typeOpts := newTypeOptions(target)

	val := reflect.ValueOf(&typeOpts).Elem()

	for i := 0; i < val.NumField(); i++ {
		wg.Add(1)
		go func(val reflect.Value, i int) {
			defer wg.Done()
			typeName := val.Type().Field(i).Name
			requestOpts, err := typeOpts.GetByType(typeName)
			if err != nil {
				return
			}
			httpRequest := NewHTTPRequest(*requestOpts, client)

			req, err := httpRequest.Send()
			if err != nil {
				fmt.Println(err)
				return
			}
			req.Type = typeName

			responses = append(responses, req)
		}(val, i)
	}
	wg.Wait()

	return responses
}
