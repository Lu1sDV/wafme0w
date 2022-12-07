package wafme0w

import (
	"compress/flate"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

var defaultHeaders = map[string]string{
	"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
	"Accept-Encoding":           "gzip, deflate",
	"Accept-Language":           "en-US,en;q=0.9",
	"DNT":                       "1", // Do Not Track request header
	"User-Agent":                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36",
	"Upgrade-Insecure-Requests": "1",
	"Referer":                   "https://www.google.com/",
}

const timeOut = 5 * time.Second

type RequestResponse struct {
	Target string
	Type   string
	Data   *http.Response
	Body   []byte
	Error  error
}

type HTTPRequest struct {
	Options RequestOpts
	Client  http.Client
}

type RequestOpts struct {
	Method   string
	Target   string
	Path     string
	Headers  map[string]string
	Params   map[string]string
	Type     string
	PostBody io.Reader
}

func NewRequestOpts() RequestOpts {
	return RequestOpts{Method: "GET",
		Target:   "https://example.com",
		Path:     "/",
		Params:   nil,
		Headers:  defaultHeaders,
		Type:     "normal",
		PostBody: nil}
}

func NewHTTPRequest(options RequestOpts, client http.Client) HTTPRequest {
	return HTTPRequest{Options: options, Client: client}
}

func NewHTTPClient() http.Client {
	return http.Client{
		Timeout: timeOut,
	}
}

func (h HTTPRequest) Send() (response RequestResponse, err error) {
	var reader io.ReadCloser
	endPoint := h.Options.Target + h.Options.Path

	if len(h.Options.Params) != 0 {
		baseUrl, err := url.Parse(endPoint)
		if err != nil {
			return RequestResponse{}, fmt.Errorf("error parsing endpoint. %w", err)
		}

		params := url.Values{}

		for param, value := range h.Options.Params {
			params.Add(param, value)
		}
		baseUrl.RawQuery = params.Encode()
		endPoint = baseUrl.String()
	}

	req, err := http.NewRequest(h.Options.Method, endPoint, h.Options.PostBody)
	if err != nil {
		return RequestResponse{}, fmt.Errorf("error creating request: %w", err)
	}

	//set headers
	for header, value := range h.Options.Headers {
		req.Header.Set(header, value)
	}

	resp, err := h.Client.Do(req)
	if err != nil {
		return RequestResponse{}, fmt.Errorf("error sending request to endpoint. %w", err)
	}
	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		reader, err = gzip.NewReader(resp.Body)
		if err != nil {
			return RequestResponse{}, fmt.Errorf("error reading body: %w", err)
		}
	case "deflate":
		reader = flate.NewReader(resp.Body)
	default:
		reader = resp.Body
	}

	body, err := io.ReadAll(reader)

	if err != nil {
		return RequestResponse{}, fmt.Errorf("error reading body: %w", err)
	}
	defer reader.Close()

	return RequestResponse{Target: h.Options.Target, Data: resp, Body: body}, nil
}
