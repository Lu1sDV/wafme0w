package wafme0w

import (
	"context"
	"io"
	"math/rand"
	"net/http"
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

type requestOpts struct {
	Method   string
	Target   string
	Path     string
	Headers  map[string]string
	Params   map[string]string
	Type     string
	PostBody io.Reader
}

// newTypeOptions builds the existing ordered probe catalogue once per target.
// An empty Path means the exact supplied path, not an appended slash.
func newTypeOptions(target string) []requestOpts {
	randomPath := "/" + strconv.Itoa(rand.Intn(900001)+100000) + ".html"
	headersNoUA := make(map[string]string, len(defaultHeaders))
	for key, value := range defaultHeaders {
		headersNoUA[key] = value
	}
	// An explicit empty value suppresses net/http's default wire User-Agent.
	headersNoUA["User-Agent"] = ""
	return []requestOpts{
		{Method: "GET", Target: target, Headers: defaultHeaders, Type: "Normal"},
		{Method: "GET", Target: target, Headers: headersNoUA, Type: "NoUserAgent"},
		{Method: "GET", Target: target, Path: randomPath, Headers: defaultHeaders, Type: "NonExistent"},
		{Method: "GET", Target: target, Params: map[string]string{"p": xssString}, Headers: defaultHeaders, Type: "XssAttack"},
		{Method: "GET", Target: target, Params: map[string]string{"p": xxeString}, Headers: defaultHeaders, Type: "XxeAttack"},
		{Method: "GET", Target: target, Params: map[string]string{"p": lfiString}, Headers: defaultHeaders, Type: "LfiAttack"},
		{Method: "GET", Target: target, Params: map[string]string{"l": lfiString, "d": xssString, "v": sqliString}, Headers: defaultHeaders, Type: "CentralAttack"},
		{Method: "GET", Target: target, Params: map[string]string{"p": sqliString}, Headers: defaultHeaders, Type: "SqliAttack"},
		{Method: "GET", Target: target, Params: map[string]string{"p": rceString}, Headers: defaultHeaders, Type: "RceAttack"},
	}
}

func sendRequests(ctx context.Context, target string, client *http.Client, config Config) []Evidence {
	options := newTypeOptions(target)
	if config.BaselineOnly {
		options = options[:1]
	} else if config.FastMode {
		options = []requestOpts{options[0], options[1], options[6]}
	}
	responses := make([]Evidence, len(options))
	for i, option := range options {
		responses[i].Role = option.Type
	}
	send := func(i int) {
		requestCtx, cancel := context.WithTimeout(ctx, config.RequestTimeout)
		defer cancel()
		responses[i], _ = sendHTTP(requestCtx, options[i], client, config.MaxBodyBytes)
	}
	var pending sync.WaitGroup
	for i := range options {
		if config.FastMode && i != 0 {
			timer := time.NewTimer(requestsDelay)
			select {
			case <-ctx.Done():
				timer.Stop()
			case <-timer.C:
			}
		}
		if ctx.Err() != nil {
			break
		}
		if config.FastMode {
			pending.Add(1)
			go func(i int) {
				defer pending.Done()
				send(i)
			}(i)
		} else {
			send(i)
			if i == 0 && responses[i].StatusCode == 0 {
				responses = responses[:1]
				break
			}
		}
	}
	pending.Wait()
	if err := ctx.Err(); err != nil {
		for i := range responses {
			if responses[i].StatusCode == 0 && responses[i].TransportError == "" {
				responses[i].TransportError = err.Error()
				responses[i].ErrorCode = acquisitionCode(err)
			}
		}
	}
	return responses
}
