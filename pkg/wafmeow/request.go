package wafmeow

import (
	"context"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"sync"
)

const (
	xssString  = `"><script>alert("XSS")</script>`
	sqliString = `' OR 1=1 UNION SELECT ALL FROM information_schema AND ' or SLEEP(5) or '-- -"><script>alert("XSS")</script>`
	lfiString  = "../../../../etc/passwd"
	jndiString = `${jndi:ldap://127.0.0.1:1/a}`
	xxeString  = "<!ENTITY xxe SYSTEM \"file:///etc/shadow\">]><pwn>&hack;</pwn>"
)

type requestOpts struct {
	Method         string
	Target         string
	Path           string
	Headers        map[string]string
	ExtraHeaders   []Header
	Params         map[string]string
	Type           string
	PostBody       io.Reader
	evidenceBudget *httpEvidenceBudget
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
		{Method: "GET", Target: target, Params: map[string]string{
			"l":  lfiString,
			"l2": `..\..\..\..\etc\passwd`,
			"d":  xssString,
			"v":  sqliString,
			"c":  ";wafmeow-canary",
			"r":  "\r\nX-Wafmeow: canary",
			"h":  "() { :;};",
		}, Headers: defaultHeaders, Type: "CentralAttack"},
		{Method: "GET", Target: target, Params: map[string]string{"p": jndiString}, Headers: defaultHeaders, Type: "JndiAttack"},
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
	budget := &httpEvidenceBudget{remaining: config.MaxTargetEvidenceBytes, maxHeader: config.MaxResponseHeaderBytes}
	for i, option := range options {
		responses[i].Role = option.Type
		options[i].ExtraHeaders = config.Headers
		options[i].evidenceBudget = budget
	}
	send := func(i int) {
		requestCtx, cancel := context.WithTimeout(ctx, config.RequestTimeout)
		defer cancel()
		responses[i], _ = sendHTTP(requestCtx, options[i], client, config.MaxBodyBytes)
	}
	first, workers := 0, len(options)
	if !config.FastMode {
		// Do not launch active probes against a target with no baseline metadata.
		send(0)
		if responses[0].StatusCode == 0 {
			return responses[:1]
		}
		first, workers = 1, min(config.ProbeConcurrency, len(options)-1)
	}
	if workers <= 1 {
		for i := first; i < len(options) && ctx.Err() == nil; i++ {
			send(i)
		}
	} else {
		var pending sync.WaitGroup
		for worker := range workers {
			pending.Add(1)
			go func() {
				defer pending.Done()
				for i := first + worker; i < len(options) && ctx.Err() == nil; i += workers {
					send(i)
				}
			}()
		}
		pending.Wait()
	}
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
