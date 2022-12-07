package wafme0w

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	httputil "github.com/Lu1sDV/wafme0w/pkg/utils/http"
	strutils "github.com/Lu1sDV/wafme0w/pkg/utils/strings"
	"github.com/logrusorgru/aurora/v4"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type Runner struct {
	Options *Options
	Wafs    []WAF
	Aurora  *aurora.Aurora
}

func NewRunner(options *Options) *Runner {
	return &Runner{Options: options, Aurora: aurora.New(aurora.WithColors(false))}
}

type Result struct {
	Target      string
	FingerPrint []FingerPrintDetection
	Generic     GenericDetection
	Errors      []error
}

func (r *Runner) Scan() ([]Result, error) {
	var results []Result

	if r.Options.InputFile == "" && r.Options.Target == "" && r.Options.Inputs == nil {
		return results, errors.New("no target provided")
	}

	if r.Options.HeadersFile != "" {
		var headers []string
		headersFileName := r.Options.HeadersFile

		headersFile, err := os.Open(headersFileName)
		if err != nil {
			return []Result{}, err
		}

		scanner := bufio.NewScanner(headersFile)
		for scanner.Scan() {
			headers = append(headers, scanner.Text())
		}
		r.Options.Headers = headers
	}

	if err := r.getWAFsFromFingerPrints(); err != nil {
		return []Result{}, err
	}

	if r.Options.Concurrency > 1 {
		//concurrent
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		urls := urlStream(ctx, r.Options.Inputs)

		workers := make([]<-chan Result, r.Options.Concurrency)
		for i := 0; i < r.Options.Concurrency; i++ {
			workers[i] = concurrentScan(ctx, urls, i, &r.Wafs, r.Options)
		}

		for result := range mergeResults(ctx, workers...) {
			if !r.Options.Silent {
				r.outputResult(result)
			}
			results = append(results, result)
		}
	} else {
		//non concurrent
		scanner := bufio.NewScanner(r.Options.Inputs)
		for scanner.Scan() {
			target := scanner.Text()
			result := sequentialFingerPrint(target, r.Wafs, r.Options.FastMode, !r.Options.ExcludeGeneric)
			if !r.Options.Silent {
				r.outputResult(result)
			}
		}
	}

	//Eventually, write results to output
	if r.Options.OutputFile != "" && len(results) > 0 {
		var output []byte
		fileExt := strings.ToLower(filepath.Ext(r.Options.OutputFile))

		if fileExt == ".json" {
			var err error
			output, err = prepareJSONOutput(results)
			if err != nil {
				return []Result{}, err
			}
		} else {
			output = prepareTXTOutput(results)
		}
		if len(output) != 0 {
			err := os.WriteFile(r.Options.OutputFile, output, 0644)
			if err != nil {
				return []Result{}, err
			}
		}
	}
	return results, nil
}

func (r *Runner) getWAFsFromFingerPrints() error {
	var wafs []WAF

	if r.Options.FingerPrints == nil {
		return errors.New("no JSON-formatted fingerprints provided")
	}

	byt, err := io.ReadAll(r.Options.FingerPrints)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(byt, &wafs); err != nil {
		return err
	}
	r.Wafs = wafs
	return nil
}

func (r *Runner) GetAllWAFs() (map[string]string, error) {

	result := make(map[string]string, len(r.Wafs))

	for _, waf := range r.Wafs {
		wafName := strings.Split(waf.Name, " (")[0]
		manufacturer := strutils.SubStringBetweenDelimiters(waf.Name, "(", ")")
		result[wafName] = manufacturer
	}
	return result, nil
}

func (r *Runner) outputResult(result Result) {
	if !r.Options.SuppressWarnings {
		if len(result.Errors) > 0 {
			for _, err := range result.Errors {
				PrintWarning(err.Error(), r.Aurora)
			}
		}
	}
	printResult(result, r.Aurora)
}

func sequentialFingerPrint(target string, wafs []WAF, fastMode bool, withGeneric bool) Result {

	var fingErrors []error
	var responses []RequestResponse
	var generic = GenericDetection{}

	if !httputil.IsValidHTTPURL(target) {
		err := fmt.Errorf("invalid url: %v", target)
		fingErrors = append(fingErrors, err)
		return Result{Target: target, Errors: fingErrors}
	}

	parsedUrl, _ := httputil.ParseURI(target)
	urlNoPath := parsedUrl.Scheme + "://" + parsedUrl.Host

	if fastMode {
		responses = SendBasicRequests(parsedUrl.String())
	} else {
		responses = SendAllTypesRequests(parsedUrl.String())
	}

	for _, resp := range responses {
		if resp.Error != nil {
			fingErrors = append(fingErrors, resp.Error)
		}
	}
	identify := NewIdentifier(responses, wafs)
	results := identify.DoAll()

	if withGeneric {
		generic = identify.GenericDetect()
	}

	return Result{Target: urlNoPath, FingerPrint: results, Generic: generic, Errors: fingErrors}
}

// read urls from buffered file and send them to channel
func urlStream(ctx context.Context, reader io.Reader) <-chan string {

	scanner := bufio.NewScanner(reader)
	stream := make(chan string)
	go func() {
		for scanner.Scan() {
			uri := scanner.Text()
			select {
			case <-ctx.Done():
				return
			case stream <- uri:
			}
		}
		close(stream)
	}()
	return stream
}

func concurrentScan(ctx context.Context, urls <-chan string, workerID int, wafs *[]WAF, options *Options) <-chan Result {

	results := make(chan Result)
	go func() {
		for url := range urls {
			result := sequentialFingerPrint(url, *wafs, options.FastMode, !options.ExcludeGeneric)
			select {
			case <-ctx.Done():
				return
			case results <- result:
			}
		}
		close(results)
	}()
	return results
}

func mergeResults(ctx context.Context, channels ...<-chan Result) <-chan Result {
	var wg sync.WaitGroup

	wg.Add(len(channels))
	outgoingResults := make(chan Result)
	multiplex := func(c <-chan Result) {
		defer wg.Done()
		for i := range c {
			select {
			case <-ctx.Done():
				return
			case outgoingResults <- i:
			}
		}
	}
	for _, c := range channels {
		go multiplex(c)
	}
	go func() {
		wg.Wait()
		close(outgoingResults)
	}()
	return outgoingResults
}
