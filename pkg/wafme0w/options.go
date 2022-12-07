package wafme0w

import "io"

type Options struct {
	Inputs           io.Reader
	FingerPrints     io.Reader
	Headers          []string
	StdIn            bool
	Target           string `short:"t" long:"target" description:"Your Web Application target"`
	InputFile        string `short:"I" long:"input" description:"Your input file with a list of targets"`
	OutputFile       string `short:"O" long:"output" description:"Output file, will be JSON CSV or TXT depending on extension"`
	HeadersFile      string `short:"H" long:"headers" description:"File containing custom headers, will replace default ones"`
	FingerPrintFile  string `long:"fingerprints" description:"File containing the JSON-formatted fingerprints"`
	Concurrency      int    `short:"c" long:"concurrency" description:"Number of concurrent workers" default:"20"`
	FastMode         bool   `long:"fast" description:"Enable Fast Mode, blazing fast but less precise. Sends less requests more concurrently"`
	ExcludeGeneric   bool   `long:"no-generic" description:"Exclude generic WAF check"`
	ListWAFS         bool   `long:"list" description:"List all detectable WAFs"`
	Silent           bool   `long:"silent" description:"Enable silent mode to disable console output"`
	NoColors         bool   `long:"no-colors" description:"Disable colored output"`
	SuppressWarnings bool   `long:"no-warning" description:"Suppress console scan warnings"`
	//Verbose         bool   `short:"v" long:"verbose" description:"Show verbose debug information"` TODO
	//Payload         string `long:"payload" description:"Payload to send along with default attack vectors"` TODO

}

func NewOptions() *Options {
	return &Options{}
}
