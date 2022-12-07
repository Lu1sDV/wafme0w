package wafme0w

import (
	"encoding/json"
	"fmt"
	"github.com/logrusorgru/aurora/v4"
	"strings"
)

func printResult(result Result, au *aurora.Aurora) {
	var wafs []string
	var foundBrackets = "[" + au.Bold(au.BrightGreen("+")).String() + "]"
	var informativeBrackets = "[" + au.Bold(au.BrightBlue("*")).String() + "]"
	var notFoundBrackets = "[" + au.Bold(au.Yellow("~")).String() + "]"
	var colouredTarget = au.BrightCyan(result.Target).Hyperlink(result.Target).String()
	//var line string

	for _, finger := range result.FingerPrint {
		if finger.WafName != "" {
			colouredWafName := au.Bold(au.BrightMagenta(finger.WafName)).String()
			wafs = append(wafs, colouredWafName)
		}
	}

	if len(wafs) > 0 {
		fingerResult := colouredTarget + " is behind " + strings.Join(wafs, " AND ")
		line := foundBrackets + " " + fingerResult
		fmt.Println(line)
	}

	if result.Generic.Reason != "" {
		formattedReason := strings.Replace(result.Generic.Reason, "\n", "\n    ", -1)
		genericResult := foundBrackets + " " + colouredTarget + " seems to be behind a WAF or some sort of security solution"
		genericReason := informativeBrackets + " Reason: " + formattedReason
		line := genericResult + "\n" + genericReason
		fmt.Println(line)
	}

	if len(wafs) == 0 && result.Generic.Reason == "" {
		line := notFoundBrackets + " " + colouredTarget + " no WAFs have been found"
		fmt.Println(line)
	}
}

func prepareJSONOutput(results []Result) ([]byte, error) {
	var validResults []Result
	var jsonOutput []byte

	for _, res := range results {
		if res.Generic.Reason != "" || len(res.FingerPrint) != 0 {
			validResults = append(validResults, res)
		}
	}

	if len(validResults) == 0 {
		return jsonOutput, nil
	}

	jsonOutput, err := json.MarshalIndent(validResults, "", "\t")
	if err != nil {
		return nil, err
	}

	return jsonOutput, nil
}

func prepareTXTOutput(results []Result) []byte {
	var output string
	var emptyGeneric = GenericDetection{}

	for _, res := range results {
		var line = res.Target

		fingerPrintsFound := len(res.FingerPrint)
		var fingerPrints []string

		if fingerPrintsFound == 0 && res.Generic == emptyGeneric {
			continue
		}
		if fingerPrintsFound > 0 {
			for _, f := range res.FingerPrint {
				fingerPrints = append(fingerPrints, f.WafName)
			}
			line = line + ":" + strings.Join(fingerPrints, ", ")
		}

		if res.Generic != emptyGeneric {
			genericNoNewline := strings.Replace(res.Generic.Reason, "\n", " ", -1)
			line = line + ":" + genericNoNewline
		}

		line = line + "\n"
		output = output + line
	}

	return []byte(output)
}

func PrintError(error string, au *aurora.Aurora) {
	var errorBrackets = "[" + au.Bold(au.BrightRed("!!")).String() + "]"
	line := errorBrackets + " " + error
	fmt.Println(line)
}

func PrintWarning(warning string, au *aurora.Aurora) {
	var warningBrackets = "[" + au.Bold(au.BrightYellow("!")).String() + "]"
	line := warningBrackets + " " + warning
	fmt.Println(line)
}

func PrintAllWafs(wafs map[string]string, au *aurora.Aurora) {
	for waf, manufacturer := range wafs {
		colouredWaf := au.Bold(au.BrightMagenta(waf)).String()
		colouredManufacturer := au.BrightCyan(manufacturer).String()

		line := "\t" + colouredWaf + " BY " + colouredManufacturer
		fmt.Println(line)
	}
}
