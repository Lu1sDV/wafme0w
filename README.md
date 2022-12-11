
<h1 align="center">
  Wafme0w
</h1>

<h4 align="center">Fast and lightweight Web Application Firewall fingerprinting tool.</h4>

# Features

Based on <a href ="https://github.com/EnableSecurity/wafw00f/">Wafw00f</a>, its features are:

- Can detect **153** different Firewalls
- Concurrent fingerprinting
- **STDIN** supported
- Fast detection mode for huge target lists
- Multiple output formats supported (JSON, file, stdout)

# Benchmark

Scanned Alexa top 100 domains. Running on i7-7700K CPU @ 4.20GHz × 4 (8 Threads)

<table role="table">
<thead>
<tr>
<th>tool</th>
<th>flags</th>
<th>Time elapsed</th>
<th>Wafs found</th>
<th>Generic Wafs found</th>
<th>Diff</th>

</tr>
</thead>
<tbody>
<tr>
<td><b>wafme0w</b></td>
<td>--fast --concurrency 30</td>
<td>1min 37s (Best)</td>
<td>20</td>
<td>11</td>
<td>+0%</td>
</tr>
<tr>
<td><b>wafme0w</b></td>
<td>--concurrency 30</td>
<td>3min 51s</td>
<td>22 (Best)</td>
<td>16</td>
<td>+138%</td>
</tr>
<tr>
<td>wafw00f</td>
<td></td>
<td>13min 3s</td>
<td>20</td>
<td>16</td>
<td>+707%</td>
</tr>
<tr>
<td>wafw00f</td>
<td>-a</td>
<td>15min 8s</td>
<td>20</td>
<td>23 (Best)</td>
<td>+836%</td>
</tr>

</tbody>
</table>

# Getting started
## Installation
`wafme0w` requires **go >= 1.19** to install successfully. Run the following command to install the latest version:

```sh
go install -v github.com/Lu1sDV/wafme0w/cmd/wafme0w@latest
```

## Running Wafme0w

To run the tool on a target, just use the following command.

```console
cat /tmp/alexa-top-30.txt | wafme0w --concurrency 30 --no-warning --no-generic


             /\_/\           ___
            = o_o =_______    \ \ 
             __^      __(  \.__) )
            <_____>__(_____)____/

                Wafme0w v1.0.0

Fast Web Application Firewall Fingerprinting tool

[~] https://microsoftonline.com no WAFs have been found
[~] https://reddit.com no WAFs have been found
[+] https://canva.com is behind Cloudflare (Cloudflare Inc.)
[~] https://whatsapp.com no WAFs have been found
[~] https://microsoft.com no WAFs have been found
[~] https://live.com no WAFs have been found
[~] https://163.com no WAFs have been found
[~] https://yandex.ru no WAFs have been found
[~] https://zhihu.com no WAFs have been found
[~] https://taobao.com no WAFs have been found
[~] https://wikipedia.org no WAFs have been found
[~] https://qq.com no WAFs have been found
[~] https://bilibili.com no WAFs have been found
[~] https://bing.com no WAFs have been found
[~] https://vk.com no WAFs have been found
[~] https://facebook.com no WAFs have been found
[~] https://twitch.tv no WAFs have been found
[~] https://google.com no WAFs have been found
[~] https://yahoo.com no WAFs have been found
[~] https://linkedin.com no WAFs have been found
[~] https://twitter.com no WAFs have been found
[~] https://office.com no WAFs have been found
[+] https://zoom.us is behind Cloudflare (Cloudflare Inc.)
[~] https://csdn.net no WAFs have been found
[~] https://github.com no WAFs have been found
[~] https://baidu.com no WAFs have been found
[~] https://netflix.com no WAFs have been found
[+] https://amazon.com is behind Cloudfront (Amazon)
[~] https://instagram.com no WAFs have been found
[~] https://youtube.com no WAFs have been found

```
<table>
<tr>
<td>

## Wafme0w Go library

Usage Example:
```go
package main

import (
"bytes"
"fmt"
"github.com/Lu1sDV/wafme0w/pkg/wafme0w"
"os"
)

func main() {
	targets := []byte("https://google.com\nhttps://paypal.com\n")
	targetsReader := bytes.NewReader(targets)
	/*
	Otherwise you can also load your targets from a file
	targetsReader, err := os.Open("/tmp/alexa-top-20.txt")
	if err != nil {
		panic(err)
	}
	*/
	fingerPrintsFile, err := os.Open("/PATH/TO/wafme0w/cmd/wafme0w/resources/waf-fingerprints.json")
	//fingerprints at https://github.com/Lu1sDV/wafme0w/blob/main/cmd/wafme0w/resources/waf-fingerprints.json 
	opts := &wafme0w.Options{Inputs: targetsReader,
		FingerPrints: fingerPrintsFile,
		Silent:       true,
		Concurrency:  10,
		//FastMode:     true,
		//OutputFile: "myout.json",
	}
	runner := wafme0w.NewRunner(opts)
	result, err := runner.Scan()
	if err != nil {
		panic(err)
	}
	fmt.Printf("%#v\n", result)
}

```
</td>  
</tr>
</table>

# Thanks
People who contributed

[@Fibonaccispiralz](https://github.com/Fibonaccispiralz)

# Contact

divittorioluis **AT** gmail **DOT** com

Project Link: [https://github.com/Lu1sDV/wafme0w](https://github.com/Lu1sDV/wafme0w)


