package wafme0w

import (
	"fmt"
)

const version = "v0.1.6"

const cat = `
             /\_/\           ___
            = o_o =_______    \ \ 
             __^      __(  \.__) )
            <_____>__(_____)____/` + "\n"

const whatIs = `
                Wafme0w ` + version + "\n"
const explain = `
Fast Web Application Firewall Fingerprinting tool`

func PrintBanner() {

	banner := cat + whatIs + explain + "\n\n"
	fmt.Print(banner)
}
