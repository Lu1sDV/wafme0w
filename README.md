
<h1 align="center">
  Wafme0w
</h1>

<h4 align="center">Fast and lightweight Web Application Fingerprinting tool.</h4>

# Features

Based on <a href ="https://github.com/EnableSecurity/wafw00f/">Wafw00f</a>, its features are:

- Concurrent fingerprint
- **STDIN** supported
- Fast detection mode for huge target lists
- Multiple output formats supported (JSON, file, stdout)

# Getting started
## Installation
`wafme0w` requires **go >= 1.19** to install successfully. Run the following command to install the latest version:

```sh
go install -v github.com/Lu1sDV/wafme0w/cmd/wafme0w@latest
```

# Running Wafme0w

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


# Contact

divittorioluis **AT** gmail **DOT** com

Project Link: [https://github.com/Lu1sDV/wafme0w](https://github.com/Lu1sDV/wafme0w)


