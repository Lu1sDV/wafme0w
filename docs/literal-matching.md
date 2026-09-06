# Replacing regex with literal matching—without changing the answer

A fingerprint can be written as a regular expression without needing a regular-expression engine for every comparison. An escaped hostname, a fixed header marker, or an exact status code often has a simpler implementation.

The difficult part is not finding a faster primitive. It is proving that the primitive answers the same question. In wafme0w, the boundary is deliberately conservative: recognize a safe subset, preserve its semantics, and retain compiled regex matching for everything else.

## Parse the meaning, not the punctuation

[`compileFingerprint` and `setLiteral`](../pkg/wafme0w/matcher.go#L31-L138) parse textual expressions with Go's `regexp/syntax`. The literal recognizer walks the resulting syntax tree, accepting literal nodes, captures, concatenation, empty matches, and correctly positioned whole-text anchors. It rejects unsupported operators and literal segments with inconsistent case-folding flags.

Consider three small expressions:

| Expression | Meaning and execution |
| --- | --- |
| `plain\.text` | The dot is literal: an exact substring search suffices. |
| `\Aplain\.text\z` | The entire input must equal `plain.text`. |
| `(?m)^plain\.text$` | A matching line inside a larger input is enough: retain regex matching. |

Removing metacharacters from source text cannot distinguish these contracts. Worse, changing `plain.text` into a literal loses the dot's “any non-newline character” behavior. Escaping is syntax, not decoration.

Whole-text anchors become equality, prefix, or suffix checks. In Go, `^` and `$` without multiline mode are whole-text anchors; `(?m)` changes their meaning to line boundaries. The syntax tree records that distinction, so the literal path need not guess from spelling.

Flags also belong to individual syntax nodes. `(?i)foo(?-i:BAR)` accepts case variants of `foo` but requires uppercase `BAR`. Lowercasing the entire expression and input would incorrectly accept `foobar`. This mixed-flag expression stays on the regex path.

Status fingerprints have a separate, typed contract: compilation accepts a three-digit integer from 100 through 999, not a status regex. [`evaluate`](../pkg/wafme0w/identify.go#L292-L331) compares that integer directly with the observed status. For textual patterns outside the literal subset, regexes are compiled during [engine construction](../pkg/wafme0w/identify.go#L83-L131), not for each response comparison.

## Case-insensitive is not “lowercase both sides”

Go regex case-insensitive matching uses Unicode simple folding. That groups `K`, `k`, and the Kelvin sign `K`; `S`, `s`, and long-s `ſ`; and `Σ`, `σ`, and final sigma `ς`. Equivalent runes can even occupy different numbers of UTF-8 bytes, so a folded suffix cannot simply slice the original input using the literal's byte length.

Lowercasing is a different operation. It misses the long-s and final-sigma equivalences, while Go's lowercasing of dotted capital `İ` to `i` merges characters that simple folding keeps separate. The ordinary `I`/`i` orbit, dotted `İ`, and dotless `ı` are distinct under Go's default simple folding; this is not locale-sensitive Turkish casing.

Save this standalone example as `folding.go` and run `go run folding.go`. It prints regex matching beside the naive lowercase comparison; disagreement is the point, not a performance measurement.

```go
package main

import (
    "fmt"
    "regexp"
    "strings"
)

func main() {
    for _, pair := range [][2]string{
        {"K", "K"}, {"S", "ſ"}, {"σ", "ς"}, {"İ", "i"}, {"I", "ı"},
    } {
        literal, input := pair[0], pair[1]
        re := regexp.MustCompile(`(?i)\A` + regexp.QuoteMeta(literal) + `\z`)
        fmt.Printf("%q / %q: regexp=%v lowercase=%v\n",
            literal, input, re.MatchString(input),
            strings.ToLower(literal) == strings.ToLower(input))
    }
}
```

The matcher uses [`unicode.SimpleFold` and `strings.EqualFold`](../pkg/wafme0w/matcher.go#L140-L196) where appropriate. For shared body searches, [`foldText`](../pkg/wafme0w/matcher.go#L299-L355) selects a canonical representative from each simple-fold orbit instead of treating lowercase as canonical.

Malformed UTF-8 needs another guard. Go regex interprets invalid UTF-8 bytes as `RuneError` (U+FFFD); a byte substring search for the encoded replacement character does not. Consequently, literals containing `RuneError` retain regex matching, and required-literal extraction refuses to use them as rejection evidence.

## A filter may reject; it may not declare a match

For repeated body searches, [`matchBody`](../pkg/wafme0w/matcher.go#L211-L282) uses shared byte-pair masks, a lazily constructed four-byte-fragment filter, and conservatively extracted required literals. A missing required fragment can prove a miss. Present fragments cannot prove a hit: hash collisions, wrong ordering, or intervening bytes may still defeat the actual expression.

Every surviving candidate therefore reaches authoritative exact matching: a literal operation or a compiled regex. Some guarded expressions also use a compiled regex over the shared folded body, but only after [`foldContent`](../pkg/wafme0w/matcher.go#L419-L461) accepts the transformation. ASCII word boundaries are rejected there: folding Kelvin or long-s into ASCII changes word membership.

The [matcher tests](../pkg/wafme0w/matcher_test.go#L67-L158) compare optimized paths with Go regex across anchors, mixed flags, Unicode, and malformed inputs. Such equivalence checks defend matcher behavior, not real-world detection accuracy. Performance still depends on the patterns and response data.

[Try wafme0w](https://github.com/Lu1sDV/wafme0w) with the [synthetic offline demo captures](../assets/demo/captures.jsonl). They illustrate saved-response classification without probing a public target—and without pretending synthetic markers establish what a deployed WAF would return.
