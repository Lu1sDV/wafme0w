package wafme0w

import (
	"bytes"
	"encoding/json"
	"math/rand/v2"
	"os"
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"
)

func TestCompileRejectsMalformedCatalogue(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{"no schemas", `[{"name":"broken"}]`},
		{"empty name", `[{"schemas":[{"fingerprints":[{"type":"Content","pattern":"x"}]}]}]`},
		{"duplicate name", `[{"name":"broken","schemas":[{"fingerprints":[{"type":"Content","pattern":"x"}]}]},{"name":"broken","schemas":[{"fingerprints":[{"type":"Content","pattern":"y"}]}]}]`},
		{"empty schema", `[{"name":"broken","schemas":[{}]}]`},
		{"empty OR schema", `[{"name":"broken","schemas":[{"any":true}]}]`},
		{"unknown type", `[{"name":"broken","schemas":[{"fingerprints":[{"type":"Unknown","pattern":"x"}]}]}]`},
		{"empty pattern", `[{"name":"broken","schemas":[{"fingerprints":[{"type":"Content"}]}]}]`},
		{"empty header key", `[{"name":"broken","schemas":[{"fingerprints":[{"type":"Header","header_value":"x"}]}]}]`},
		{"empty header value", `[{"name":"broken","schemas":[{"fingerprints":[{"type":"Header","header_key":"Server"}]}]}]`},
		{"invalid regexp", `[{"name":"broken","schemas":[{"fingerprints":[{"type":"Content","pattern":"["}]}]}]`},
		{"invalid OR after valid fingerprint", `[{"name":"broken","schemas":[{"any":true,"fingerprints":[{"type":"Content","pattern":"x"},{"type":"Content","pattern":"["}]}]}]`},
		{"invalid alternative after valid schema", `[{"name":"broken","schemas":[{"fingerprints":[{"type":"Content","pattern":"x"}]},{"fingerprints":[{"type":"Content","pattern":"["}]}]}]`},
		{"status regexp", `[{"name":"broken","schemas":[{"fingerprints":[{"type":"Status","pattern":"4.."}]}]}]`},
		{"status too small", `[{"name":"broken","schemas":[{"fingerprints":[{"type":"Status","pattern":"99"}]}]}]`},
		{"status too large", `[{"name":"broken","schemas":[{"fingerprints":[{"type":"Status","pattern":"1000"}]}]}]`},
		{"status overflow", `[{"name":"broken","schemas":[{"fingerprints":[{"type":"Status","pattern":"99999999999999999999"}]}]}]`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var wafs []WAF
			if err := json.Unmarshal([]byte(tt.data), &wafs); err != nil {
				t.Fatal(err)
			}
			engine, err := Compile(wafs)
			if err == nil || engine != nil {
				t.Fatalf("published invalid catalogue: %v, %v", engine, err)
			}
		})
	}
}

func TestCompileValidatesHeaderNames(t *testing.T) {
	for _, name := range []string{"", "X Bad", "X:Bad", "X\tBad", "X\r\nBad", "X-Bad\x00", "X-é", "[Xx]-Header"} {
		definitions := []WAF{{Name: "invalid header", Schemas: []Scheme{{FingerPrints: []FingerPrint{{Type: "Header", HeaderKey: name, HeaderValue: "marker"}}}}}}
		if engine, err := Compile(definitions); err == nil || engine != nil {
			t.Fatalf("accepted invalid HTTP header name %q", name)
		}
	}
	name := "!#$%&'*+-.^_`|~012AZaz"
	engine, err := Compile([]WAF{{Name: "token", Schemas: []Scheme{{FingerPrints: []FingerPrint{{Type: "Header", HeaderKey: name, HeaderValue: "marker"}}}}}})
	if err != nil {
		t.Fatal(err)
	}
	got := engine.Classify([]Evidence{{StatusCode: 200, Headers: []Header{{Name: name, Value: "marker"}}}})
	if got.State != Complete || len(got.Matches) != 1 || got.Matches[0].Product != "token" {
		t.Fatalf("valid token header cannot be classified: %+v", got)
	}
}

func TestMatcherRegexpEquivalence(t *testing.T) {
	patterns := []string{
		`plain.text`, `plain\.text`, `^plain\.text`, `plain\.text$`, `\Aplain\.text\z`,
		`(?i)kelvin`, `(?i)^kelvin`, `(?i)kelvin$`, `(?i)^kelvin$`,
		`(?i)s`, `(?i)^s`, `(?i)s$`, `(?i)^s$`,
		`(?i)σ`, `(?i)^σ`, `(?i)σ$`, `(?i)^σ$`,
		`(?i)Äpfel`, `(?i)foo(?-i:BAR)`, `foo(?i:bar)`, `(?i:foo)(?-i:bar)(?i:baz)`,
		`(foo|bar)`, `(?i)[a-z]+`, `[ab]`, `[a]`, `^$`, `^`, `$`,
		`(?m)^foo$`, `(?s)foo.bar`, `\bfoo\b`, `世界`, `^世界$`, `�`,
		`a\+b\[c\]\$`, `(?i)\(k\.s\)`, `(?:foo)`, `(?i)(?:foo)`,
		`(?i)ß`, `(?i)İ`, `\x{212a}`, `\x00`, `(?i)^$`,
		`(?i)µ`, `(?i)ω`, `(?i)Ǆ`, `(?i)ı`,
		`(?i)(optional)?required.*tail`, `(?i)(optional)*required`,
		`(?i)(repeat){0,2}tail`, `(?i)(repeat){2,3}tail`,
		`(?i)(foo|bar)+END`, `(?i)(foo|bar)?`, `(?i)(foo|bar)*`,
		`(?i)(foo){0}`, `(?i)(foo){0,3}`, `(?i)foo.*(?-i:BAR)`,
		`(?i)K.*ſ`, `(?i)�.*required`, `(?i)foo\bbar`, `(?m)^foo.*bar$`,
		`(?i)(alpha.*tail|beta.+suffix)`, `(?i)(alpha.*tail|(?:beta)?)`,
		`(?i)(alpha.*tail|beta.+suffix){0,2}END`, `(?i)(alpha.*tail|beta.+suffix){2,3}`,
		`(?i)(Kelvin.*ſuffix|ſuffix.+Kelvin)`, `(?i)left(?-i:UPPER)|right.*lower`,
		`(?i)^prefix kelvin σ s suffix$`, `(?i)^prefix世界suffix$`,
		`(?i)prefix�.*kelvin.*suffix`, `(?i)^�kelvin�$`,
		`(?i)(alpha.*tail|beta.+suffix)(gamma|delta)`,
		`(?i)([0-9]+|alpha.*tail)`, `(?i)(alpha.*tail|[0-9]+)`,
		`(?i)(�|alpha.*tail)`, `(?i)(alpha.*tail|�)`,
		`(?i)(alpha|beta){0,2}.*(gamma|delta)`,
		`(?i)(alpha.*a|bravo.*b|charlie.*c|delta.*d|echo.*e|foxtrot.*f|golf.*g|hotel.*h|india.*i|` +
			`juliet.*j|kilo.*k|lima.*l|mike.*m|november.*n|oscar.*o|papa.*p|quebec.*q)`,
		`(?i)\bkelvin.*s\b`, `(?i)\Bkelvin.*s\B`, `(?i)^k.s$`,
		`(?i)foo(?-i:[A-Z])bar`, `(?i)foo(?-i:[Σ-Ω])bar`, `(?i)foo(?-i:[^k])bar`,
		`(?i)k*[0-9]`,
	}
	samples := []string{
		"", "plain.text", "xplain.text", "plain.textx", "plainXtext", "plain.text\n", "\nplain.text",
		"kelvin", "KELVIN", "Kelvin", "xKELVIN", "KELVINx", "xKELVINx", "KELVIN\n",
		"s", "S", "ſ", "xſ", "ſx", "xſx", "σ", "Σ", "ς", "xς", "ςx", "xςx",
		"ÄPFEL", "äpfel", "fooBAR", "FOOBAR", "FOObar", "foobar", "FOObarBAZ", "FOOBARBAZ",
		"bar", "a", "b", "foo\nbar", "x\nfoo\nx", "世界", "x世界x", "世界\n", "a+b[c]$",
		"(K.ſ)", "(k.s)", "ß", "ẞ", "ss", "İ", "i", "ı", "�", "\xff", "x\xffy", "\x00", "x\x00y",
		"µ", "Μ", "μ", "ω", "Ω", "Ω", "Ǆ", "ǅ", "ǆ",
		"requiredtail", "OPTIONALrequired tail", "tail", "REPEATrepeatTAIL",
		"barEND", "FOOfoofoo", "K S", "K ſ", "\xff REQUIRED", "fooBAR", "foo bar",
		"ab bc", "prefix kelvin suffix", "Kx ſy", "\xfffoo\x00BAR",
		"ALPHA tail", "beta-suffix", "alpha suffix", "ALPHA tailbeta-suffix", "END",
		"Kelvin ſuffix", "ſuffix x KELVIN", "LEFTUPPER", "LEFTupper", "RIGHT lower",
		"prefix Kelvin ς ſ suffix", "prefix kelvin Σ s suffix", "PREFIX KELVIN ς ſ SUFFIX",
		"PREFIX世界SUFFIX", "prefix世界suffix", "prefix\xffKelvin suffix", "PREFIX�kelvin SUFFIX",
		"\xffKELVIN\xff", "�Kelvin�", "kelvin\xef\xbf", "\xef\xbfkelvin",
		"ALPHA tailGAMMA", "beta-xsuffixDELTA", "123", "alpha tail", "GAMMA", "alpha beta DELTA",
		"ALPHA a", "QUEBEC--q",
		"KELVIN ſ", "KELVIN S", "Kxſ", "fooZbar", "foozbar", "FOOΣBAR", "FOOσBAR",
		"fooKbar", "fookbar", "K7", "K7",
	}
	for _, pattern := range patterns {
		matcher, err := compileFingerprint(FingerPrint{Type: "Content", Pattern: pattern})
		if err != nil {
			t.Fatalf("%q: %v", pattern, err)
		}
		oracle := regexp.MustCompile(pattern)
		for _, sample := range samples {
			if got, want := matcher.match(sample), oracle.MatchString(sample); got != want {
				t.Errorf("pattern %q sample %q: got %v, want %v", pattern, sample, got, want)
			}
			folded := foldBytes([]byte(sample))
			mask := contentMask(folded)
			response := responseData{body: []byte(sample), foldedBody: folded, bodyMask: mask, bodyFilter: true}
			if got, want := matcher.matchBody(&response), oracle.MatchString(sample); got != want {
				t.Errorf("filtered pattern %q sample %q: got %v, want %v", pattern, sample, got, want)
			}
		}
		for _, count := range []int{1, 16} {
			definitions := make([]WAF, count)
			for i := range definitions {
				definitions[i] = WAF{Name: string(rune('A' + i)), Schemas: []Scheme{{FingerPrints: []FingerPrint{{Type: "Content", Pattern: pattern}}}}}
			}
			engine, err := Compile(definitions)
			if err != nil {
				t.Fatal(err)
			}
			for _, sample := range samples {
				want := 0
				if oracle.MatchString(sample) {
					want = count
				}
				outcome := engine.Classify([]Evidence{{StatusCode: 200, Body: []byte(sample)}})
				if outcome.State != Complete || len(outcome.Matches) != want {
					t.Errorf("prepared content %q sample %q: got %+v, want %d matches", pattern, sample, outcome, want)
				}
			}
		}
	}
}

func TestFoldBytesPreservesCallerStorage(t *testing.T) {
	for _, test := range []struct {
		name  string
		input string
		want  string
	}{
		{"unchanged ASCII", "ordinary response", "ordinary response"},
		{"unchanged Unicode", "世界�", "世界�"},
		{"first-byte fold", "ORDINARY response", "ordinary response"},
		{"late fold", "ordinary RESPONSE", "ordinary response"},
		{"simple-fold orbits", "Kσſ", "kΣs"},
		{"malformed UTF-8", "ordinary \xff\xef\xbf", "ordinary ���"},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := []byte(test.input)
			folded := foldBytes(body)
			if string(folded) != test.want {
				t.Fatalf("folded %q: got %q, want %q", body, folded, test.want)
			}
			if !bytes.Equal(body, []byte(test.input)) {
				t.Fatalf("folding mutated caller body: %q", body)
			}
			if test.input == test.want {
				if &folded[0] != &body[0] {
					t.Fatal("unchanged body was copied")
				}
			} else {
				folded[0] ^= 1
				if !bytes.Equal(body, []byte(test.input)) {
					t.Fatal("changed folded body aliases caller storage")
				}
			}
		})
	}
}

func TestMatcherMandatoryGuardEquivalence(t *testing.T) {
	patterns := []string{
		`(?i)lengthy-prefix.*tail`,
		`(?i)lengthy-prefix.*(tail|ending)`,
		`(?i)(lengthy-prefix.*tail|other-prefix.+ending).*finish`,
		`(?i)(lengthy-prefix.*tail|[0-9]+).*finish`,
		`(?i)(lengthy-prefix.*tail)?finish`,
		`(?i)(lengthy-prefix.*tail){0,2}finish`,
		`(?i)(lengthy-prefix.*tail){2,3}finish`,
		`(?i)^lengthy-prefix.*tail$`,
		`(?i)\blengthy-prefix.*tail\b`,
		`(?i)\Blengthy-prefix.*tail\B`,
		`(?i)lengthy-prefix.*(?-i:UPPER).*tail`,
		`(?i)lengthy-prefix.*�.*tail`,
		`(?i)Kelvin.*ſuffix.*ς`,
		strings.Repeat(`(?i)segment.*`, 18) + `end`,
		`(?i)(` + strings.Join([]string{
			"one", "two", "three", "four", "five", "six", "seven", "eight", "nine",
			"ten", "eleven", "twelve", "thirteen", "fourteen", "fifteen", "sixteen", "seventeen",
		}, "|") + `).*finish`,
	}
	samples := []string{
		"", "lengthy-prefix", "tail", "tail lengthy-prefix", "lengthy-prefixTAIL",
		"lengthy-prefix ending", "lengthy-prefix other tail finish",
		"other-prefix ending finish", "other-prefix ending", "123finish", "finish",
		"lengthy-prefix tail lengthy-prefix tail finish", "lengthy-prefix UPPER tail",
		"lengthy-prefix upper tail", "lengthy-prefix\xffTAIL", "lengthy-prefix�TAIL",
		"lengthy-prefix tail\n", "xlengthy-prefix tailx", "ſeventeen finish",
		"KELVIN ſUFFIX Σ", "kelvin suffix ς", "\xfflengthy-prefix tail\xff",
		strings.Repeat("lengthy-prefix ", 1024),
		strings.Repeat("lengthy-prefix ", 1024) + "TAIL",
		strings.Repeat("segment ", 18) + "end",
	}
	for _, pattern := range patterns {
		t.Run(pattern, func(t *testing.T) {
			matcher, err := compileFingerprint(FingerPrint{Type: "Content", Pattern: pattern})
			if err != nil {
				t.Fatal(err)
			}
			oracle := regexp.MustCompile(pattern)
			for _, sample := range samples {
				body := []byte(sample)
				folded := foldBytes(body)
				mask := contentMask(folded)
				for _, indexed := range []bool{false, true} {
					response := responseData{body: body, foldedBody: folded, bodyMask: mask, bodyFilter: true, allowIndex: indexed}
					if indexed {
						response.bodyQuadgrams = newQuadgramFilter(folded)
					}
					if got, want := matcher.matchBody(&response), oracle.Match(body); got != want {
						t.Fatalf("indexed=%t, body %q: got %t, want %t", indexed, sample, got, want)
					}
				}
			}
		})
	}
}

func TestContentFilterSaturation(t *testing.T) {
	var diverse strings.Builder
	for first := byte(32); first < 127; first++ {
		for second := byte(32); second < 127; second++ {
			diverse.WriteByte(first)
			diverse.WriteByte(second)
		}
	}
	base := diverse.String()
	const literal = "kelvin sentinel"
	var separated []string
	for i := 3; i < len(literal); i++ {
		separated = append(separated, literal[i-3:i+1])
	}
	definitions := make([]WAF, 33)
	for i := range 32 {
		definitions[i] = WAF{Name: string(rune('A' + i)), Schemas: []Scheme{{FingerPrints: []FingerPrint{{Type: "Content", Pattern: `(?i)definitely absent fingerprint`}}}}}
	}
	for _, pattern := range []string{`(?i)kelvin sentinel`, `(?i)(absent alternative.*tail|kelvin.*sentinel)`, `(?i)abc`, `(?i)abcd`, `(?i)Kſx`, `(?i)Kſxy`} {
		definitions[32] = WAF{Name: "target", Schemas: []Scheme{{FingerPrints: []FingerPrint{{Type: "Content", Pattern: pattern}}}}}
		engine, err := Compile(definitions)
		if err != nil {
			t.Fatal(err)
		}
		oracle := regexp.MustCompile(pattern)
		for _, bodies := range [][]string{
			{base},
			{base + " KELVIN ſENTINEL"},              // A trailing hit after many misses.
			{base + strings.Join(separated, "\x00")}, // All four-byte fragments, but no literal.
			{base + " sentinel"},                     // A regexp guard alone is not a match.
			{base + " KELVIN", base + " ſENTINEL"},   // Never join separate bodies.
			{base, base + " KELVIN ſENTINEL"},
			{base + " ABCD KſXY"}, // Three/four-byte literals after folding.
		} {
			evidence := make([]Evidence, len(bodies))
			wantEvidence := -1
			for i, body := range bodies {
				evidence[i] = Evidence{StatusCode: 200, Body: []byte(body)}
				if wantEvidence == -1 && oracle.MatchString(body) {
					wantEvidence = i
				}
			}
			outcome := engine.Classify(evidence)
			wantMatches := 0
			if wantEvidence != -1 {
				wantMatches = 1
			}
			if outcome.State != Complete || len(outcome.Matches) != wantMatches {
				t.Fatalf("saturated content %q: got %+v, want %d matches", pattern, outcome, wantMatches)
			}
			if wantEvidence != -1 {
				got := outcome.Matches[0]
				want := FingerprintMatch{Fingerprint: 1, Evidence: wantEvidence}
				if got.Product != "target" || len(got.Fingerprints) != 1 || got.Fingerprints[0] != want {
					t.Fatalf("saturated content %q: got %+v, want target witness %+v", pattern, got, want)
				}
			}
		}
	}
}

func TestBundledPatterns(t *testing.T) {
	data, err := os.ReadFile("../../cmd/wafme0w/resources/waf-fingerprints.json")
	if err != nil {
		t.Fatal(err)
	}
	var wafs []WAF
	if err := json.Unmarshal(data, &wafs); err != nil {
		t.Fatal(err)
	}
	common := []string{"", "ordinary response", "403 Forbidden", "\n", "\x00", "KſΣσς", "世界", "\xff"}
	random := rand.New(rand.NewPCG(1, 2))
	alphabet := []rune("abcXYZ019-_=<> /\nKſΣσς世界")
	for range 64 {
		var sample strings.Builder
		for range random.IntN(80) {
			sample.WriteRune(alphabet[random.IntN(len(alphabet))])
		}
		common = append(common, sample.String())
	}
	counts := map[string]int{"literal": 0, "regex": 0, "status": 0}
	folded, schemas, total := 0, 0, 0
	for _, waf := range wafs {
		schemas += len(waf.Schemas)
		for si, schema := range waf.Schemas {
			for fi, fp := range schema.FingerPrints {
				total++
				matcher, err := compileFingerprint(fp)
				if err != nil {
					t.Fatalf("%s schema %d fingerprint %d: %v", waf.Name, si+1, fi+1, err)
				}
				if fp.Type == "Status" {
					counts["status"]++
					// Status matching is integer equality, not substring matching.
					// Audit its textual pattern independently against the regexp oracle.
					matcher, err = compileFingerprint(FingerPrint{Type: "Content", Pattern: fp.Pattern})
					if err != nil {
						t.Fatal(err)
					}
				} else if matcher.regex != nil {
					counts["regex"]++
				} else {
					counts["literal"]++
					if matcher.fold {
						folded++
					}
				}
				pattern := matcher.pattern
				if fp.Type == "Reason" {
					pattern = `\A` + regexp.QuoteMeta(pattern) + `\z`
				}
				oracle := regexp.MustCompile(pattern)
				expression, err := syntax.Parse(pattern, syntax.Perl)
				if err != nil {
					t.Fatal(err)
				}
				samples := append([]string(nil), common...)
				for seed := range 12 {
					witness := patternSample(expression, seed)
					samples = append(samples, witness, strings.ToLower(witness), strings.ToUpper(witness),
						"prefix "+witness, witness+" suffix", "prefix "+witness+" suffix", witness+"\n",
						strings.NewReplacer("K", "K", "k", "K", "S", "ſ", "s", "ſ", "σ", "ς").Replace(witness))
				}
				for _, sample := range samples {
					if got, want := matcher.match(sample), oracle.MatchString(sample); got != want {
						t.Fatalf("%s schema %d fingerprint %d, %q on %q: got %v, want %v", waf.Name, si+1, fi+1, matcher.pattern, sample, got, want)
					}
					folded := foldBytes([]byte(sample))
					mask := contentMask(folded)
					response := responseData{body: []byte(sample), foldedBody: folded, bodyMask: mask, bodyFilter: true}
					if got, want := matcher.matchBody(&response), oracle.MatchString(sample); got != want {
						t.Fatalf("%s schema %d fingerprint %d, prepared body %q on %q: got %v, want %v", waf.Name, si+1, fi+1, matcher.pattern, sample, got, want)
					}
				}
			}
		}
	}
	t.Logf("%d WAFs, %d schemas, %d fingerprints: %d literal (%d Unicode-folded), %d status, %d regex", len(wafs), schemas, total, counts["literal"], folded, counts["status"], counts["regex"])
}

// patternSample provides deterministic varied witnesses, not an exhaustive
// regexp generator. Oracle comparison also covers misses and boundary mutations.
func patternSample(node *syntax.Regexp, seed int) string {
	switch node.Op {
	case syntax.OpLiteral:
		return string(node.Rune)
	case syntax.OpCharClass:
		return string(node.Rune[seed%len(node.Rune)])
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return []string{"a", "0", "界"}[seed%3]
	case syntax.OpCapture:
		return patternSample(node.Sub[0], seed)
	case syntax.OpConcat:
		var result strings.Builder
		for _, child := range node.Sub {
			result.WriteString(patternSample(child, seed))
		}
		return result.String()
	case syntax.OpAlternate:
		return patternSample(node.Sub[seed%len(node.Sub)], seed)
	case syntax.OpQuest, syntax.OpStar:
		return strings.Repeat(patternSample(node.Sub[0], seed), seed%2)
	case syntax.OpPlus:
		return strings.Repeat(patternSample(node.Sub[0], seed), 1+seed%2)
	case syntax.OpRepeat:
		count := node.Min
		if node.Max < 0 || count < node.Max {
			count += seed % 2
		}
		return strings.Repeat(patternSample(node.Sub[0], seed), count)
	default:
		return ""
	}
}

// FuzzMatcherRegexpEquivalence checks optimizations against the standard-library
// regexp oracle, including malformed UTF-8 and rejection-only body indexes.
func FuzzMatcherRegexpEquivalence(f *testing.F) {
	for _, seed := range [][2]string{
		{`(?i)kelvin`, "KELVIN"},
		{`(?i)^�kelvin�$`, "\xffKELVIN\xff"},
		{`(?i)(alpha.*tail|beta.+suffix)`, "BETA--SUFFIX"},
		{`(?i)foo(?-i:[A-Z])bar`, "FOOZBAR"},
		{`(?m)^foo$`, "before\nfoo\nafter"},
		{`(?i)k*[0-9]`, "K7"},
		{`(?i)kelvin sentinel`, strings.Repeat("ordinary ", 512) + "Kelvin sentinel"},
		{`^$`, ""},
	} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, pattern, body string) {
		if pattern == "" || len(pattern) > 256 || len(body) > 16<<10 {
			return
		}
		oracle, err := regexp.Compile(pattern)
		if err != nil {
			return
		}
		matcher, err := compileFingerprint(FingerPrint{Type: "Content", Pattern: pattern})
		if err != nil {
			t.Fatalf("valid regexp %q rejected: %v", pattern, err)
		}
		want := oracle.MatchString(body)
		if got := matcher.match(body); got != want {
			t.Fatalf("pattern %q on %q: got %v, want %v", pattern, body, got, want)
		}
		folded := foldBytes([]byte(body))
		for _, indexed := range []bool{false, true} {
			response := responseData{body: []byte(body), foldedBody: folded, bodyMask: contentMask(folded), bodyFilter: true, allowIndex: indexed}
			if indexed {
				response.bodyQuadgrams = newQuadgramFilter(folded)
			}
			if got := matcher.matchBody(&response); got != want {
				t.Fatalf("pattern %q on %q, indexed=%t: got %v, want %v", pattern, body, indexed, got, want)
			}
		}
	})
}

var benchmarkMatches int
var benchmarkMatcher *fingerprintMatcher
var benchmarkRegexp *regexp.Regexp

var matcherBenchmarkPatterns = []struct {
	name    string
	pattern string
}{
	{"case_sensitive_literal", `blocked by firewall`},
	{"folded_literal", `(?i)blocked by firewall`},
	{"escaped_literal", `(?i)firewall\.example\.com`},
	{"anchored_unicode", `(?i)^kelvin σ s$`},
	{"complex_regexp", `(?i)(blocked|denied).{0,20}firewall`},
}

func BenchmarkPreparedMatching(b *testing.B) {
	inputs := []string{
		"blocked by firewall", "BLOCKED BY FIREWALL", "firewall.example.com", "FIREWALL.EXAMPLE.COM",
		"KELVIN ς ſ", "denied by firewall", "welcome", strings.Repeat("ordinary multibyte 世界 response ", 64),
	}
	for _, fixture := range matcherBenchmarkPatterns {
		b.Run(fixture.name, func(b *testing.B) {
			prepared, err := compileFingerprint(FingerPrint{Type: "Content", Pattern: fixture.pattern})
			if err != nil {
				b.Fatal(err)
			}
			compiled := regexp.MustCompile(fixture.pattern)
			// All three match the same strings; preparation is excluded here.
			b.Run("prepared", func(b *testing.B) {
				b.ReportAllocs()
				matches := 0
				for range b.N {
					for _, input := range inputs {
						if prepared.match(input) {
							matches++
						}
					}
				}
				benchmarkMatches = matches
			})
			b.Run("precompiled_regexp", func(b *testing.B) {
				b.ReportAllocs()
				matches := 0
				for range b.N {
					for _, input := range inputs {
						if compiled.MatchString(input) {
							matches++
						}
					}
				}
				benchmarkMatches = matches
			})
			b.Run("legacy_compile_each_match", func(b *testing.B) {
				b.ReportAllocs()
				matches := 0
				for range b.N {
					for _, input := range inputs {
						matched, err := regexp.MatchString(fixture.pattern, input)
						if err != nil {
							b.Fatal(err)
						}
						if matched {
							matches++
						}
					}
				}
				benchmarkMatches = matches
			})
		})
	}
}

func BenchmarkFingerprintCompilation(b *testing.B) {
	for _, fixture := range matcherBenchmarkPatterns {
		b.Run(fixture.name, func(b *testing.B) {
			b.Run("prepared", func(b *testing.B) {
				b.ReportAllocs()
				for range b.N {
					matcher, err := compileFingerprint(FingerPrint{Type: "Content", Pattern: fixture.pattern})
					if err != nil {
						b.Fatal(err)
					}
					benchmarkMatcher = matcher
				}
			})
			b.Run("regexp", func(b *testing.B) {
				b.ReportAllocs()
				for range b.N {
					compiled, err := regexp.Compile(fixture.pattern)
					if err != nil {
						b.Fatal(err)
					}
					benchmarkRegexp = compiled
				}
			})
		})
	}
}
