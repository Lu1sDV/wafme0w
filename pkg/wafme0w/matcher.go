package wafme0w

import (
	"fmt"
	"net/textproto"
	"regexp"
	"regexp/syntax"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Lu1sDV/wafme0w/internal/httpmeta"
)

type fingerprintMatcher struct {
	typ         string
	pattern     string
	header      string
	status      int
	regex       *regexp.Regexp
	foldedRegex *regexp.Regexp
	literal     string
	required    []string
	mask        [4]uint64
	fold        bool
	start       bool
	end         bool
}

func compileFingerprint(fp FingerPrint) (*fingerprintMatcher, error) {
	m := &fingerprintMatcher{typ: fp.Type, pattern: fp.Pattern}
	switch fp.Type {
	case "Header":
		if !httpmeta.ValidHeaderName(fp.HeaderKey) {
			return nil, fmt.Errorf("invalid HTTP header name %q", fp.HeaderKey)
		}
		m.pattern = fp.HeaderValue
		m.header = textproto.CanonicalMIMEHeaderKey(fp.HeaderKey)
	case "Content", "Cookie", "Reason", "Status":
	default:
		return nil, fmt.Errorf("unsupported fingerprint type %q", fp.Type)
	}
	if m.pattern == "" {
		return nil, fmt.Errorf("empty %s pattern", fp.Type)
	}
	if fp.Type == "Status" {
		status, err := strconv.Atoi(m.pattern)
		if err != nil || len(m.pattern) != 3 || status < 100 || status > 999 {
			return nil, fmt.Errorf("invalid HTTP status %q", m.pattern)
		}
		m.status = status
		return m, nil
	}
	if fp.Type == "Reason" {
		m.literal, m.start, m.end = m.pattern, true, true
		return m, nil
	}
	expression, err := syntax.Parse(m.pattern, syntax.Perl)
	if err != nil {
		return nil, err
	}
	if m.setLiteral(expression) {
		if m.fold {
			m.literal = foldText(m.literal)
		}
		if fp.Type == "Content" && !m.start && !m.end {
			literal := m.literal
			if !m.fold {
				literal = foldText(literal)
			}
			m.mask = contentMask(literal)
		}
		return m, nil
	}
	if fp.Type == "Content" {
		m.required, m.mask = requiredContent(expression)
	}
	m.regex, err = regexp.Compile(m.pattern)
	// Reuse text required by the guard; unguarded regexps can match immediately.
	if err == nil && len(m.required) > 0 && foldContent(expression) {
		m.foldedRegex, err = regexp.Compile(expression.String())
	}
	return m, err
}

// setLiteral accepts only a single literal with optional whole-text anchors.
// Mixed case flags, line anchors and other operators retain Go's regexp engine.
func (m *fingerprintMatcher) setLiteral(expression *syntax.Regexp) bool {
	var literal strings.Builder
	seenLiteral, seenEnd := false, false
	var visit func(*syntax.Regexp) bool
	visit = func(node *syntax.Regexp) bool {
		switch node.Op {
		case syntax.OpCapture:
			return visit(node.Sub[0])
		case syntax.OpConcat:
			for _, child := range node.Sub {
				if !visit(child) {
					return false
				}
			}
			return true
		case syntax.OpEmptyMatch:
			return true
		case syntax.OpBeginText:
			if seenLiteral || seenEnd {
				return false
			}
			m.start = true
			return true
		case syntax.OpEndText:
			m.end, seenEnd = true, true
			return true
		case syntax.OpLiteral:
			fold := node.Flags&syntax.FoldCase != 0
			if seenEnd || (seenLiteral && m.fold != fold) {
				return false
			}
			for _, r := range node.Rune {
				// Regexp treats malformed UTF-8 as RuneError, unlike byte search.
				if r == utf8.RuneError {
					return false
				}
				literal.WriteRune(r)
			}
			m.fold, seenLiteral = fold, true
			return true
		default:
			return false
		}
	}
	if !visit(expression) {
		return false
	}
	m.literal = literal.String()
	return true
}

func (m *fingerprintMatcher) match(value string) bool {
	if m.regex != nil {
		return m.regex.MatchString(value)
	}
	if !m.fold {
		return m.matchLiteral(value)
	}
	if m.start && m.end {
		return strings.EqualFold(value, m.literal)
	}
	if m.end {
		start := len(value)
		for range m.literal {
			if start == 0 {
				return false
			}
			_, size := utf8.DecodeLastRuneInString(value[:start])
			start -= size
		}
		return strings.EqualFold(value[start:], m.literal)
	}
	// ponytail: O(text × literal) folded search; use a linear-time search if profiling warrants it.
	for {
		if foldedPrefix(value, m.literal) {
			return true
		}
		if m.start || value == "" {
			return false
		}
		_, size := utf8.DecodeRuneInString(value)
		value = value[size:]
	}
}

// foldedPrefix follows Unicode simple folding, including K/kelvin, S/long-s
// and both lowercase sigmas; lowercasing alone does not preserve regexp semantics.
func foldedPrefix(value, literal string) bool {
	offset := 0
	for _, want := range literal {
		if offset == len(value) {
			return false
		}
		got, size := utf8.DecodeRuneInString(value[offset:])
		offset += size
		if got == want {
			continue
		}
		fold := unicode.SimpleFold(got)
		for fold != got && fold != want {
			fold = unicode.SimpleFold(fold)
		}
		if fold != want {
			return false
		}
	}
	return true
}

func (m *fingerprintMatcher) matchLiteral(value string) bool {
	switch {
	case m.start && m.end:
		return value == m.literal
	case m.start:
		return strings.HasPrefix(value, m.literal)
	case m.end:
		return strings.HasSuffix(value, m.literal)
	default:
		return strings.Contains(value, m.literal)
	}
}

// Bodies share one folded representation across all rules and witness lookups.
func (m *fingerprintMatcher) matchBody(response *responseData) bool {
	mask := &response.bodyMask
	if response.bodyFilter && (m.mask[0]&^mask[0]|m.mask[1]&^mask[1]|m.mask[2]&^mask[2]|m.mask[3]&^mask[3]) != 0 {
		return false
	}
	if m.regex != nil {
		if len(m.required) > 0 {
			found := false
			for _, literal := range m.required {
				if response.containsFolded(literal) {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
		if m.foldedRegex != nil {
			return m.foldedRegex.MatchString(response.foldedBody)
		}
		return m.regex.MatchString(response.body)
	}
	if m.fold {
		if !m.start && !m.end {
			return response.containsFolded(m.literal)
		}
		return m.matchLiteral(response.foldedBody)
	}
	return m.matchLiteral(response.body)
}

type quadgramFilter [1024]uint64

func quadgramBit(first, second, third, fourth byte) uint32 {
	gram := uint32(first)<<24 | uint32(second)<<16 | uint32(third)<<8 | uint32(fourth)
	return (gram * 0x9e3779b1) >> 16
}

func newQuadgramFilter(value string) *quadgramFilter {
	filter := new(quadgramFilter)
	for i := 3; i < len(value); i++ {
		bit := quadgramBit(value[i-3], value[i-2], value[i-1], value[i])
		filter[bit>>6] |= uint64(1) << (bit & 63)
	}
	return filter
}

func (r *responseData) containsFolded(literal string) bool {
	if !r.allowIndex || len(r.foldedBody) < 4096 || len(literal) < 4 || len(literal) > len(r.foldedBody) {
		return strings.Contains(r.foldedBody, literal)
	}
	// ponytail: only index catalogues eligible for shared filtering, after 8 misses.
	// A qualifying body still costs one 8 KiB allocation; few-rule engines bypass it.
	// Collisions only admit candidates; exact matching still confirms every hit.
	if r.bodyQuadgrams == nil && r.bodyMisses == 8 {
		r.bodyQuadgrams = newQuadgramFilter(r.foldedBody)
	}
	if r.bodyQuadgrams != nil {
		for i := 3; i < len(literal); i++ {
			bit := quadgramBit(literal[i-3], literal[i-2], literal[i-1], literal[i])
			if r.bodyQuadgrams[bit>>6]&(uint64(1)<<(bit&63)) == 0 {
				return false
			}
		}
	}
	matched := strings.Contains(r.foldedBody, literal)
	if !matched && r.bodyMisses < 8 {
		r.bodyMisses++
	}
	return matched
}

// Each adjacent byte pair sets one bit. Collisions only permit extra exact
// searches; a missing bit proves the required folded literal cannot occur.
func contentMask(value string) (mask [4]uint64) {
	for i := 1; i < len(value); i++ {
		pair := uint32(value[i-1])<<8 | uint32(value[i])
		bit := (pair * 0x9e3779b1) >> 24
		mask[bit>>6] |= uint64(1) << (bit & 63)
		if i&63 == 0 && mask[0]&mask[1]&mask[2]&mask[3] == ^uint64(0) {
			break // Saturation makes every query a candidate; no more input is needed.
		}
	}
	return mask
}

// foldText maps each Unicode simple-fold orbit to one rune. Lowercasing alone
// conflates distinct orbits (İ/i) and misses equivalent runes (ſ/S and K/K).
func foldText(value string) string {
	var folded strings.Builder
	// Reuse unchanged text; allocate only at the first changed or malformed rune.
	for index, r := range value {
		mapped := r
		if r < utf8.RuneSelf {
			if r < 'A' || r > 'Z' {
				continue
			}
			mapped += 'a' - 'A'
		} else {
			mapped = foldNonASCII(r)
			if mapped == r && r != utf8.RuneError {
				continue
			}
		}
		_, width := utf8.DecodeRuneInString(value[index:])
		if mapped == r && width != 1 {
			continue
		}
		folded.Grow(len(value) + utf8.UTFMax)
		folded.WriteString(value[:index])
		folded.WriteRune(mapped)
		value = value[index+width:]
		break
	}
	if folded.Cap() == 0 {
		return value
	}
	// Inline ASCII mapping without a callback or repeated allocation checks.
	for _, r := range value {
		if r < utf8.RuneSelf {
			if r >= 'A' && r <= 'Z' {
				r += 'a' - 'A'
			}
			folded.WriteByte(byte(r))
		} else {
			folded.WriteRune(foldNonASCII(r))
		}
	}
	return folded.String()
}

func foldNonASCII(r rune) rune {
	least := r
	for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
		if next < least {
			least = next
		}
	}
	if least >= 'A' && least <= 'Z' {
		least += 'a' - 'A'
	}
	return least
}

// At least one returned folded literal must occur; an empty list cannot reject.
// Sequences select a mandatory child; alternatives retain every branch.
// Byte-pair masks combine sequences by union and alternatives by intersection.
func requiredContent(node *syntax.Regexp) (literals []string, mask [4]uint64) {
	switch node.Op {
	case syntax.OpLiteral:
		for _, r := range node.Rune {
			if r == utf8.RuneError {
				return nil, mask
			}
		}
		literal := foldText(string(node.Rune))
		return []string{literal}, contentMask(literal)
	case syntax.OpCapture, syntax.OpPlus:
		return requiredContent(node.Sub[0])
	case syntax.OpRepeat:
		if node.Min > 0 {
			return requiredContent(node.Sub[0])
		}
	case syntax.OpConcat:
		bestLength := 0
		for _, child := range node.Sub {
			required, childMask := requiredContent(child)
			shortest := 0
			for i, literal := range required {
				if i == 0 || len(literal) < shortest {
					shortest = len(literal)
				}
			}
			if shortest > bestLength {
				literals, bestLength = required, shortest
			}
			for i := range mask {
				mask[i] |= childMask[i]
			}
		}
	case syntax.OpAlternate:
		filterable := true
		for index, child := range node.Sub {
			required, childMask := requiredContent(child)
			// ponytail: cap alternative searches at 16; wider expressions retain regexp.
			if len(required) == 0 || len(literals)+len(required) > 16 {
				filterable = false
			}
			if filterable {
				literals = append(literals, required...)
			}
			if index == 0 {
				mask = childMask
				continue
			}
			for i := range mask {
				mask[i] &= childMask[i]
			}
		}
		if !filterable {
			literals = nil
		}
	}
	return literals, mask
}

// foldContent enables regexp's case-sensitive prefix search on the shared folded
// body. Only fold-invariant operators are admitted; notably, ASCII word boundaries
// differ for K/kelvin and S/long-s. Unsupported expressions keep the original regexp.
func foldContent(expression *syntax.Regexp) bool {
	changed := false
	var visit func(*syntax.Regexp) bool
	visit = func(node *syntax.Regexp) bool {
		switch node.Op {
		case syntax.OpLiteral:
			for _, r := range node.Rune {
				if unicode.SimpleFold(r) != r {
					if node.Flags&syntax.FoldCase == 0 {
						return false
					}
					changed = true
				}
			}
			node.Rune = []rune(foldText(string(node.Rune)))
			node.Flags &^= syntax.FoldCase
		case syntax.OpCharClass:
			// ponytail: only uncased ASCII classes; broader classes retain regexp.
			for i := 0; i < len(node.Rune); i += 2 {
				lo, hi := node.Rune[i], node.Rune[i+1]
				if hi >= utf8.RuneSelf || lo <= 'Z' && hi >= 'A' || lo <= 'z' && hi >= 'a' {
					return false
				}
			}
		case syntax.OpNoMatch, syntax.OpEmptyMatch, syntax.OpAnyCharNotNL, syntax.OpAnyChar,
			syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText, syntax.OpEndText,
			syntax.OpCapture, syntax.OpStar, syntax.OpPlus, syntax.OpQuest, syntax.OpRepeat,
			syntax.OpConcat, syntax.OpAlternate:
		default:
			return false
		}
		for _, child := range node.Sub {
			if !visit(child) {
				return false
			}
		}
		return true
	}
	return visit(expression) && changed
}
