package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Lu1sDV/wafmeow/v3/pkg/wafmeow"
	"github.com/logrusorgru/aurora/v4"
)

const (
	logoRows     = 9
	logoColumns  = 35
	logoInterval = 180 * time.Millisecond
)

// The cat moves against a stationary wall. Every frame has the same nine ASCII
// rows, including its leading empty rows. Keep a spare terminal row and column:
// the final newline and automatic wrapping must not scroll away our redraw area.
var logoFrames = [...][logoRows]string{
	{
		``,
		``,
		`      /\_/\`,
		`     (     )___o+-----+-----+-----+`,
		`     /       /  |     |     |     |`,
		`  __/       /   +--+-----+-----+--+`,
		` (  \      /    |  |     |     |  |`,
		`  \__\ /\ /     +-----+-----+-----+`,
		`     (_/ \_)    |     |     |     |`,
	},
	{
		``,
		`      /\_/\`,
		`     (     )__`,
		`     /      / \o+-----+-----+-----+`,
		`  __/       /   |     |     |     |`,
		` (  \      /    +--+-----+-----+--+`,
		`  \__\ /\ /     |  |     |     |  |`,
		`     (_/ \_)    +-----+-----+-----+`,
		`                |     |     |     |`,
	},
	{
		`      /\_/\`,
		`     (     )__`,
		`     /      / \`,
		`  __/       / \o+-----+-----+-----+`,
		` (  \      /    |     |     |     |`,
		`  \__\ /\ /     +--+-----+-----+--+`,
		`     (_/ \_)    |  |     |     |  |`,
		`                +-----+-----+-----+`,
		`                |     |     |     |`,
	},
	{
		`      /\_/\`,
		`     (     )__`,
		`     /      / \`,
		`  __/       / \o+-----+-----+-----+`,
		` (   \     /    |     |     |     |`,
		`  \___\/\ /     +--+-----+-----+--+`,
		`     (_/ \_)    |  |     |     |  |`,
		`                +-----+-----+-----+`,
		`                |     |     |     |`,
	},
}

// Dimensions are sampled again before each redraw. Tests inject this boundary
// instead of pretending that a buffer is a terminal or changing global stdout.
type bannerTerminal struct {
	interactive   bool
	ansi          bool
	sharedOutput  bool // Injected tests only; real streams use file identity.
	columns, rows int
	size          func() (columns, rows int)
}

func inspectBannerTerminal(writer io.Writer) bannerTerminal {
	file, ok := writer.(*os.File)
	if !ok || !isTerminal(file) {
		return bannerTerminal{}
	}
	columns, rows := terminalSize(file)
	term := os.Getenv("TERM")
	return bannerTerminal{
		interactive: true,
		// Windows isTerminal already requires virtual-terminal processing.
		ansi:    term != "dumb" && (term != "" || runtime.GOOS == "windows"),
		columns: columns, rows: rows,
		size: func() (int, int) { return terminalSize(file) },
	}
}

// Plan lines advance the same cursor only when both outputs share a TTY.
// A wrapped plan invalidates its fixed redraw coordinates; use a static logo.
func scanBannerPlanRows(terminal bannerTerminal, stdout, stderr io.Writer, plan string) int {
	if plan == "" || (!terminal.sharedOutput && !writersShareTerminal(stdout, stderr)) {
		return 0
	}
	for _, line := range strings.Split(strings.TrimSuffix(plan, "\n"), "\n") {
		if terminal.columns <= 0 || len(line) >= terminal.columns {
			return -1
		}
	}
	return strings.Count(plan, "\n")
}

func writersShareTerminal(stdout, stderr io.Writer) bool {
	left, okLeft := stdout.(*os.File)
	right, okRight := stderr.(*os.File)
	if !okLeft || !okRight {
		return false
	}
	leftInfo, leftErr := left.Stat()
	rightInfo, rightErr := right.Stat()
	return leftErr == nil && rightErr == nil &&
		leftInfo.Mode()&os.ModeCharDevice != 0 && rightInfo.Mode()&os.ModeCharDevice != 0 &&
		os.SameFile(leftInfo, rightInfo)
}

func (terminal bannerTerminal) fitsLogo() bool {
	return terminal.interactive && terminal.columns > logoColumns && terminal.rows > logoRows
}

func (terminal bannerTerminal) unchanged() bool {
	if terminal.size == nil {
		return true
	}
	columns, rows := terminal.size()
	return columns == terminal.columns && rows == terminal.rows
}

// One goroutine owns timed frames. requestStop only stops that owner, so it is
// safe before a result's journal handoff. stop joins it, then settles the logo
// once before either console writes. Settling is fallible output and happens
// after the journal. No results wait for a timer and no cursor state is hidden.
type bannerAnimation struct {
	requested   chan struct{}
	done        chan struct{}
	once        sync.Once
	settled     sync.Once
	settle      func() error
	abort       func()
	frame       int   // Owner writes until done closes; stop reads after joining.
	err         error // Owner, then settled.Do; readers join both owners.
	invalidated bool  // Observed reflow cannot be undone by restoring dimensions.
	footerRows  int   // Plan lines occupying the same physical terminal.
}

func (animation *bannerAnimation) requestStop() {
	if animation != nil {
		animation.once.Do(func() { close(animation.requested) })
	}
}

func (animation *bannerAnimation) stop() error {
	if animation == nil {
		return nil
	}
	animation.requestStop()
	<-animation.done
	animation.settled.Do(func() {
		if animation.err == nil && !animation.invalidated && animation.frame != len(logoFrames)-1 {
			animation.err = animation.settle()
			if animation.err != nil {
				animation.abort()
			}
		}
	})
	return animation.err
}

func (animation *bannerAnimation) join(err error) error {
	animationErr := animation.stop()
	if errors.Is(err, animationErr) {
		return err
	}
	return errors.Join(err, animationErr)
}

func startScanBanner(ctx context.Context, writer io.Writer, opts options, au *aurora.Aurora, terminal bannerTerminal, abort func()) (*bannerAnimation, error) {
	return startScanBannerWithPlan(ctx, writer, opts, au, terminal, abort, nil, 0)
}

// Paint the first frame and plan synchronously, before any timer starts.
func startScanBannerWithPlan(ctx context.Context, writer io.Writer, opts options, au *aurora.Aurora, terminal bannerTerminal, abort func(), afterLogo func() error, footerRows int) (*bannerAnimation, error) {
	printPlan := func() error {
		if afterLogo != nil {
			return afterLogo()
		}
		return nil
	}
	if opts.Silent || opts.JSONL || opts.ListWAFS || opts.Version {
		return nil, printPlan()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	_, noColor := os.LookupEnv("NO_COLOR")
	if opts.NoColors || noColor || !terminal.ansi {
		au = aurora.New(aurora.WithColors(false))
	}
	if !terminal.fitsLogo() || !terminal.ansi || footerRows < 0 || terminal.rows <= logoRows+footerRows {
		if err := printBanner(writer, au); err != nil {
			return nil, err
		}
		return nil, printPlan()
	}
	animated := terminal.ansi && !opts.NoAnimation && !opts.NoColors && !noColor
	frame := len(logoFrames) - 1
	if animated {
		frame = 0
	}
	first := fmt.Sprintf("%s  %s\n  HTTP evidence fingerprinting\n\n", au.Bold("wafmeow"), terminalText(wafmeow.Version())) + logoFrame(frame, false, au)
	if err := writeLogo(writer, first); err != nil {
		return nil, err
	}
	if err := printPlan(); err != nil {
		return nil, err
	}
	if !animated {
		return nil, nil
	}
	animation := &bannerAnimation{
		requested: make(chan struct{}), done: make(chan struct{}), abort: abort,
		footerRows: footerRows,
		settle: func() error { return settleLogo(ctx, writer, au, terminal, footerRows) },
	}
	go func() {
		defer close(animation.done)
		animation.err = animation.play(ctx, writer, au, terminal)
		if animation.err != nil {
			abort()
		}
	}()
	return animation, nil
}

func (animation *bannerAnimation) play(ctx context.Context, writer io.Writer, au *aurora.Aurora, terminal bannerTerminal) error {
	timer := time.NewTimer(logoInterval)
	defer timer.Stop()
	for frame := 1; frame < len(logoFrames); frame++ {
		select {
		case <-ctx.Done():
			return nil
		case <-animation.requested:
			return nil
		case <-timer.C:
		}
		// Prefer an already requested stop over another timed frame. Reflow on
		// resize invalidates old cursor coordinates, so leave the last frame
		// in place rather than moving up over potentially unrelated output.
		select {
		case <-animation.requested:
			return nil
		default:
		}
		if ctx.Err() != nil {
			return nil
		}
		if !terminal.unchanged() {
			animation.invalidated = true
			return nil
		}
		if err := writeLogo(writer, logoFrameOffset(frame, true, au, animation.footerRows)); err != nil {
			return err
		}
		animation.frame = frame
		timer.Reset(logoInterval)
	}
	return nil
}

func settleLogo(ctx context.Context, writer io.Writer, au *aurora.Aurora, terminal bannerTerminal, footerRows int) error {
	if ctx.Err() != nil || !terminal.unchanged() {
		return nil
	}
	return writeLogo(writer, logoFrameOffset(len(logoFrames)-1, true, au, footerRows))
}

func logoFrame(index int, redraw bool, au *aurora.Aurora) string {
	return logoFrameOffset(index, redraw, au, 0)
}

func logoFrameOffset(index int, redraw bool, au *aurora.Aurora, footerRows int) string {
	var text strings.Builder
	if redraw {
		fmt.Fprintf(&text, "\x1b[%dA", logoRows+footerRows)
	}
	for _, row := range logoFrames[index] {
		if redraw {
			text.WriteString("\r\x1b[2K")
		}
		// The fixed wall starts in column 16; all earlier cells are the cat.
		cat, wall := row, ""
		if len(row) > 16 {
			cat, wall = row[:16], row[16:]
		}
		fmt.Fprintf(&text, "%s%s\n", au.Gray(16, cat), au.Index(208, wall))
	}
	// Return the cursor below the plan; never overwrite its lines.
	if redraw && footerRows > 0 {
		fmt.Fprintf(&text, "\x1b[%dB", footerRows)
	}
	return text.String()
}

func writeLogo(writer io.Writer, text string) error {
	n, err := io.WriteString(writer, text)
	if err == nil && n != len(text) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return fmt.Errorf("render startup logo: %w", err)
	}
	return nil
}
