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
	"github.com/rivo/uniseg"
)

const (
	logoFrameCount  = 4
	logoRows        = 13 // Includes the blank line after the wall.
	logoColumns     = 54
	logoWallStart   = 21
	logoWallWidth   = 33
	logoWallTop     = 3
	logoHeadingRows = 3
	logoInterval    = 180 * time.Millisecond
)

// Fixed brick courses are shared across frames. The cat climbs with its
// outstretched paw touching the same top-left corner (o+) on every frame.
var logoWallRows = [...]string{
	`+-------+-------+-------+-------+`,
	`|       |       |       |       |`,
	`+---+-------+-------+-------+---+`,
	`|   |       |       |       |   |`,
	`+-------+-------+-------+-------+`,
	`|       |       |       |       |`,
	`+---+-------+-------+-------+---+`,
	`|   |       |       |       |   |`,
	`+-------+-------+-------+-------+`,
}

var logoCatFrames = [logoFrameCount][logoRows]string{
	{
		``,
		``,
		`          /\_/\`,
		`        ( -.- )_____o`,
		`         /     \`,
		`     ___/      \`,
		`    /   /\      \`,
		`   (__ /  \____/`,
		`     \__/  \_/`,
		`      \___/`,
		``,
		``,
		``,
	},
	{
		``,
		`          /\_/\`,
		`        =( o.o )=`,
		`        /     \_____o`,
		`      _/        /`,
		`    _/  /\    __/`,
		`   /___/  \___/`,
		`   \    \__/`,
		`    \_/\_/`,
		``,
		``,
		``,
		``,
	},
	{
		`          /\_/\`,
		`        =( o.o )=`,
		`         / >^< \`,
		`     ___/      \____o`,
		`    /     /\     /`,
		`   /_____/  \___/`,
		`   \    \      /`,
		`    \___\  \_/\_/`,
		`       \__/`,
		``,
		``,
		``,
		``,
	},
	{
		`          /\_/\`,
		`        =( o.o )=`,
		`         / >^< \`,
		`     ___/       ____o`,
		`    /   /\      /`,
		`   /___/  \___/`,
		`   \  \  \      /`,
		`    \__\  \_/\_/`,
		`       \___/`,
		``,
		``,
		``,
		``,
	},
}

// Keep the wall's column fixed so redraws and independent coloring stay stable.
var logoFrames = buildLogoFrames()

func buildLogoFrames() [logoFrameCount][logoRows]string {
	var frames [logoFrameCount][logoRows]string
	for frame, cat := range logoCatFrames {
		for row, drawing := range cat {
			if row >= logoWallTop && row < logoWallTop+len(logoWallRows) {
				frames[frame][row] = fmt.Sprintf("%-*s%s", logoWallStart,
					drawing, logoWallRows[row-logoWallTop])
			} else {
				frames[frame][row] = drawing
			}
		}
	}
	return frames
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

// The heading occupies three lines before the sprite. Never scroll during
// startup: a wrapped title or short screen would invalidate redraw offsets.
func (terminal bannerTerminal) fitsLogo() bool {
	return terminal.interactive && terminal.columns > max(logoColumns, logoTitleColumns()) &&
		terminal.rows > logoRows+logoHeadingRows
}

// Center brand text over the wall, rather than over the cat-and-wall silhouette.
// Widths are measured in visible terminal cells, excluding trusted ANSI styles.
// A Go pseudo-version can be far longer than the visual wall. Keep the
// full VCS identity in --version/JSON provenance; abbreviate only the banner
// and make the abbreviation explicit with an ellipsis.
func logoDisplayVersion() string {
	version := terminalText(wafmeow.Version())
	const maxCells = 16
	if uniseg.StringWidth(version) <= maxCells {
		return version
	}
	var short strings.Builder
	width := 0
	graphemes := uniseg.NewGraphemes(version)
	for graphemes.Next() {
		value := graphemes.Str()
		if width+uniseg.StringWidth(value) > maxCells-1 {
			break
		}
		short.WriteString(value)
		width += uniseg.StringWidth(value)
	}
	return short.String() + "…"
}

func logoTitleColumns() int {
	titleWidth := uniseg.StringWidth("wafmeow " + logoDisplayVersion())
	if titleWidth > logoWallWidth {
		return logoWallStart + titleWidth
	}
	return logoColumns
}

func centerLogoText(colored string, cells int) string {
	indent := logoWallStart + max(0, (logoWallWidth-cells)/2)
	return strings.Repeat(" ", indent) + colored
}

func logoHeading(au *aurora.Aurora) string {
	version := logoDisplayVersion()
	title := centerLogoText(fmt.Sprintf("%s %s", au.Bold("wafmeow"), version),
		uniseg.StringWidth("wafmeow "+version))
	subtitle := centerLogoText(fmt.Sprint(au.Cyan("WAF fingerprinting")),
		uniseg.StringWidth("WAF fingerprinting"))
	return title + "\n" + subtitle + "\n\n"
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
	if !terminal.fitsLogo() || !terminal.ansi || footerRows < 0 || terminal.rows <= logoRows+logoHeadingRows+footerRows {
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
	first := logoHeading(au) + logoFrame(frame, false, au)
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
		settle:     func() error { return settleLogo(ctx, writer, au, terminal, footerRows) },
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
		// Color the cat and the wider brick wall independently.
		cat, wall := row, ""
		if len(row) > logoWallStart {
			cat, wall = row[:logoWallStart], row[logoWallStart:]
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
