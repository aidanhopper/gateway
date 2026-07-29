package cli

import (
	"fmt"
	"io"
	"regexp"
	"strings"
)

var (
	colorOverride *bool
	ansiRegex     = regexp.MustCompile("\x1b\\[[0-9;]*[a-zA-Z]")
)

// SetColorEnabled explicitly enables or disables ANSI color output (useful for testing).
func SetColorEnabled(enabled bool) {
	colorOverride = &enabled
}

// ResetColorMode resets color override back to auto-detection.
func ResetColorMode() {
	colorOverride = nil
}

// isColorSupported returns true if ANSI color codes are enabled.
func isColorSupported() bool {
	if colorOverride != nil {
		return *colorOverride
	}
	return false
}

// visibleWidth returns the visual character width of a string excluding ANSI escape sequences.
func visibleWidth(s string) int {
	clean := ansiRegex.ReplaceAllString(s, "")
	return len(clean)
}

// Basic ANSI styles
func ColorBold(s string) string {
	if !isColorSupported() {
		return s
	}
	return "\x1b[1m" + s + "\x1b[0m"
}

func ColorDim(s string) string {
	if !isColorSupported() {
		return s
	}
	return "\x1b[2m" + s + "\x1b[0m"
}

func ColorCyan(s string) string {
	if !isColorSupported() {
		return s
	}
	return "\x1b[36m" + s + "\x1b[0m"
}

func ColorGreen(s string) string {
	if !isColorSupported() {
		return s
	}
	return "\x1b[32m" + s + "\x1b[0m"
}

func ColorYellow(s string) string {
	if !isColorSupported() {
		return s
	}
	return "\x1b[33m" + s + "\x1b[0m"
}

func ColorRed(s string) string {
	if !isColorSupported() {
		return s
	}
	return "\x1b[31m" + s + "\x1b[0m"
}

func ColorGray(s string) string {
	if !isColorSupported() {
		return s
	}
	return "\x1b[90m" + s + "\x1b[0m"
}

// Badge Formatters (Text-only, zero emojis)
func BadgeSuccess(text string) string {
	return ColorBold(ColorGreen(text))
}

func BadgeError(text string) string {
	return ColorBold(ColorRed(text))
}

func BadgeWarning(text string) string {
	return ColorBold(ColorYellow(text))
}

func BadgeInfo(text string) string {
	return ColorBold(ColorCyan(text))
}

// Table represents a dynamically formatted CLI data table.
type Table struct {
	Headers []string
	Rows    [][]string
}

// NewTable initializes a new dynamic CLI table with headers.
func NewTable(headers ...string) *Table {
	return &Table{
		Headers: headers,
		Rows:    [][]string{},
	}
}

// AddRow appends a row of cell values to the table.
func (t *Table) AddRow(cells ...string) {
	t.Rows = append(t.Rows, cells)
}

// Render writes the dynamically spaced table to the given writer.
func (t *Table) Render(w io.Writer) {
	if len(t.Headers) == 0 && len(t.Rows) == 0 {
		return
	}

	numCols := len(t.Headers)
	for _, row := range t.Rows {
		if len(row) > numCols {
			numCols = len(row)
		}
	}

	colWidths := make([]int, numCols)
	for i, h := range t.Headers {
		w := visibleWidth(h)
		if w > colWidths[i] {
			colWidths[i] = w
		}
	}

	for _, row := range t.Rows {
		for i, cell := range row {
			if i < numCols {
				w := visibleWidth(cell)
				if w > colWidths[i] {
					colWidths[i] = w
				}
			}
		}
	}

	// Calculate total divider width
	totalWidth := 0
	for _, w := range colWidths {
		totalWidth += w + 2
	}
	if totalWidth > 2 {
		totalWidth -= 2
	}

	// Render Headers
	if len(t.Headers) > 0 {
		for i, h := range t.Headers {
			pad := colWidths[i] - visibleWidth(h)
			cellStr := h + strings.Repeat(" ", pad)
			if i < len(t.Headers)-1 {
				cellStr += "  "
			}
			fmt.Fprint(w, cellStr)
		}
		fmt.Fprintln(w)

		// Render Divider Line
		fmt.Fprintln(w, strings.Repeat("-", totalWidth))
	}

	// Render Rows
	for _, row := range t.Rows {
		for i := 0; i < numCols; i++ {
			cellVal := ""
			if i < len(row) {
				cellVal = row[i]
			}
			pad := colWidths[i] - visibleWidth(cellVal)
			cellStr := cellVal + strings.Repeat(" ", pad)
			if i < numCols-1 {
				cellStr += "  "
			}
			fmt.Fprint(w, cellStr)
		}
		fmt.Fprintln(w)
	}
}

// String returns the rendered table as a string.
func (t *Table) String() string {
	var sb strings.Builder
	t.Render(&sb)
	return sb.String()
}
