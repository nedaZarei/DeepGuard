package report

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"golang.org/x/term"
)

// ANSI color codes
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorCyan   = "\033[36m"
	ColorBold   = "\033[1m"
	ColorOrange = "\033[38;5;208m" // 256-color orange
)

// Box drawing characters
const (
	BoxHorizontal = "─"
	BoxVertical   = "│"
	BoxTopLeft    = "┌"
	BoxTopRight   = "┐"
	BoxBottomLeft = "└"
	BoxBottomRight = "┘"
	BoxT           = "┬"
	BoxBT          = "┴"
)

// TerminalReporter handles formatted terminal output
type TerminalReporter struct {
	writer    io.Writer
	width     int
	colorMode bool
}

// NewTerminalReporter creates a new terminal reporter
func NewTerminalReporter() *TerminalReporter {
	width := 80 // Default width

	// Try to get terminal width
	if w, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil && w > 0 {
		width = w
	}

	// Detect if output is a TTY (for color support)
	colorMode := term.IsTerminal(int(os.Stdout.Fd()))

	return &TerminalReporter{
		writer:    os.Stdout,
		width:     width,
		colorMode: colorMode,
	}
}

// NewTerminalReporterWithWriter creates a reporter with a custom writer (for testing)
func NewTerminalReporterWithWriter(w io.Writer, width int, colorMode bool) *TerminalReporter {
	return &TerminalReporter{
		writer:    w,
		width:     width,
		colorMode: colorMode,
	}
}

// PrintSummary prints a formatted summary of the scan report to the terminal
func (tr *TerminalReporter) PrintSummary(report ScanReport) {
	tr.printHeader()
	tr.printMetadata(report.ScanMetadata)
	tr.printResults(report)
	tr.printFooter(report.ScanMetadata)
}

// PrintSummary is a convenience function to print a summary with default settings
func PrintSummary(report ScanReport) {
	reporter := NewTerminalReporter()
	reporter.PrintSummary(report)
}

// printHeader prints the application header
func (tr *TerminalReporter) printHeader() {
	tr.println("")
	tr.printBox("DeepGuard Security Scanner", "v1.0.0")
	tr.println("")
}

// printMetadata prints scan metadata
func (tr *TerminalReporter) printMetadata(metadata ScanMetadata) {
	tr.printSectionTitle("SCAN METADATA")
	tr.printKeyValue("Target Path", metadata.TargetPath)
	tr.printKeyValue("Languages", strings.Join(metadata.Languages, ", "))
	tr.printKeyValue("Frameworks", strings.Join(metadata.Frameworks, ", "))
	tr.printKeyValue("Model Used", metadata.ModelUsed)
	tr.println("")
}

// printResults prints the vulnerability findings summary
func (tr *TerminalReporter) printResults(report ScanReport) {
	tr.printSectionTitle("SCAN RESULTS")

	// Total findings (with filtering info if applicable)
	if report.ScanMetadata.Filtering != nil && report.ScanMetadata.Filtering.Enabled {
		findingsText := fmt.Sprintf("%d (%d filtered)",
			report.Summary.TotalFindings,
			report.ScanMetadata.Filtering.FilteredFindings)
		tr.printKeyValue("Total Findings", findingsText)
		tr.printKeyValue("  Confidence Threshold", fmt.Sprintf("%.2f", report.ScanMetadata.Filtering.ThresholdUsed))
	} else {
		tr.printKeyValue("Total Findings", fmt.Sprintf("%d", report.Summary.TotalFindings))
	}
	tr.println("")

	// Severity breakdown
	if report.Summary.TotalFindings > 0 {
		tr.println("  By Severity:")
		tr.printSeverityCounts(report.Summary.BySeverity)
		tr.println("")

		// Type breakdown
		tr.println("  Top Vulnerability Types:")
		tr.printTypeBreakdown(report.Summary.ByType)
		tr.println("")
	}
}

// printFooter prints cost and duration information
func (tr *TerminalReporter) printFooter(metadata ScanMetadata) {
	tr.printSectionTitle("SCAN SUMMARY")
	tr.printKeyValue("Total Cost", tr.formatCost(metadata.TotalCost))
	tr.printKeyValue("Duration", tr.formatDuration(metadata.ScanDurationSeconds))
	tr.println("")
	tr.printSeparator()
}

// printSeverityCounts prints severity counts with colors
func (tr *TerminalReporter) printSeverityCounts(bySeverity map[string]int) {
	severities := []string{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow}

	for _, severity := range severities {
		count := bySeverity[severity]
		if count > 0 {
			label := fmt.Sprintf("    %s:", strings.Title(severity))
			value := fmt.Sprintf("%d", count)
			tr.printColoredSeverity(label, value, severity)
		}
	}
}

// printTypeBreakdown prints top vulnerability types sorted by count
func (tr *TerminalReporter) printTypeBreakdown(byType map[string]int) {
	// Sort types by count (descending)
	type typeCount struct {
		vulnType string
		count    int
	}

	var types []typeCount
	for t, c := range byType {
		types = append(types, typeCount{t, c})
	}

	sort.Slice(types, func(i, j int) bool {
		return types[i].count > types[j].count
	})

	// Show top 10
	limit := 10
	if len(types) < limit {
		limit = len(types)
	}

	for i := 0; i < limit; i++ {
		label := fmt.Sprintf("    %s:", tr.formatTypeName(types[i].vulnType))
		value := fmt.Sprintf("%d", types[i].count)
		tr.printKeyValueIndented(label, value)
	}
}

// printBox prints a centered box with title and subtitle
func (tr *TerminalReporter) printBox(title, subtitle string) {
	// Calculate padding
	contentLen := len(title) + len(subtitle) + 3 // " - " separator
	if contentLen > tr.width-4 {
		contentLen = tr.width - 4
	}

	padding := (tr.width - contentLen - 2) / 2
	leftPad := strings.Repeat(" ", padding)

	content := fmt.Sprintf("%s - %s", title, subtitle)

	tr.println(leftPad + BoxTopLeft + strings.Repeat(BoxHorizontal, contentLen) + BoxTopRight)
	tr.println(leftPad + BoxVertical + tr.center(content, contentLen) + BoxVertical)
	tr.println(leftPad + BoxBottomLeft + strings.Repeat(BoxHorizontal, contentLen) + BoxBottomRight)
}

// printSectionTitle prints a section header
func (tr *TerminalReporter) printSectionTitle(title string) {
	colored := tr.colorize(title, ColorCyan+ColorBold)
	tr.println(colored)
	tr.printSeparator()
}

// printSeparator prints a horizontal line
func (tr *TerminalReporter) printSeparator() {
	tr.println(strings.Repeat(BoxHorizontal, tr.width))
}

// printKeyValue prints a key-value pair with right-aligned value
func (tr *TerminalReporter) printKeyValue(key, value string) {
	maxKeyLen := tr.width - len(value) - 4
	if len(key) > maxKeyLen {
		key = key[:maxKeyLen]
	}

	padding := tr.width - len(key) - len(value) - 4
	line := fmt.Sprintf("  %s%s%s", key, strings.Repeat(" ", padding), value)
	tr.println(line)
}

// printKeyValueIndented is like printKeyValue but for indented items
func (tr *TerminalReporter) printKeyValueIndented(key, value string) {
	maxKeyLen := tr.width - len(value) - 6
	if len(key) > maxKeyLen {
		key = key[:maxKeyLen]
	}

	padding := tr.width - len(key) - len(value) - 2
	if padding < 1 {
		padding = 1
	}
	line := fmt.Sprintf("%s%s%s", key, strings.Repeat(" ", padding), value)
	tr.println(line)
}

// printColoredSeverity prints a severity line with appropriate color
func (tr *TerminalReporter) printColoredSeverity(label, value, severity string) {
	var color string
	switch severity {
	case SeverityCritical:
		color = ColorRed + ColorBold
	case SeverityHigh:
		color = ColorOrange + ColorBold
	case SeverityMedium:
		color = ColorYellow
	case SeverityLow:
		color = ColorBlue
	default:
		color = ""
	}

	coloredValue := tr.colorize(value, color)

	maxLabelLen := tr.width - len(value) - 6
	if len(label) > maxLabelLen {
		label = label[:maxLabelLen]
	}

	padding := tr.width - len(label) - len(value) - 2
	if padding < 1 {
		padding = 1
	}
	line := fmt.Sprintf("%s%s%s", label, strings.Repeat(" ", padding), coloredValue)
	tr.println(line)
}

// println writes a line to the output
func (tr *TerminalReporter) println(line string) {
	fmt.Fprintln(tr.writer, line)
}

// center centers text within a given width
func (tr *TerminalReporter) center(text string, width int) string {
	if len(text) >= width {
		return text[:width]
	}
	padding := (width - len(text)) / 2
	return strings.Repeat(" ", padding) + text + strings.Repeat(" ", width-len(text)-padding)
}

// colorize adds ANSI color codes to text if color mode is enabled
func (tr *TerminalReporter) colorize(text, color string) string {
	if !tr.colorMode || color == "" {
		return text
	}
	return color + text + ColorReset
}

// formatDuration converts seconds to human-readable format
func (tr *TerminalReporter) formatDuration(seconds int) string {
	if seconds < 60 {
		return fmt.Sprintf("%ds", seconds)
	}

	minutes := seconds / 60
	remainingSeconds := seconds % 60

	if remainingSeconds == 0 {
		return fmt.Sprintf("%dm", minutes)
	}

	return fmt.Sprintf("%dm %ds", minutes, remainingSeconds)
}

// formatCost formats cost with 2 decimal places
func (tr *TerminalReporter) formatCost(cost float64) string {
	return fmt.Sprintf("$%.2f", cost)
}

// formatTypeName converts snake_case to Title Case
func (tr *TerminalReporter) formatTypeName(typeName string) string {
	parts := strings.Split(typeName, "_")
	for i, part := range parts {
		if len(part) > 0 {
			parts[i] = strings.ToUpper(part[:1]) + part[1:]
		}
	}
	return strings.Join(parts, " ")
}

// StripColors removes ANSI color codes from a string (for testing)
func StripColors(s string) string {
	// Simple regex-free implementation
	result := strings.Builder{}
	inEscape := false

	for i := 0; i < len(s); i++ {
		if s[i] == '\033' {
			inEscape = true
			continue
		}

		if inEscape {
			if (s[i] >= 'A' && s[i] <= 'Z') || (s[i] >= 'a' && s[i] <= 'z') {
				inEscape = false
			}
			continue
		}

		result.WriteByte(s[i])
	}

	return result.String()
}
