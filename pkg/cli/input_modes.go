package cli

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/cli/internal/clicommon"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// inputModeEntry describes a supported input mode.
type inputModeEntry struct {
	Name        string
	Aliases     []string
	Description string
	Example     string
}

// Examples use -i/--input, not -T/--target-file. -T reads its file as one
// target URL per line, so pointing it at a spec or an export would treat each
// line of that file as a target. The one exception is the urls mode, which is
// exactly what -T parses.
var inputModes = []inputModeEntry{
	{
		Name:        "urls",
		Aliases:     []string{"url", "list"},
		Description: "Plain text file with one URL per line",
		Example:     "vigolium scan -T targets.txt",
	},
	{
		Name:        "nuclei-output",
		Aliases:     []string{"nuclei"},
		Description: "Nuclei JSON output (one JSON object per line, supports .gz)",
		Example:     "vigolium scan -i nuclei-results.json -I nuclei-output",
	},
	{
		Name:        "openapi",
		Aliases:     []string{"swagger"},
		Description: "OpenAPI 3.0 / Swagger 2.0 specification (JSON or YAML)",
		Example:     "vigolium scan -i spec.yaml -I openapi -t https://api.example.com",
	},
	{
		Name:        "postman",
		Aliases:     nil,
		Description: "Postman Collection v2.1 JSON file",
		Example:     "vigolium scan -i collection.json -I postman",
	},
	{
		Name:        "curl",
		Aliases:     nil,
		Description: "File containing curl commands (.sh, .md, or raw)",
		Example:     "vigolium scan -i requests.sh -I curl",
	},
	{
		Name:        "burpraw",
		Aliases:     []string{"burp-raw", "raw"},
		Description: "Single raw HTTP request file (optional response after *** separator)",
		Example:     "vigolium scan -i request.txt -I burpraw",
	},
	{
		Name:        "burpxml",
		Aliases:     []string{"burp-xml", "burp", "burpstate"},
		Description: "Burp Suite XML export (.burpsession / .xml)",
		Example:     "vigolium scan -i export.xml -I burpxml",
	},
	{
		Name:        "burpscope",
		Aliases:     []string{"burp-scope", "burp-config"},
		Description: "Burp Suite project-config scope JSON (include rules become targets)",
		Example:     "vigolium scan -T scope.json",
	},
	{
		Name:        "har",
		Aliases:     []string{"http-archive"},
		Description: "HAR (HTTP Archive) 1.2 JSON file",
		Example:     "vigolium scan -i archive.har -I har",
	},
	{
		Name:        "deparos",
		Aliases:     []string{"deparos-output"},
		Description: "Deparos content discovery JSONL output (supports .gz)",
		Example:     "vigolium scan -i deparos-results.jsonl -I deparos",
	},
}

// maxAliasWidth caps the Aliases column so it doesn't dominate the table.
const maxAliasWidth = 26

// printInputModes prints all supported input modes as a borderless table.
func printInputModes() {
	type row struct {
		mode    string
		aliases string
		desc    string
		example string
	}

	rows := make([]row, len(inputModes))
	for i, m := range inputModes {
		aliasPlain := strings.Join(m.Aliases, ", ")
		aliasDisplay := clicommon.TruncateVisible(aliasPlain, maxAliasWidth)
		rows[i] = row{
			mode:    terminal.Cyan(m.Name),
			aliases: terminal.Cyan(aliasDisplay),
			desc:    m.Description,
			example: terminal.Gray(m.Example),
		}
	}

	headers := [4]string{
		terminal.Bold("Mode"),
		terminal.Bold("Aliases"),
		terminal.Bold("Description"),
		terminal.Bold("Example"),
	}

	// Compute column widths from headers and data.
	widths := [4]int{
		clicommon.VisibleLen(headers[0]),
		clicommon.VisibleLen(headers[1]),
		clicommon.VisibleLen(headers[2]),
		clicommon.VisibleLen(headers[3]),
	}
	for _, r := range rows {
		if w := clicommon.VisibleLen(r.mode); w > widths[0] {
			widths[0] = w
		}
		if w := clicommon.VisibleLen(r.aliases); w > widths[1] {
			widths[1] = w
		}
		if w := clicommon.VisibleLen(r.desc); w > widths[2] {
			widths[2] = w
		}
		if w := clicommon.VisibleLen(r.example); w > widths[3] {
			widths[3] = w
		}
	}

	// Cap aliases column.
	if widths[1] > maxAliasWidth {
		widths[1] = maxAliasWidth
	}

	// padRight pads s to width based on its visible length.
	padRight := func(s string, width int) string {
		pad := width - clicommon.VisibleLen(s)
		if pad <= 0 {
			return s
		}
		return s + strings.Repeat(" ", pad)
	}

	fmt.Println()

	// Header row.
	fmt.Printf("  %s │ %s │ %s │ %s\n",
		padRight(headers[0], widths[0]),
		padRight(headers[1], widths[1]),
		padRight(headers[2], widths[2]),
		headers[3],
	)

	// Separator.
	fmt.Printf("  %s─┼─%s─┼─%s─┼─%s\n",
		strings.Repeat("─", widths[0]),
		strings.Repeat("─", widths[1]),
		strings.Repeat("─", widths[2]),
		strings.Repeat("─", widths[3]),
	)

	// Data rows.
	for _, r := range rows {
		fmt.Printf("  %s │ %s │ %s │ %s\n",
			padRight(r.mode, widths[0]),
			padRight(r.aliases, widths[1]),
			padRight(r.desc, widths[2]),
			r.example,
		)
	}

	fmt.Println()
}
