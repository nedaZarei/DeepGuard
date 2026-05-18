package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

//go:embed web/dashboard.html
var dashboardHTML string

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Launch the web dashboard for viewing scan reports",
	Long: `Start a local HTTP server to visualize DeepGuard scan reports in your browser.

The dashboard shows severity distributions, vulnerability type breakdowns,
and detailed findings with code snippets and remediation guidance.`,
	Example: `  # Serve on the default port (3000)
  deepguard serve

  # Serve on a custom port
  deepguard serve --port 8080

  # Serve reports from a different directory
  deepguard serve --reports ./security-reports`,
	RunE: runServe,
}

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.Flags().IntP("port", "P", 3000, "port to listen on")
	serveCmd.Flags().StringP("reports", "r", "./reports", "directory containing scan reports")
}

// validFilename rejects any name with path-traversal characters.
var validFilename = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

func runServe(cmd *cobra.Command, args []string) error {
	port, _ := cmd.Flags().GetInt("port")
	reportsDir, _ := cmd.Flags().GetString("reports")

	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		return fmt.Errorf("cannot create reports directory: %w", err)
	}

	absDir, err := filepath.Abs(reportsDir)
	if err != nil {
		return fmt.Errorf("cannot resolve reports directory: %w", err)
	}

	mux := http.NewServeMux()

	// Dashboard UI
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		fmt.Fprint(w, dashboardHTML)
	})

	// List scan reports
	mux.HandleFunc("/api/reports", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-cache")

		entries, err := os.ReadDir(reportsDir)
		if err != nil {
			http.Error(w, `{"error":"cannot read reports directory"}`, http.StatusInternalServerError)
			return
		}

		type entry struct {
			Name string `json:"name"`
		}

		var reports []entry
		for _, e := range entries {
			name := e.Name()
			if !e.IsDir() && strings.HasPrefix(name, "scan-") && strings.HasSuffix(name, ".json") {
				reports = append(reports, entry{Name: name})
			}
		}

		// Newest first (filenames contain a timestamp)
		sort.Slice(reports, func(i, j int) bool {
			return reports[i].Name > reports[j].Name
		})

		json.NewEncoder(w).Encode(reports)
	})

	// Serve an individual report
	mux.HandleFunc("/api/reports/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/api/reports/")

		if !validFilename.MatchString(name) || strings.Contains(name, "..") {
			http.Error(w, `{"error":"invalid filename"}`, http.StatusBadRequest)
			return
		}

		target := filepath.Join(absDir, name)
		if !strings.HasPrefix(filepath.Clean(target), filepath.Clean(absDir)) {
			http.Error(w, `{"error":"access denied"}`, http.StatusForbidden)
			return
		}

		data, err := os.ReadFile(target)
		if err != nil {
			http.Error(w, `{"error":"report not found"}`, http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-cache")
		w.Write(data)
	})

	n := countScanReports(reportsDir)
	plural := "reports"
	if n == 1 {
		plural = "report"
	}

	addr := fmt.Sprintf(":%d", port)
	fmt.Printf("\n  DeepGuard Dashboard\n\n")
	fmt.Printf("  Reports  %s  (%d %s)\n", absDir, n, plural)
	fmt.Printf("  URL      http://localhost%s\n\n", addr)
	fmt.Printf("  Press Ctrl+C to stop\n\n")

	return http.ListenAndServe(addr, mux)
}

func countScanReports(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	count := 0
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() && strings.HasPrefix(name, "scan-") && strings.HasSuffix(name, ".json") {
			count++
		}
	}
	return count
}
