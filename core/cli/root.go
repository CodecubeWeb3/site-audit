package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodecubeWeb3/site-audit/core/audit"
	"github.com/CodecubeWeb3/site-audit/core/config"
	"github.com/CodecubeWeb3/site-audit/core/model"
	"github.com/CodecubeWeb3/site-audit/core/reporting"
	"github.com/CodecubeWeb3/site-audit/modules/dmca"
	"github.com/spf13/cobra"
)

// Execute runs the site-audit CLI root command.
func Execute() {
	if err := NewRootCommand().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// NewRootCommand builds the root command with subcommands for the tool.
func NewRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "site-audit",
		Short: "Consent-first web reconnaissance and reporting toolkit",
	}

	cmd.AddCommand(newAuditCommand())
	cmd.AddCommand(newDmcaCommand())
	cmd.AddCommand(newOsintCommand())
	cmd.AddCommand(newPentestCommand())
	cmd.AddCommand(newReportCommand())

	return cmd
}

func newAuditCommand() *cobra.Command {
	var cfgPath string
	var outputDir string
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Run a passive consent-first audit",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgPath)
			if err != nil {
				return err
			}
			if outputDir != "" {
				cfg.Reporting.OutputDir = outputDir
			}

			ctx := commandContext(cmd)
			runner := audit.NewRunner()
			result, err := runner.Run(ctx, cfg)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "run completed in %s\n", result.Completed.Sub(result.StartedAt).Round(time.Millisecond))
			fmt.Fprintf(cmd.OutOrStdout(), "artifacts written to %s\n", cfg.Reporting.OutputDir)
			for _, warn := range result.Errors {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s\n", warn)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&cfgPath, "config", "c", "config.yaml", "Configuration file (JSON or YAML)")
	cmd.Flags().StringVar(&outputDir, "output", "", "Override output directory")
	return cmd
}

func newDmcaCommand() *cobra.Command {
	var files []string
	var complainant string
	var output string
	cmd := &cobra.Command{
		Use:   "dmca",
		Short: "Generate DMCA evidence pack",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(files) == 0 {
				return errors.New("at least one --file must be provided")
			}
			items := make([]dmca.EvidenceItem, 0, len(files))
			for _, f := range files {
				items = append(items, dmca.EvidenceItem{Path: f, Type: inferEvidenceType(f)})
			}
			ctx := commandContext(cmd)
			packager := dmca.NewPackager(output)
			archive, err := packager.CreatePack(ctx, dmca.Evidence{
				Complainant: complainant,
				Infringing:  items,
				Metadata:    map[string]string{"generatedBy": "site-audit"},
			})
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "evidence pack created: %s\n", archive)
			return nil
		},
	}
	cmd.Flags().StringSliceVarP(&files, "file", "f", nil, "Evidence file paths to include")
	cmd.Flags().StringVar(&complainant, "complainant", "", "Complainant organisation or contact")
	cmd.Flags().StringVar(&output, "output", "artifacts/evidence", "Output directory for DMCA packs")
	return cmd
}

func newOsintCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "osint",
		Short: "Run OSINT-only reconnaissance",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("osint integrations require API credentials and are not yet implemented in this build")
		},
	}
}

func newPentestCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "pentest",
		Short: "Execute safe-active penetration modules (requires consent)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("pentest mode requires explicit signed consent and is disabled by default")
		},
	}
}

func newReportCommand() *cobra.Command {
	var runPath string
	var output string
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Render reports from existing run artifacts",
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := os.ReadFile(runPath)
			if err != nil {
				return fmt.Errorf("read run file: %w", err)
			}
			var result model.RunResult
			if err := json.Unmarshal(data, &result); err != nil {
				return fmt.Errorf("parse run file: %w", err)
			}
			htmlPath := output
			if htmlPath == "" {
				htmlPath = filepath.Join(filepath.Dir(runPath), "report.html")
			}
			if err := reporting.WriteHTML(htmlPath, &result); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "report written to %s\n", htmlPath)
			return nil
		},
	}
	cmd.Flags().StringVar(&runPath, "run", filepath.Join("artifacts", "run.json"), "Path to run.json")
	cmd.Flags().StringVar(&output, "output", "", "Output HTML path (defaults next to run.json)")
	return cmd
}

func commandContext(cmd *cobra.Command) context.Context {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	return ctx
}

func inferEvidenceType(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".har":
		return "har"
	case ".png", ".jpg", ".jpeg":
		return "screenshot"
	case ".html", ".htm":
		return "html"
	default:
		return strings.TrimPrefix(ext, ".")
	}
}
