package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"

	"github.com/spf13/cobra"

	"github.com/aquasecurity/tracee"
	"github.com/aquasecurity/tracee/common/errfmt"
	"github.com/aquasecurity/tracee/common/logger"
	"github.com/aquasecurity/tracee/pkg/cmd/initialize/sigs"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/signatures/signature"
	"github.com/aquasecurity/tracee/types/detect"
)

var (
	// signaturesOnce ensures signatures are loaded only once
	signaturesOnce sync.Once
	// loadedSignatures stores the loaded signatures for reuse
	loadedSignatures []detect.Signature
	// signaturesLoaded indicates whether signature loading was attempted and successful
	signaturesLoaded bool
)

// ensureSignaturesLoaded loads signatures if not already loaded
func ensureSignaturesLoaded() {
	signaturesOnce.Do(func() {
		signatures, _, err := signature.Find([]string{}, nil)
		if err != nil {
			logger.Debugw("Failed to find signatures", "err", err)
			return
		}
		if len(signatures) == 0 {
			logger.Debugw("No signatures found")
			return
		}
		sigs.CreateEventsFromSignatures(events.StartSignatureID, signatures)
		loadedSignatures = signatures
		signaturesLoaded = true
	})
}

func init() {
	rootCmd.AddCommand(manCmd)

	// add subcommands to manCmd
	manCmd.AddCommand(
		buffersCmd,
		capabilitiesCmd,
		captureCmd,
		configCmd,
		enrichmentCmd,
		eventCmd,
		eventsCmd,
		loggingCmd,
		outputCmd,
		scopeCmd,
		serverCmd,
		storesCmd,
	)
}

var manCmd = &cobra.Command{
	Use:     "man",
	Aliases: []string{"m"},
	Short:   "Open manual pages for tracee flags and events",
	Long: `Open manual pages for tracee flags and events.

This command provides access to detailed documentation for tracee flags and events.
Use the available subcommands to access documentation for specific topics.

Examples:
  tracee man cache          # Open manual page for --cache flag
  tracee man events         # Open manual page for --events flag
  tracee man event bpf_attach # Open documentation for the 'bpf_attach' event`,
	Run: func(cmd *cobra.Command, args []string) {
		// if here, no valid subcommand was provided
		if err := cmd.Help(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			os.Exit(1)
		}
	},
	DisableFlagsInUseLine: true,
}

var capabilitiesCmd = &cobra.Command{
	Use:     "capabilities",
	Aliases: []string{"C"},
	Short:   "Show manual page for the --capabilities flag",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runManForFlag("capabilities")
	},
}

var captureCmd = &cobra.Command{
	Use:     "capture",
	Aliases: []string{"c"},
	Short:   "Show manual page for the --capture flag",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runManForFlag("capture")
	},
}

var configCmd = &cobra.Command{
	Use:     "config",
	Aliases: []string{},
	Short:   "Show manual page for the --config flag",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runManForFlag("config")
	},
}

var enrichmentCmd = &cobra.Command{
	Use:     "enrichment",
	Aliases: []string{},
	Short:   "Show manual page for the --enrichment flag",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runManForFlag("enrichment")
	},
}

var eventsCmd = &cobra.Command{
	Use:     "events",
	Aliases: []string{"e"},
	Short:   "Show manual page for the --events flag",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runManForFlag("events")
	},
}

var loggingCmd = &cobra.Command{
	Use:     "logging",
	Aliases: []string{"l"},
	Short:   "Show manual page for the --logging flag",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runManForFlag("logging")
	},
}

var outputCmd = &cobra.Command{
	Use:     "output",
	Aliases: []string{"o"},
	Short:   "Show manual page for the --output flag",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runManForFlag("output")
	},
}

var scopeCmd = &cobra.Command{
	Use:     "scope",
	Aliases: []string{"s"},
	Short:   "Show manual page for the --scope flag",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runManForFlag("scope")
	},
}

var serverCmd = &cobra.Command{
	Use:     "server",
	Aliases: []string{},
	Short:   "Show manual page for the --server flag",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runManForFlag("server")
	},
}

var eventCmd = &cobra.Command{
	Use:   "event [event-name]",
	Short: "Show manual page for a specific event",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return showEventDocumentation(args[0])
	},
}

var storesCmd = &cobra.Command{
	Use:     "stores",
	Aliases: []string{},
	Short:   "Show manual page for the --stores flag",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runManForFlag("stores")
	},
}

var buffersCmd = &cobra.Command{
	Use:     "buffers",
	Aliases: []string{"b"},
	Short:   "Show manual page for the --buffers flag",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runManForFlag("buffers")
	},
}

// runManForFlag runs man for the specified flag name
func runManForFlag(flagName string) error {
	// Read the embedded manual page
	manFileName := fmt.Sprintf("docs/man/%s.1", flagName)
	manContent, err := tracee.ManPagesBundle.ReadFile(manFileName)
	if err != nil {
		return errfmt.Errorf("manual page not found for %s: %v", flagName, err)
	}

	// Create a temporary file with the manual content
	tmpFile, err := os.CreateTemp("", fmt.Sprintf("tracee-man-%s-*.1", flagName))
	if err != nil {
		return errfmt.WrapError(err)
	}
	defer func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
	}()

	// Write the embedded content to the temporary file
	if _, err := tmpFile.Write(manContent); err != nil {
		return errfmt.WrapError(err)
	}

	// Close the file so man can read it
	if err := tmpFile.Close(); err != nil {
		return errfmt.WrapError(err)
	}

	// Try to find man command in PATH
	manPath, err := exec.LookPath("man")
	if err != nil {
		// Fallback: display content directly without man formatting
		fmt.Println("Note: 'man' command not found - displaying unformatted documentation")
		fmt.Println()
		cleanContent := cleanGroffFormatting(string(manContent))
		fmt.Print(cleanContent)
		return nil
	}

	// Execute man on the temporary file
	cmd := exec.Command(manPath, tmpFile.Name())
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Run()
	return errfmt.WrapError(err)
}

// showEventDocumentation displays documentation for a specific event
func showEventDocumentation(eventName string) error {
	// Ensure signatures are loaded (will only load once)
	ensureSignaturesLoaded()

	// Check if event exists first
	eventID, found := events.Core.GetDefinitionIDByName(eventName)
	if !found {
		fmt.Printf("Event '%s' not found.\n\n", eventName)
		fmt.Println("To see all available events, run:")
		fmt.Println("  tracee list")
		return nil
	}

	// Try to use embedded man page
	manFileName := fmt.Sprintf("docs/man/%s.1", eventName)
	if manContent, err := tracee.ManPagesBundle.ReadFile(manFileName); err == nil {
		return displayManPage(manContent, eventName)
	}

	// Fallback: show basic information about the event
	definition := events.Core.GetDefinitionByID(eventID)
	fmt.Printf("Event: %s\n", definition.GetName())
	fmt.Printf("Description: %s\n", definition.GetDescription())
	fmt.Printf("ID: %d\n", definition.GetID())
	if definition.IsSyscall() {
		fmt.Println("Type: System call")
		fmt.Printf("\nFor detailed documentation about the '%s' system call, run:\n", definition.GetName())
		fmt.Printf("  man 2 %s\n", definition.GetName())
	} else if definition.IsSignature() {
		fmt.Println("Type: Security signature")
		fmt.Println("\nNo detailed documentation available for this event.")
	} else if definition.IsNetwork() {
		fmt.Println("Type: Network event")
		fmt.Println("\nNo detailed documentation available for this event.")
	} else {
		fmt.Println("Type: Built-in event")
		fmt.Println("\nNo detailed documentation available for this event.")
	}
	return nil
}

// displayManPage displays a man page using the system man command or fallback
func displayManPage(manContent []byte, name string) error {
	// Try to find man command in PATH
	manPath, err := exec.LookPath("man")
	if err != nil {
		// Fallback: display content directly without man formatting
		fmt.Println("Note: 'man' command not found - displaying unformatted documentation")
		fmt.Println()
		cleanContent := cleanGroffFormatting(string(manContent))
		fmt.Print(cleanContent)
		return nil
	}

	// Create a temporary file with the manual content
	tmpFile, err := os.CreateTemp("", fmt.Sprintf("tracee-man-%s-*.1", name))
	if err != nil {
		return errfmt.WrapError(err)
	}
	defer func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
	}()

	// Write the embedded content to the temporary file
	if _, err := tmpFile.Write(manContent); err != nil {
		return errfmt.WrapError(err)
	}

	// Close the file so man can read it
	if err := tmpFile.Close(); err != nil {
		return errfmt.WrapError(err)
	}

	// Execute man on the temporary file
	cmd := exec.Command(manPath, tmpFile.Name())
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Run()
	return errfmt.WrapError(err)
}

// cleanGroffFormatting removes groff/troff formatting directives for plain text display
func cleanGroffFormatting(content string) string {
	lines := strings.Split(content, "\n")
	var cleanLines []string

	// Regex patterns for common groff formatting
	formattingRegex := regexp.MustCompile(`\\f\[[BR]\]|\\f\[R\]|\\-`)

	for _, line := range lines {
		// Skip lines that start with groff directives
		if strings.HasPrefix(strings.TrimSpace(line), ".") {
			continue
		}

		// Remove inline formatting codes
		cleanLine := formattingRegex.ReplaceAllString(line, "")

		// Only add non-empty lines or preserve intentional spacing
		if strings.TrimSpace(cleanLine) != "" || strings.TrimSpace(line) == "" {
			cleanLines = append(cleanLines, cleanLine)
		}
	}

	return strings.Join(cleanLines, "\n")
}
