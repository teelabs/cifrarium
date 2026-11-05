package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	ansiReset     = "\x1b[0m"
	ansiHeader    = "\x1b[38;2;88;166;255m"
	ansiCommand   = "\x1b[38;2;63;185;80m"
	ansiLocation  = "\x1b[38;2;121;192;255m"
	ansiWarning   = "\x1b[38;2;210;153;34m"
	ansiFailure   = "\x1b[38;2;248;81;73m"
	ansiIdentity  = "\x1b[38;2;210;168;255m"
	ansiSecondary = "\x1b[38;2;139;148;158m"
)

type terminalColor string

const (
	colorHeader    terminalColor = "header"
	colorCommand   terminalColor = "command"
	colorLocation  terminalColor = "location"
	colorWarning   terminalColor = "warning"
	colorFailure   terminalColor = "failure"
	colorIdentity  terminalColor = "identity"
	colorSecondary terminalColor = "secondary"
)

type terminalPalette struct {
	header, command, location, warning, failure, identity, secondary string
}

var codexPalette = terminalPalette{
	header:    ansiHeader,
	command:   ansiCommand,
	location:  ansiLocation,
	warning:   ansiWarning,
	failure:   ansiFailure,
	identity:  ansiIdentity,
	secondary: ansiSecondary,
}

const commandRule = "────────────────────────────────────────"

type terminalUI struct {
	w       io.Writer
	color   bool
	palette terminalPalette
}

type setupDecision struct {
	Title    string
	Decision string
	Effect   string
	Next     string
}

func newTerminalUI(w io.Writer) terminalUI {
	return terminalUI{w: w, color: writerIsTerminal(w), palette: codexPalette}
}

func writerIsTerminal(w io.Writer) bool {
	file, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func (ui terminalUI) colorFor(role terminalColor) string {
	palette := ui.palette
	if palette == (terminalPalette{}) {
		palette = codexPalette
	}
	switch role {
	case colorHeader:
		return palette.header
	case colorCommand:
		return palette.command
	case colorLocation:
		return palette.location
	case colorWarning:
		return palette.warning
	case colorFailure:
		return palette.failure
	case colorIdentity:
		return palette.identity
	case colorSecondary:
		return palette.secondary
	default:
		return ""
	}
}

func (ui terminalUI) colorize(role terminalColor, value string) string {
	if !ui.color || value == "" {
		return value
	}
	color := ui.colorFor(role)
	if color == "" {
		return value
	}
	return color + value + ansiReset
}

func (ui terminalUI) Header(title string) {
	fmt.Fprintf(ui.w, "\n%s\n%s\n", ui.colorize(colorHeader, title), ui.colorize(colorHeader, strings.Repeat("=", len(title))))
}

func (ui terminalUI) Section(title string) {
	fmt.Fprintf(ui.w, "\n%s\n%s\n", ui.colorize(colorHeader, title), ui.colorize(colorHeader, strings.Repeat("─", len(title))))
}

func (ui terminalUI) Value(label, value string) {
	role := terminalColor("")
	switch label {
	case "Path", "Configured vault":
		role = colorLocation
	case "User", "System":
		role = colorIdentity
	case "Snapshots", "Pending uploads":
		role = colorWarning
	}
	if role != "" {
		value = ui.colorize(role, value)
	}
	fmt.Fprintf(ui.w, "%s %s\n", label+":", value)
}

func (ui terminalUI) Status(label, value string) {
	role := terminalColor("")
	state := value
	if separator := strings.IndexByte(state, ' '); separator >= 0 {
		state = state[:separator]
	}
	switch state {
	case "problem", "error", "unreachable", "unsafe-permissions", "keyring-unavailable":
		role = colorFailure
	case "warning", "partial", "not-configured", "not-running", "disabled", "enabled-but-inactive", "unknown":
		role = colorWarning
	}
	if role != "" && strings.HasPrefix(value, state) {
		value = ui.colorize(role, state) + value[len(state):]
	}
	fmt.Fprintf(ui.w, "%s %s\n", label+":", value)
}

func (ui terminalUI) Command(command string) {
	fmt.Fprintf(ui.w, "\n%s\n", ui.colorize(colorCommand, "$ "+command))
}

func (ui terminalUI) CommandBlock(commands string) {
	fmt.Fprintf(ui.w, "\n%s\n", ui.colorize(colorHeader, commandRule))
	for _, command := range strings.Split(strings.TrimSpace(commands), "\n") {
		if command == "" {
			continue
		}
		fmt.Fprintf(ui.w, "%s\n", ui.colorize(colorCommand, "  "+command))
	}
	fmt.Fprintf(ui.w, "%s\n\n", ui.colorize(colorHeader, commandRule))
}

func (ui terminalUI) Text(role terminalColor, value string) {
	fmt.Fprintln(ui.w, ui.colorize(role, value))
}

func (ui terminalUI) Decision(decision setupDecision) {
	fmt.Fprintf(ui.w, "\n╭─ %s ─────────────────────────────────────────╮\n", ui.colorize(colorCommand, "Decision confirmed"))
	ui.panelLine("", "")
	ui.panelLine("Decision: "+decision.Decision, colorCommand)
	ui.panelLine(decision.Title, "")
	ui.panelLine("Effect: "+decision.Effect, "")
	if decision.Next != "" {
		ui.panelLine("Next: "+decision.Next, "")
	}
	fmt.Fprintln(ui.w, "╰─────────────────────────────────────────────╯")
	fmt.Fprintln(ui.w)
}

func (ui terminalUI) panelLine(value string, role terminalColor) {
	const width = 43
	for _, line := range wrapText(value, width) {
		padding := width - len([]rune(line))
		if padding < 0 {
			padding = 0
		}
		fmt.Fprint(ui.w, "│ ")
		if role != "" {
			fmt.Fprint(ui.w, ui.colorize(role, line))
		} else {
			fmt.Fprint(ui.w, line)
		}
		fmt.Fprintf(ui.w, "%s │\n", strings.Repeat(" ", padding))
	}
}

func wrapText(value string, width int) []string {
	if value == "" {
		return []string{""}
	}
	words := strings.Fields(value)
	lines := []string{""}
	for _, word := range words {
		current := lines[len(lines)-1]
		candidate := word
		if current != "" {
			candidate = current + " " + word
		}
		if len([]rune(candidate)) <= width {
			lines[len(lines)-1] = candidate
			continue
		}
		lines = append(lines, word)
	}
	return lines
}

func (ui terminalUI) Error(title, happened, why, fix, next string) {
	ui.Section(title)
	ui.Failure(title)
	fmt.Fprintf(ui.w, "What happened\n%s\n\nWhy it matters\n%s\n\nHow to fix it\n%s\n\nWhat to do next\n%s\n", happened, why, fix, next)
}

func (ui terminalUI) Failure(value string) {
	fmt.Fprintf(ui.w, "%s\n", ui.colorize(colorFailure, value))
}

func renderSetupFailure(w io.Writer, home string, err error) {
	ui := newTerminalUI(w)
	ui.Header("Setup needs attention")
	ui.Section("What happened")
	ui.Failure("The setup could not finish the first local capture.")
	ui.Section("Why it matters")
	ui.Text(colorSecondary, "Cifrarium stopped before any remote upload. Correct the input and retry the local setup.")
	ui.Section("How to fix it")
	if path, ok := rejectedSymlinkPath(home, err); ok {
		ui.Text(colorSecondary, "Cifrarium does not follow symlinks during capture.")
		ui.Value("Adapter path", path)
		ui.Text(colorSecondary, "If this link is managed intentionally, materialize a regular file through its managing tool.")
	} else if path, cause, ok := capturePathDiagnostic(home, err); ok {
		ui.Value("Adapter path", path)
		ui.Text(colorSecondary, cause)
		ui.Text(colorSecondary, "Correct this path without disabling capture safety, then run setup again.")
	} else {
		ui.Text(colorSecondary, "Review the reported adapter path and correct it without disabling capture safety.")
	}
	ui.Section("What to do next")
	ui.Command("cifrarium setup")
}

func renderDaemonFailure(w io.Writer, home string, err error) {
	ui := newTerminalUI(w)
	reason := daemonUploadFailureReasonFor(err)
	ui.Header("Daemon needs attention")
	ui.Section("What happened")
	if reason != daemonUploadNone {
		ui.Failure("The daemon could not upload pending encrypted work.")
	} else {
		ui.Failure("The daemon could not complete its recovery snapshot.")
	}
	ui.Section("Why it matters")
	if reason != daemonUploadNone {
		ui.Text(colorSecondary, "Cifrarium preserved the encrypted pending queue and stopped before remote upload. Existing vault history was preserved.")
	} else {
		ui.Text(colorSecondary, "Cifrarium stopped this capture before saving or uploading a new snapshot. Existing vault history was preserved.")
	}
	ui.Section("How to fix it")
	if path, ok := rejectedSymlinkPath(home, err); ok {
		ui.Text(colorSecondary, "Cifrarium does not follow symlinks during capture.")
		ui.Value("Adapter path", path)
		ui.Text(colorSecondary, "Leave the daemon stopped. If this link is managed intentionally, materialize a regular file through its managing tool.")
		ui.CommandBlock("cifrarium snapshot\nsystemctl --user start cifrarium.service")
	} else if reason != daemonUploadNone {
		renderDaemonUploadGuidance(ui, reason)
	} else if path, cause, ok := capturePathDiagnostic(home, err); ok {
		ui.Value("Adapter path", path)
		ui.Text(colorSecondary, cause)
		ui.Text(colorSecondary, "Correct this path without disabling capture safety, then run `cifrarium snapshot` before starting the daemon again.")
	} else {
		ui.Text(colorSecondary, "Review the reported adapter path and correct it without disabling capture safety.")
		ui.Command("cifrarium doctor")
	}
	ui.Section("What to do next")
	if reason != daemonUploadNone {
		ui.Text(colorWarning, "Do not delete pending.queue or put recovery material in shell history. Use another console for the corrective action, then return here and press Enter or wait for the retry.")
	} else {
		ui.Text(colorWarning, "Do not use rm, source, sudo, or a symlink-following override. Keep the daemon stopped until a local snapshot succeeds.")
	}
}

func daemonUploadGateFailure(err error) bool {
	return daemonUploadFailureReasonFor(err) != daemonUploadNone
}

type daemonUploadFailureReason uint8

const (
	daemonUploadNone daemonUploadFailureReason = iota
	daemonUploadRecovery
	daemonUploadPrivacy
	daemonUploadProvider
	daemonUploadAccess
)

func daemonUploadFailureReasonFor(err error) daemonUploadFailureReason {
	var captureFailure interface{ CaptureFailure() }
	if errors.As(err, &captureFailure) {
		return daemonUploadNone
	}
	value := strings.ToLower(err.Error())
	switch {
	case strings.Contains(value, "recovery verification required before upload"):
		return daemonUploadRecovery
	case strings.Contains(value, "private repository verification required before upload"):
		return daemonUploadPrivacy
	case strings.Contains(value, "provider is not configured"):
		return daemonUploadProvider
	case strings.Contains(value, "provider"), strings.Contains(value, "upload"), strings.Contains(value, "remote"):
		return daemonUploadAccess
	default:
		return daemonUploadNone
	}
}

func renderDaemonUploadGuidance(ui terminalUI, reason daemonUploadFailureReason) {
	switch reason {
	case daemonUploadRecovery:
		ui.Text(colorSecondary, "The pending snapshots need protected recovery verification for the active vault before remote upload can continue.")
		ui.CommandBlock("cifrarium provider setup\ncifrarium doctor")
		ui.Text(colorSecondary, "In another console, validate or configure the protected recovery settings. Do not paste their values into this terminal.")
	case daemonUploadPrivacy:
		ui.Text(colorSecondary, "The configured provider must be confirmed private before Cifrarium can upload encrypted snapshots.")
		ui.CommandBlock("cifrarium provider health --verify-private")
		ui.Text(colorSecondary, "In another console, make the configured repository private or correct its access, then return here.")
	case daemonUploadProvider:
		ui.Text(colorSecondary, "No provider is configured for the daemon, so pending encrypted snapshots cannot be uploaded.")
		ui.CommandBlock("cifrarium provider setup")
		ui.Text(colorSecondary, "Configure the provider in another console, or keep the daemon disabled for local-only snapshots.")
	default:
		ui.Text(colorSecondary, "The configured provider could not accept the pending encrypted snapshots.")
		ui.CommandBlock("cifrarium provider health --verify-private")
		ui.Text(colorSecondary, "In another console, restore provider access and privacy, then return here.")
	}
}

func rejectedSymlinkPath(home string, err error) (string, bool) {
	if path, cause, ok := capturePathDiagnostic(home, err); ok && cause == "Cifrarium rejected a symbolic link during capture." {
		return path, true
	}
	const marker = "symlink rejected: "
	const recoverySuffix = "; recovery snapshot failed"
	value := err.Error()
	index := strings.Index(value, marker)
	if index < 0 {
		return "", false
	}
	path := strings.TrimSpace(value[index+len(marker):])
	if suffixIndex := strings.Index(path, recoverySuffix); suffixIndex >= 0 {
		path = strings.TrimSpace(path[:suffixIndex])
	}
	if path == "" {
		return "", false
	}
	if filepath.IsAbs(path) {
		clean := filepath.Clean(path)
		relative, relErr := filepath.Rel(home, clean)
		if relErr != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return "", false
		}
		path = relative
	}
	if filepath.Clean(path) != path {
		return "", false
	}
	if path == ".." || strings.HasPrefix(path, ".."+string(filepath.Separator)) {
		return "", false
	}
	path = filepath.ToSlash(path)
	if !allowedCaptureRelativePath(path) {
		return "", false
	}
	return path, true
}

func capturePathDiagnostic(home string, err error) (string, string, bool) {
	var pathErr *os.PathError
	if !errors.As(err, &pathErr) || pathErr == nil || pathErr.Err == nil {
		return "", "", false
	}
	path := pathErr.Path
	if filepath.IsAbs(path) {
		relative, relErr := filepath.Rel(home, filepath.Clean(path))
		if relErr != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return "", "", false
		}
		path = relative
	}
	path = filepath.ToSlash(path)
	if filepath.IsAbs(path) || filepath.ToSlash(filepath.Clean(filepath.FromSlash(path))) != path || !allowedCaptureRelativePath(path) {
		return "", "", false
	}
	message := strings.ToLower(pathErr.Err.Error())
	switch {
	case strings.Contains(message, "symlink rejected") || errors.Is(pathErr.Err, syscall.ELOOP):
		return path, "Cifrarium rejected a symbolic link during capture.", true
	case os.IsPermission(pathErr.Err):
		return path, "Cifrarium could not read this path because of file permissions.", true
	case strings.Contains(message, "unsupported custom entry"):
		return path, "This adapter path contains an unsupported file type.", true
	default:
		return path, "Cifrarium could not safely read this allowlisted path.", true
	}
}

func allowedCaptureRelativePath(path string) bool {
	switch path {
	case ".codex/AGENTS.md", ".codex/config.toml", ".zshrc", ".zprofile", ".config/starship.toml", ".oh-my-zsh/custom":
		return true
	}
	if !strings.HasPrefix(path, ".oh-my-zsh/custom/") {
		return false
	}
	for _, component := range strings.Split(path, "/") {
		if component == "" || component == "." || component == ".." || strings.HasPrefix(component, ".") && component != ".oh-my-zsh" {
			return false
		}
	}
	return !strings.Contains(path, "\\")
}
