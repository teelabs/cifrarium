package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/teelabs/cifrarium/internal/daemon"
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
		ui.Text(colorSecondary, "No validated adapter path or safe cause was identified. Do not change adapter paths based on this message.")
		ui.Command("cifrarium doctor -format=json")
	}
	ui.Section("What to do next")
	ui.Command("cifrarium setup")
}

func renderDaemonFailure(w io.Writer, home string, err error) {
	ui := newTerminalUI(w)
	reason := daemonUploadFailureReasonFor(err)
	var enqueueFailure *daemon.QueueEnqueueFailure
	hasEnqueueFailure := errors.As(err, &enqueueFailure)
	var uploadFailure *daemon.UploadFailure
	hasUploadFailure := errors.As(err, &uploadFailure)
	var persistenceFailure *daemon.PersistenceError
	hasPersistenceFailure := errors.As(err, &persistenceFailure)
	var recoveryQueueFailure *daemon.RecoveryQueueFailure
	hasRecoveryQueueFailure := errors.As(err, &recoveryQueueFailure)
	var recoveryFailure *daemon.RecoverySnapshotError
	hasRecoveryFailure := errors.As(err, &recoveryFailure)
	var captureErr *daemon.CaptureError
	isCaptureFailure := errors.As(err, &captureErr)
	ui.Header("Daemon needs attention")
	ui.Section("What happened")
	if hasEnqueueFailure && errors.Is(enqueueFailure.Enqueue, daemon.ErrQueueFull) {
		ui.Failure("Upload of the new snapshot was not confirmed, and it could not be queued because the pending queue is full.")
	} else if hasEnqueueFailure {
		ui.Failure("Upload of the new snapshot was not confirmed, and it could not be retained in the pending queue.")
	} else if hasRecoveryQueueFailure && errors.Is(recoveryQueueFailure.Enqueue, daemon.ErrQueueFull) {
		ui.Failure("Initial work failed, and the recovery snapshot could not be queued because the pending queue is full.")
	} else if hasRecoveryQueueFailure {
		ui.Failure("Initial work failed, and the recovery snapshot could not be retained in the pending queue.")
	} else if hasPersistenceFailure && persistenceFailure.Stage == daemon.PersistenceStagePendingDrain {
		ui.Failure("A pending upload may have completed, but removing it from the queue could not be persisted.")
	} else if hasPersistenceFailure && persistenceFailure.Stage == daemon.PersistenceStageSnapshot {
		ui.Failure("Upload of the new snapshot was not confirmed, and the pending queue update could not be persisted.")
	} else if hasPersistenceFailure {
		ui.Failure("A recovery queue update could not be persisted.")
	} else if reason != daemonUploadNone && hasRecoveryFailure {
		ui.Failure("The daemon could not confirm a pending upload or complete its recovery snapshot.")
	} else if hasUploadFailure && uploadFailure.Stage == daemon.UploadStageSnapshot {
		ui.Failure("The daemon could not confirm upload of the newly captured snapshot.")
	} else if reason != daemonUploadNone {
		ui.Failure("The daemon could not upload pending encrypted work.")
	} else if hasRecoveryFailure {
		ui.Failure("The initial snapshot and its recovery snapshot both failed.")
	} else if isCaptureFailure {
		ui.Failure("The daemon could not complete its local snapshot.")
	} else {
		ui.Failure("The daemon could not complete its initial work.")
	}
	ui.Section("Why it matters")
	if hasEnqueueFailure && errors.Is(enqueueFailure.Enqueue, daemon.ErrQueueFull) {
		ui.Text(colorSecondary, "The local snapshot was captured, but upload was not confirmed and this new item was not queued. Existing pending.queue entries remain intact.")
	} else if hasEnqueueFailure {
		ui.Text(colorSecondary, "The local snapshot was captured, but upload was not confirmed and this new item could not be queued. Existing pending.queue entries remain intact.")
	} else if hasRecoveryQueueFailure {
		ui.Text(colorSecondary, "A local recovery snapshot was captured but not queued; existing pending.queue entries remain intact. The initial failure is not safe to display here.")
	} else if hasPersistenceFailure && persistenceFailure.Stage == daemon.PersistenceStagePendingDrain {
		ui.Text(colorSecondary, "The queue entry remains available for retry; the provider may already have accepted it, so a later retry may repeat the same encrypted snapshot.")
	} else if hasPersistenceFailure && persistenceFailure.Stage == daemon.PersistenceStageSnapshot {
		ui.Text(colorSecondary, "The local snapshot was captured, but its upload was not confirmed and its new pending queue entry may not have reached disk.")
	} else if hasPersistenceFailure {
		ui.Text(colorSecondary, "A recovery snapshot queue update was attempted, but its persisted state could not be confirmed.")
	} else if reason != daemonUploadNone && hasRecoveryFailure {
		ui.Text(colorSecondary, "The encrypted pending queue was preserved because the provider upload was not confirmed. The follow-up recovery snapshot also failed.")
	} else if hasUploadFailure && uploadFailure.Stage == daemon.UploadStageSnapshot {
		ui.Text(colorSecondary, "The local snapshot was captured and retained in pending.queue, but upload was not confirmed. Existing vault history was preserved.")
	} else if reason != daemonUploadNone {
		ui.Text(colorSecondary, "Cifrarium preserved the encrypted pending queue and stopped before remote upload. Existing vault history was preserved.")
	} else if hasRecoveryFailure {
		ui.Text(colorSecondary, "Cifrarium could not confirm a completed initial or recovery snapshot. The underlying errors are not safe to display in this message.")
	} else if isCaptureFailure {
		renderCaptureFailureImpact(ui, captureErr.Stage)
	} else {
		ui.Text(colorSecondary, "Cifrarium could not confirm a completed snapshot. The underlying error is not safe to display in this message.")
	}
	ui.Section("How to fix it")
	if hasPersistenceFailure {
		ui.Text(colorSecondary, "Preserve the vault and pending.queue. Inspect local status and provider health before any retry; do not edit the queue manually.")
		renderStopDaemonForDiagnostics(ui, w)
	} else if hasEnqueueFailure {
		ui.Text(colorSecondary, "Inspect the pending count and resolve the upload prerequisite before allowing retries; do not delete or edit pending.queue.")
		renderStopDaemonForDiagnostics(ui, w)
		renderDaemonUploadGuidance(ui, reason)
	} else if hasRecoveryQueueFailure {
		ui.Text(colorSecondary, "Keep the daemon stopped and preserve the vault and pending.queue. Inspect local state before retrying; do not edit the queue manually.")
		renderStopDaemonForDiagnostics(ui, w)
		if reason == daemonUploadNone {
			ui.Command("cifrarium doctor -format=json")
		} else {
			renderDaemonUploadGuidance(ui, reason)
		}
	} else if reason != daemonUploadNone && hasRecoveryFailure {
		renderDaemonUploadGuidance(ui, reason)
		renderRecoverySnapshotGuidance(ui, home, recoveryFailure.Recovery)
	} else if isCaptureFailure && captureErr.Stage == daemon.CaptureStageAdapters {
		if path, ok := rejectedSymlinkPath(home, err); ok {
			ui.Text(colorSecondary, "Cifrarium does not follow symlinks during capture.")
			ui.Value("Adapter path", path)
			ui.Text(colorSecondary, "If this link is managed intentionally, materialize a regular file through its managing tool.")
			renderLocalSnapshotRecovery(ui, w, false)
		} else if path, cause, ok := capturePathDiagnostic(home, err); ok {
			ui.Value("Adapter path", path)
			ui.Text(colorSecondary, cause)
			ui.Text(colorSecondary, "Correct this path without disabling capture safety.")
			renderLocalSnapshotRecovery(ui, w, false)
		} else {
			ui.Text(colorSecondary, "No validated adapter path was identified; do not change adapter paths based on this message.")
			ui.Command("cifrarium doctor -format=json")
			renderLocalSnapshotRecovery(ui, w, true)
		}
	} else if reason != daemonUploadNone {
		renderDaemonUploadGuidance(ui, reason)
	} else if isCaptureFailure {
		renderCaptureStageGuidance(ui, captureErr.Stage)
	} else {
		ui.Text(colorSecondary, "No validated adapter path or safe cause was identified. Do not change adapter paths based on this message.")
		ui.Command("cifrarium doctor -format=json")
		renderLocalSnapshotRecovery(ui, w, true)
	}
	ui.Section("What to do next")
	if hasPersistenceFailure || hasRecoveryQueueFailure {
		ui.Text(colorWarning, "Do not delete or edit pending.queue. Do not restart the daemon until local state and provider health have been checked.")
	} else if hasEnqueueFailure {
		ui.Text(colorWarning, "Do not delete pending.queue. Resolve the provider or queue issue first; the new local snapshot was not retained for upload.")
	} else if reason != daemonUploadNone && hasRecoveryFailure {
		ui.Text(colorWarning, "Preserve pending.queue. Keep the daemon stopped until a local snapshot succeeds; resolve the provider issue before allowing queued uploads to retry.")
	} else if reason != daemonUploadNone {
		ui.Text(colorWarning, "Do not delete pending.queue or put recovery material in shell history. Use another console for the corrective action, then return here and press Enter or wait for the retry.")
	} else if hasRecoveryFailure {
		ui.Text(colorWarning, "Keep the daemon stopped until a local snapshot succeeds. Do not alter adapter paths unless a validated path is shown above.")
	} else if isCaptureFailure {
		ui.Text(colorWarning, "Do not use rm, source, sudo, or a symlink-following override. Keep the daemon stopped until a local snapshot succeeds.")
	} else {
		ui.Text(colorWarning, "Keep the daemon stopped until `cifrarium doctor -format=json` reports the backend state and a local snapshot succeeds.")
	}
}

func renderStopDaemonForDiagnostics(ui terminalUI, w io.Writer) {
	if writerIsTerminal(w) {
		ui.Text(colorSecondary, "For a foreground daemon already retrying, press Ctrl+C to stop it, or answer `n` at the next Retry? prompt. For a systemd-managed daemon, stop the service before these read-only checks.")
		ui.Command("cifrarium status -format=json")
		ui.Command("cifrarium provider health --verify-private")
		return
	}
	ui.Text(colorSecondary, "Stop the systemd-managed daemon before running these read-only checks. For a foreground daemon, answer `n` at Retry? first.")
	ui.CommandBlock("systemctl --user stop cifrarium.service\ncifrarium status -format=json\ncifrarium provider health --verify-private")
}

func renderLocalSnapshotRecovery(ui terminalUI, w io.Writer, inspectDoctor bool) {
	if writerIsTerminal(w) {
		ui.Text(colorSecondary, "For a foreground daemon, answer `n` to Retry? to exit before running a local snapshot.")
		if inspectDoctor {
			ui.Command("cifrarium doctor -format=json")
		}
		ui.Command("cifrarium snapshot")
		return
	}
	ui.Text(colorSecondary, "Exit a foreground daemon with `n` at Retry?; stop the systemd service with `systemctl --user stop cifrarium.service` before a local snapshot.")
	commands := "systemctl --user stop cifrarium.service"
	if inspectDoctor {
		commands += "\ncifrarium doctor -format=json"
	}
	commands += "\ncifrarium snapshot"
	ui.CommandBlock(commands)
}

func renderRecoverySnapshotGuidance(ui terminalUI, home string, err error) {
	var captureErr *daemon.CaptureError
	if errors.As(err, &captureErr) && captureErr.Stage == daemon.CaptureStageAdapters {
		if path, ok := rejectedSymlinkPath(home, err); ok {
			ui.Value("Recovery adapter path", path)
			ui.Text(colorSecondary, "The local recovery snapshot rejected a symbolic link.")
			ui.Text(colorSecondary, "Materialize a regular file through its managing tool; do not follow the link or disable capture safety.")
		} else if path, cause, ok := capturePathDiagnostic(home, err); ok {
			ui.Value("Recovery adapter path", path)
			ui.Text(colorSecondary, cause)
		} else {
			ui.Text(colorSecondary, "The recovery snapshot could not read adapter data; no validated path was identified.")
		}
		renderLocalSnapshotRecovery(ui, ui.w, false)
		return
	}
	if errors.As(err, &captureErr) {
		ui.Text(colorSecondary, "The recovery snapshot failed during local snapshot preparation ("+safeCaptureStage(captureErr.Stage)+").")
		renderLocalSnapshotRecovery(ui, ui.w, true)
		return
	}
	ui.Text(colorSecondary, "The follow-up recovery snapshot also failed; its underlying error is not safe to display.")
}

func safeCaptureStage(stage daemon.CaptureStage) string {
	switch stage {
	case daemon.CaptureStageAdapters, daemon.CaptureStageVaultWrite, daemon.CaptureStageSnapshotRead, daemon.CaptureStageManifestPreparation:
		return string(stage)
	default:
		return "unknown"
	}
}

func renderCaptureFailureImpact(ui terminalUI, stage daemon.CaptureStage) {
	switch stage {
	case daemon.CaptureStageAdapters:
		ui.Text(colorSecondary, "Cifrarium stopped before writing a new snapshot or uploading it. Existing vault history was preserved.")
	case daemon.CaptureStageVaultWrite:
		ui.Text(colorSecondary, "The local encrypted snapshot could not be persisted. Verify vault health before retrying; no provider upload was attempted.")
	case daemon.CaptureStageSnapshotRead, daemon.CaptureStageManifestPreparation:
		ui.Text(colorSecondary, "Snapshot data may already be present locally, but Cifrarium did not attempt a provider upload. Check vault health before retrying.")
	default:
		ui.Text(colorSecondary, "Cifrarium could not confirm whether a local snapshot was completed. Check vault health before retrying.")
	}
}

func renderCaptureStageGuidance(ui terminalUI, stage daemon.CaptureStage) {
	switch stage {
	case daemon.CaptureStageVaultWrite:
		ui.Text(colorSecondary, "Cifrarium could not persist an encrypted snapshot in the local vault.")
	case daemon.CaptureStageSnapshotRead:
		ui.Text(colorSecondary, "Cifrarium saved snapshot data but could not read it back for upload preparation.")
	case daemon.CaptureStageManifestPreparation:
		ui.Text(colorSecondary, "Cifrarium saved snapshot data but could not prepare its encrypted manifest for upload.")
	default:
		ui.Text(colorSecondary, "Cifrarium could not complete local snapshot preparation.")
	}
	ui.Command("cifrarium doctor -format=json")
	ui.Text(colorSecondary, "Keep the daemon stopped until the local vault is healthy and a local snapshot succeeds.")
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
	daemonUploadUnknown
)

func daemonUploadFailureReasonFor(err error) daemonUploadFailureReason {
	if err == nil {
		return daemonUploadNone
	}
	var recoveryFailure *daemon.RecoverySnapshotError
	if errors.As(err, &recoveryFailure) {
		return daemonUploadFailureReasonFor(recoveryFailure.Primary)
	}
	var uploadFailure *daemon.UploadFailure
	if errors.As(err, &uploadFailure) {
		if reason := daemonUploadFailureReasonFor(uploadFailure.Err); reason != daemonUploadNone {
			return reason
		}
		return daemonUploadUnknown
	}
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
	case daemonUploadUnknown:
		ui.Text(colorSecondary, "The upload could not be classified safely. Check backend and provider health; do not change recovery configuration or edit pending.queue based on this message.")
		ui.CommandBlock("cifrarium doctor -format=json\ncifrarium provider health --verify-private")
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
	return "", false
}

func capturePathDiagnostic(home string, err error) (string, string, bool) {
	var captureErr *daemon.CaptureError
	if !errors.As(err, &captureErr) || captureErr.Stage != daemon.CaptureStageAdapters {
		return "", "", false
	}
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
