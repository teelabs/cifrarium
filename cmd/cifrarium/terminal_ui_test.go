package main

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTerminalUIPlainDecisionUsesSeparateBlocks(t *testing.T) {
	var out bytes.Buffer
	ui := newTerminalUI(&out)
	ui.Decision(setupDecision{Title: "Private backup", Decision: "enabled", Effect: "Commands will be prepared locally; no remote repository changed.", Next: "first local capture"})

	text := out.String()
	if strings.Contains(text, "\x1b[") {
		t.Fatalf("plain output contains ANSI escape sequence: %q", text)
	}
	for _, want := range []string{"Decision confirmed", "Private backup", "Decision: enabled", "Effect:", "Next: first local capture"} {
		if !strings.Contains(text, want) {
			t.Fatalf("decision output missing %q: %q", want, text)
		}
	}
	if !strings.Contains(text, "\n\n") {
		t.Fatalf("decision output has no visual spacing: %q", text)
	}
}

func TestTerminalUIDecisionWrapsLongTextInsidePanel(t *testing.T) {
	var out bytes.Buffer
	ui := newTerminalUI(&out)
	ui.Decision(setupDecision{
		Title:    "Private backup",
		Decision: "enabled",
		Effect:   "Commands will be prepared locally and no remote repository will be changed until you run them yourself.",
		Next:     "first local encrypted capture",
	})
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if strings.HasPrefix(line, "│") && utf8.RuneCountInString(line) > 49 {
			t.Fatalf("panel line is too wide: %d %q", utf8.RuneCountInString(line), line)
		}
	}
}

func TestTerminalUIColorizesSemanticValuesOnlyWhenEnabled(t *testing.T) {
	var out bytes.Buffer
	ui := terminalUI{w: &out, color: true}
	home := t.TempDir()
	configPath := filepath.Join(home, ".config", "cifrarium")
	rootPath := filepath.Join(home, ".local", "share", "cifrarium")
	ui.Value("Path", configPath)
	ui.Command("cifrarium setup --root " + shellQuote(rootPath))

	text := out.String()
	if !strings.Contains(text, "\x1b[38;2;121;192;255m"+configPath+ansiReset) {
		t.Fatalf("path was not colorized: %q", text)
	}
	if !strings.Contains(text, "\x1b[38;2;63;185;80m$ cifrarium setup --root") {
		t.Fatalf("command was not colorized: %q", text)
	}
}

func TestTerminalUICommandBlockSeparatesCopyableInstructions(t *testing.T) {
	var out bytes.Buffer
	ui := terminalUI{w: &out, color: false}
	ui.Section("How to fix it")
	ui.CommandBlock("systemctl --user stop cifrarium.service\ncifrarium snapshot")
	ui.Section("What to do next")

	text := out.String()
	if strings.Count(text, commandRule) != 2 {
		t.Fatalf("command block did not provide visual boundaries: %q", text)
	}
	if !strings.Contains(text, "cifrarium snapshot\n"+commandRule) {
		t.Fatalf("command block is not separated from the next section: %q", text)
	}
}

func TestCollectSetupChoicesReportsEachDecisionImmediately(t *testing.T) {
	answers := []bool{true, true, false, true}
	var decisions []setupDecision
	index := 0
	choices, err := collectSetupChoicesWithFeedback(func(string) (bool, error) {
		answer := answers[index]
		index++
		return answer, nil
	}, func(decision setupDecision) {
		decisions = append(decisions, decision)
	})
	if err != nil {
		t.Fatal(err)
	}
	if choices != (setupChoices{Provider: true, Capture: false, Activate: true}) {
		t.Fatalf("choices=%+v", choices)
	}
	if len(decisions) != 4 {
		t.Fatalf("decisions=%d, want 4", len(decisions))
	}
	if decisions[0].Title != "Recovery shares" || decisions[0].Decision != "saved" {
		t.Fatalf("first decision=%+v", decisions[0])
	}
	if decisions[2].Title != "First local capture" || decisions[2].Decision != "skipped" {
		t.Fatalf("third decision=%+v", decisions[2])
	}
}

func TestRenderSetupFailureUsesActionableSections(t *testing.T) {
	var out bytes.Buffer
	home := t.TempDir()
	renderSetupFailure(&out, home, errors.New("first capture: symlink rejected: .zshrc"))
	text := out.String()
	for _, want := range []string{"What happened", "Why it matters", "How to fix it", "What to do next", "cifrarium setup"} {
		if !strings.Contains(text, want) {
			t.Fatalf("setup error missing %q: %q", want, text)
		}
	}
	if !strings.Contains(text, filepath.Join(home, ".zshrc")) {
		t.Fatalf("setup error did not identify the path: %q", text)
	}
}

func TestRenderDaemonFailureUsesSafeSymlinkRecoveryInstructions(t *testing.T) {
	var out bytes.Buffer
	home := t.TempDir()
	renderDaemonFailure(&out, home, errors.New("recovery snapshot failed: symlink rejected: .zshrc"))
	text := out.String()
	for _, want := range []string{
		"What happened",
		"Why it matters",
		"How to fix it",
		"systemctl --user stop cifrarium.service",
		"cp --dereference --preserve=mode",
		"test ! -L",
		"mv",
		"cifrarium snapshot",
		"systemctl --user start cifrarium.service",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("daemon error missing %q: %q", want, text)
		}
	}
	for _, forbidden := range []string{"CIFRARIUM_RECOVERY_SHARE", "token", "source ", "sudo ", ".zshrc-starship"} {
		if strings.Contains(strings.ToLower(text), strings.ToLower(forbidden)) {
			t.Fatalf("daemon error leaked or encouraged %q: %q", forbidden, text)
		}
	}
}

func TestRenderDaemonFailureUsesSafePendingRecoveryInstructions(t *testing.T) {
	var out bytes.Buffer
	renderDaemonFailure(&out, t.TempDir(), errors.New("recovery verification required before upload"))
	text := strings.ToLower(out.String())
	for _, want := range []string{"pending encrypted work", "cifrarium doctor", "protected recovery"} {
		if !strings.Contains(text, want) {
			t.Fatalf("pending recovery diagnostic missing %q: %q", want, out.String())
		}
	}
	for _, forbidden := range []string{"recovery verification required before upload", "share", "token"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("pending recovery diagnostic leaked %q: %q", forbidden, out.String())
		}
	}
}

func TestRejectedSymlinkPathStopsBeforeRecoverySnapshotSuffix(t *testing.T) {
	home := t.TempDir()
	got, ok := rejectedSymlinkPath(home, errors.New("symlink rejected: .zshrc; recovery snapshot failed: symlink rejected: .zshrc"))
	want := filepath.Join(home, ".zshrc")
	if !ok || got != want {
		t.Fatalf("rejectedSymlinkPath() = %q, %t; want %s, true", got, ok, want)
	}
}

func TestRejectedSymlinkPathFailsClosedForTraversalAndExternalAbsolutePaths(t *testing.T) {
	for _, errText := range []string{
		"symlink rejected: ../outside",
		"symlink rejected: /tmp/outside",
		"symlink rejected: ../../outside/.zshrc; recovery snapshot failed: ignored",
	} {
		if got, ok := rejectedSymlinkPath(t.TempDir(), errors.New(errText)); ok || got != "" {
			t.Fatalf("rejectedSymlinkPath(%q) = %q, %t; want empty, false", errText, got, ok)
		}
	}
}

func TestRenderDaemonFailureDoesNotEchoRawErrorOrSensitiveSymlinkTarget(t *testing.T) {
	var out bytes.Buffer
	home := t.TempDir()
	renderDaemonFailure(&out, home, errors.New("recovery snapshot failed: symlink rejected: .zshrc; recovery snapshot failed: symlink rejected: /secret/target"))
	text := out.String()
	for _, forbidden := range []string{"/secret/target", "recovery snapshot failed", "CIFRARIUM_RECOVERY_SHARE", "token"} {
		if strings.Contains(strings.ToLower(text), strings.ToLower(forbidden)) {
			t.Fatalf("daemon error leaked %q: %q", forbidden, text)
		}
	}
	if !strings.Contains(text, filepath.Join(home, ".zshrc")) {
		t.Fatalf("daemon error did not show the valid path: %q", text)
	}
}

func TestRenderDaemonFailureKeepsSafeInstructionOrder(t *testing.T) {
	var out bytes.Buffer
	renderDaemonFailure(&out, t.TempDir(), errors.New("recovery snapshot failed: symlink rejected: .zshrc"))
	text := out.String()
	sections := []string{"Daemon needs attention", "What happened", "Why it matters", "How to fix it", "What to do next"}
	last := -1
	for _, section := range sections {
		index := strings.Index(text, section)
		if index <= last {
			t.Fatalf("section %q is out of order in %q", section, text)
		}
		last = index
	}
}

func TestTerminalUIPaletteMapsSemanticRoles(t *testing.T) {
	var out bytes.Buffer
	ui := terminalUI{w: &out, color: true}
	home := t.TempDir()
	ui.Header("Header")
	ui.Value("Path", filepath.Join(home, ".zshrc"))
	ui.Value("User", "example-user")
	ui.Value("Pending uploads", "2")
	ui.Status("Daemon", "problem")
	ui.Command("cifrarium snapshot")
	ui.Failure("capture failed")
	text := out.String()
	for _, want := range []string{
		"\x1b[38;2;88;166;255mHeader",
		"\x1b[38;2;121;192;255m" + filepath.Join(home, ".zshrc"),
		"\x1b[38;2;210;168;255mexample-user",
		"\x1b[38;2;210;153;34m2",
		"\x1b[38;2;248;81;73mproblem",
		"\x1b[38;2;63;185;80m$ cifrarium snapshot",
		"\x1b[38;2;248;81;73mcapture failed",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("palette output missing %q: %q", want, text)
		}
	}
}

func TestTerminalUIRedirectedOutputHasNoANSI(t *testing.T) {
	var out bytes.Buffer
	ui := newTerminalUI(&out)
	home := t.TempDir()
	ui.Header("Header")
	ui.Value("Path", filepath.Join(home, ".zshrc"))
	ui.Command("cifrarium snapshot")
	ui.Failure("capture failed")
	if strings.Contains(out.String(), "\x1b[") {
		t.Fatalf("redirected output contains ANSI escape sequence: %q", out.String())
	}
}

func TestCodexPaletteUsesMutedForegroundOnlyColors(t *testing.T) {
	for role, color := range map[terminalColor]string{
		colorHeader:    codexPalette.header,
		colorCommand:   codexPalette.command,
		colorLocation:  codexPalette.location,
		colorWarning:   codexPalette.warning,
		colorFailure:   codexPalette.failure,
		colorIdentity:  codexPalette.identity,
		colorSecondary: codexPalette.secondary,
	} {
		if !strings.HasPrefix(color, "\x1b[38;2;") || !strings.HasSuffix(color, "m") {
			t.Fatalf("%s color=%q, want truecolor foreground", role, color)
		}
		if strings.Contains(color, "\x1b[1m") || strings.Contains(color, "\x1b[4") || strings.Contains(color, "\x1b[48;") {
			t.Fatalf("%s color=%q is bright, underlined, or a background", role, color)
		}
	}
}
