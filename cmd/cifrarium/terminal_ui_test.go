package main

import (
	"bytes"
	"errors"
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
	ui.Value("Path", "/home/thiago/.config/cifrarium")
	ui.Command("cifrarium setup --root '/home/thiago/.local/share/cifrarium'")

	text := out.String()
	if !strings.Contains(text, ansiBlue+"/home/thiago/.config/cifrarium"+ansiReset) {
		t.Fatalf("path was not colorized: %q", text)
	}
	if !strings.Contains(text, ansiGreen+"$ cifrarium setup --root") {
		t.Fatalf("command was not colorized: %q", text)
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
	renderSetupFailure(&out, "/home/thiago", errors.New("first capture: symlink rejected: .zshrc"))
	text := out.String()
	for _, want := range []string{"What happened", "Why it matters", "How to fix it", "What to do next", "cifrarium setup"} {
		if !strings.Contains(text, want) {
			t.Fatalf("setup error missing %q: %q", want, text)
		}
	}
	if !strings.Contains(text, "/home/thiago/.zshrc") {
		t.Fatalf("setup error did not identify the path: %q", text)
	}
}

func TestRenderDaemonFailureUsesSafeSymlinkRecoveryInstructions(t *testing.T) {
	var out bytes.Buffer
	renderDaemonFailure(&out, "/home/thiago", errors.New("recovery snapshot failed: symlink rejected: .zshrc"))
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
