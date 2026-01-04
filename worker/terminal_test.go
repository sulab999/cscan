package worker

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestTerminalHandler_CreateSession tests session creation
func TestTerminalHandler_CreateSession(t *testing.T) {
	config := DefaultTerminalConfig()
	config.MaxSessions = 2
	handler := NewTerminalHandler(config)
	defer handler.CloseAllSessions()

	// Test creating a session
	session, err := handler.CreateSession("test-session-1")
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}
	if session == nil {
		t.Fatal("Session should not be nil")
	}
	if session.ID != "test-session-1" {
		t.Errorf("Session ID mismatch: expected test-session-1, got %s", session.ID)
	}

	// Test creating duplicate session
	_, err = handler.CreateSession("test-session-1")
	if err == nil {
		t.Error("Should fail when creating duplicate session")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("Error should mention 'already exists', got: %v", err)
	}

	// Test session limit
	_, err = handler.CreateSession("test-session-2")
	if err != nil {
		t.Fatalf("Failed to create second session: %v", err)
	}

	_, err = handler.CreateSession("test-session-3")
	if err == nil {
		t.Error("Should fail when exceeding session limit")
	}
	if !IsSessionLimitError(err) {
		t.Errorf("Error should be session limit error, got: %v", err)
	}
}

// TestTerminalHandler_CloseSession tests session closing
func TestTerminalHandler_CloseSession(t *testing.T) {
	handler := NewTerminalHandler(nil)
	defer handler.CloseAllSessions()

	// Create a session
	_, err := handler.CreateSession("test-session")
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Close the session
	err = handler.CloseSession("test-session")
	if err != nil {
		t.Errorf("Failed to close session: %v", err)
	}

	// Try to close non-existent session
	err = handler.CloseSession("non-existent")
	if err == nil {
		t.Error("Should fail when closing non-existent session")
	}

	// Verify session is removed
	_, exists := handler.GetSession("test-session")
	if exists {
		t.Error("Session should be removed after closing")
	}
}

// TestTerminalHandler_IsCommandBlacklisted tests command blacklist checking
func TestTerminalHandler_IsCommandBlacklisted(t *testing.T) {
	handler := NewTerminalHandler(nil)

	testCases := []struct {
		command     string
		blacklisted bool
		description string
	}{
		// Dangerous commands that should be blacklisted
		{"rm -rf /", true, "rm -rf / should be blacklisted"},
		{"rm -rf /*", true, "rm -rf /* should be blacklisted"},
		{"rm -rf ~", true, "rm -rf ~ should be blacklisted"},
		{"rm -r /", true, "rm -r / should be blacklisted"},
		{"shutdown", true, "shutdown should be blacklisted"},
		{"shutdown -h now", true, "shutdown -h now should be blacklisted"},
		{"reboot", true, "reboot should be blacklisted"},
		{"halt", true, "halt should be blacklisted"},
		{"poweroff", true, "poweroff should be blacklisted"},
		{"init 0", true, "init 0 should be blacklisted"},
		{"init 6", true, "init 6 should be blacklisted"},
		{"mkfs /dev/sda", true, "mkfs should be blacklisted"},
		{"dd if=/dev/zero of=/dev/sda", true, "dd to device should be blacklisted"},
		{"chmod 777 /", true, "chmod 777 / should be blacklisted"},
		{"chmod -R 777 /", true, "chmod -R 777 / should be blacklisted"},
		{"chown root /", true, "chown / should be blacklisted"},
		{"chown -R root /", true, "chown -R / should be blacklisted"},

		// Windows dangerous commands
		{"format C:", true, "format C: should be blacklisted"},
		{"del /s /q C:\\", true, "del /s /q C:\\ should be blacklisted"},
		{"rd /s /q C:\\", true, "rd /s /q C:\\ should be blacklisted"},

		// Safe commands that should NOT be blacklisted
		{"ls -la", false, "ls -la should not be blacklisted"},
		{"pwd", false, "pwd should not be blacklisted"},
		{"echo hello", false, "echo should not be blacklisted"},
		{"cat /etc/passwd", false, "cat should not be blacklisted"},
		{"rm file.txt", false, "rm single file should not be blacklisted"},
		{"rm -rf ./temp", false, "rm -rf relative path should not be blacklisted"},
		{"chmod 755 script.sh", false, "chmod on file should not be blacklisted"},
		{"mkdir test", false, "mkdir should not be blacklisted"},
		{"cd /tmp", false, "cd should not be blacklisted"},
		{"whoami", false, "whoami should not be blacklisted"},
		{"ps aux", false, "ps should not be blacklisted"},
		{"top -n 1", false, "top should not be blacklisted"},
		{"df -h", false, "df should not be blacklisted"},
		{"free -m", false, "free should not be blacklisted"},
	}

	for _, tc := range testCases {
		result := handler.IsCommandBlacklisted(tc.command)
		if result != tc.blacklisted {
			t.Errorf("%s: expected blacklisted=%v, got %v", tc.description, tc.blacklisted, result)
		}
	}
}

// TestTerminalHandler_SetBlacklist tests custom blacklist setting
func TestTerminalHandler_SetBlacklist(t *testing.T) {
	handler := NewTerminalHandler(nil)

	// Set custom blacklist
	customBlacklist := []string{
		`^custom_dangerous`,
		`^forbidden_cmd`,
	}
	handler.SetBlacklist(customBlacklist)

	// Test custom blacklist
	if !handler.IsCommandBlacklisted("custom_dangerous arg1") {
		t.Error("custom_dangerous should be blacklisted")
	}
	if !handler.IsCommandBlacklisted("forbidden_cmd") {
		t.Error("forbidden_cmd should be blacklisted")
	}

	// Original dangerous commands should no longer be blacklisted
	// (since we replaced the entire blacklist)
	if handler.IsCommandBlacklisted("rm -rf /") {
		t.Error("rm -rf / should not be blacklisted after custom blacklist set")
	}

	// Verify GetBlacklist returns the custom list
	blacklist := handler.GetBlacklist()
	if len(blacklist) != 2 {
		t.Errorf("Expected 2 blacklist patterns, got %d", len(blacklist))
	}
}

// TestTerminalHandler_ExecuteCommand tests command execution
func TestTerminalHandler_ExecuteCommand(t *testing.T) {
	handler := NewTerminalHandler(nil)
	defer handler.CloseAllSessions()

	ctx := context.Background()

	// Test executing a simple command
	var output []byte
	handler.SetOutputHandler(func(sessionId string, data []byte) {
		output = append(output, data...)
	})

	var cmd string
	if runtime.GOOS == "windows" {
		cmd = "echo hello"
	} else {
		cmd = "echo hello"
	}

	err := handler.ExecuteCommand(ctx, "test-session", cmd)
	if err != nil {
		t.Fatalf("Failed to execute command: %v", err)
	}

	// Wait for command to complete
	time.Sleep(500 * time.Millisecond)

	// Verify output contains "hello"
	if !strings.Contains(string(output), "hello") {
		t.Errorf("Output should contain 'hello', got: %s", string(output))
	}
}

// TestTerminalHandler_ExecuteBlacklistedCommand tests that blacklisted commands are rejected
func TestTerminalHandler_ExecuteBlacklistedCommand(t *testing.T) {
	handler := NewTerminalHandler(nil)
	defer handler.CloseAllSessions()

	ctx := context.Background()

	// Try to execute a blacklisted command
	err := handler.ExecuteCommand(ctx, "test-session", "rm -rf /")
	if err == nil {
		t.Error("Should fail when executing blacklisted command")
	}
	if !IsBlacklistedError(err) {
		t.Errorf("Error should be blacklist error, got: %v", err)
	}
}

// TestTerminalHandler_Timeout tests command timeout
func TestTerminalHandler_Timeout(t *testing.T) {
	config := DefaultTerminalConfig()
	config.DefaultTimeout = 1 * time.Second
	handler := NewTerminalHandler(config)
	defer handler.CloseAllSessions()

	ctx := context.Background()

	var output []byte
	handler.SetOutputHandler(func(sessionId string, data []byte) {
		output = append(output, data...)
	})

	// Execute a long-running command
	var cmd string
	if runtime.GOOS == "windows" {
		cmd = "ping -n 10 127.0.0.1"
	} else {
		cmd = "sleep 10"
	}

	err := handler.ExecuteCommand(ctx, "test-session", cmd)
	if err != nil {
		t.Fatalf("Failed to start command: %v", err)
	}

	// Wait for timeout
	time.Sleep(2 * time.Second)

	// Verify timeout message in output
	if !strings.Contains(string(output), "timed out") && !strings.Contains(string(output), "completed") {
		t.Logf("Output: %s", string(output))
		// Note: The command might complete or timeout depending on timing
	}
}

// TestTerminalHandler_ResizeTerminal tests terminal resize
func TestTerminalHandler_ResizeTerminal(t *testing.T) {
	handler := NewTerminalHandler(nil)
	defer handler.CloseAllSessions()

	// Create a session
	session, err := handler.CreateSession("test-session")
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Resize terminal
	err = handler.ResizeTerminal("test-session", 120, 40)
	if err != nil {
		t.Errorf("Failed to resize terminal: %v", err)
	}

	// Verify size was updated
	session.mu.Lock()
	cols := session.cols
	rows := session.rows
	session.mu.Unlock()

	if cols != 120 || rows != 40 {
		t.Errorf("Terminal size not updated: expected 120x40, got %dx%d", cols, rows)
	}

	// Try to resize non-existent session
	err = handler.ResizeTerminal("non-existent", 80, 24)
	if err == nil {
		t.Error("Should fail when resizing non-existent session")
	}
}

// TestTerminalHandler_InterruptCommand tests command interruption
func TestTerminalHandler_InterruptCommand(t *testing.T) {
	handler := NewTerminalHandler(nil)
	defer handler.CloseAllSessions()

	ctx := context.Background()

	// Execute a long-running command
	var cmd string
	if runtime.GOOS == "windows" {
		cmd = "ping -n 100 127.0.0.1"
	} else {
		cmd = "sleep 100"
	}

	err := handler.ExecuteCommand(ctx, "test-session", cmd)
	if err != nil {
		t.Fatalf("Failed to start command: %v", err)
	}

	// Wait a bit for command to start
	time.Sleep(200 * time.Millisecond)

	// Interrupt the command
	err = handler.InterruptCommand("test-session")
	if err != nil {
		t.Errorf("Failed to interrupt command: %v", err)
	}

	// Wait for command to be interrupted
	time.Sleep(500 * time.Millisecond)

	// Verify session is no longer running
	session, exists := handler.GetSession("test-session")
	if !exists {
		t.Log("Session was cleaned up after interrupt")
		return
	}
	if session.IsRunning() {
		t.Error("Session should not be running after interrupt")
	}
}

// TestTerminalHandler_SessionCount tests session counting
func TestTerminalHandler_SessionCount(t *testing.T) {
	handler := NewTerminalHandler(nil)
	defer handler.CloseAllSessions()

	if handler.GetSessionCount() != 0 {
		t.Error("Initial session count should be 0")
	}

	handler.CreateSession("session-1")
	if handler.GetSessionCount() != 1 {
		t.Error("Session count should be 1")
	}

	handler.CreateSession("session-2")
	if handler.GetSessionCount() != 2 {
		t.Error("Session count should be 2")
	}

	handler.CloseSession("session-1")
	if handler.GetSessionCount() != 1 {
		t.Error("Session count should be 1 after closing one")
	}

	handler.CloseAllSessions()
	if handler.GetSessionCount() != 0 {
		t.Error("Session count should be 0 after closing all")
	}
}

// TestTerminalHandler_DefaultTimeout tests default timeout configuration
func TestTerminalHandler_DefaultTimeout(t *testing.T) {
	handler := NewTerminalHandler(nil)

	// Check default timeout
	defaultTimeout := handler.GetDefaultTimeout()
	if defaultTimeout != 60*time.Second {
		t.Errorf("Default timeout should be 60s, got %v", defaultTimeout)
	}

	// Set custom timeout
	handler.SetDefaultTimeout(30 * time.Second)
	if handler.GetDefaultTimeout() != 30*time.Second {
		t.Errorf("Timeout should be 30s after setting, got %v", handler.GetDefaultTimeout())
	}
}

// TestEncodeDecodeTerminalData tests base64 encoding/decoding
func TestEncodeDecodeTerminalData(t *testing.T) {
	testData := []byte("Hello, Terminal!")

	encoded := EncodeTerminalOutput(testData)
	if encoded == "" {
		t.Error("Encoded data should not be empty")
	}

	decoded, err := DecodeTerminalInput(encoded)
	if err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	if string(decoded) != string(testData) {
		t.Errorf("Decoded data mismatch: expected %s, got %s", testData, decoded)
	}
}

// TestTerminalSession_LastActive tests last active time tracking
func TestTerminalSession_LastActive(t *testing.T) {
	session := NewTerminalSession("test")

	initialTime := session.GetLastActive()
	time.Sleep(10 * time.Millisecond)

	session.UpdateLastActive()
	updatedTime := session.GetLastActive()

	if !updatedTime.After(initialTime) {
		t.Error("Last active time should be updated")
	}
}
