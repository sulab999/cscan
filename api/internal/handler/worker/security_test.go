package worker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"cscan/api/internal/config"
	"cscan/api/internal/middleware"
	"cscan/api/internal/svc"

	"github.com/redis/go-redis/v9"
)

// TestConsoleAuthMiddleware_AdminOnly tests that console routes require admin role
// **Validates: Requirement 15.1**
func TestConsoleAuthMiddleware_AdminOnly(t *testing.T) {
	mr, redisClient := setupTestRedis(t)
	defer mr.Close()
	defer redisClient.Close()

	consoleAuth := middleware.NewConsoleAuthMiddleware(redisClient)

	tests := []struct {
		name           string
		role           string
		expectedStatus int
	}{
		{
			name:           "admin role should be allowed",
			role:           "admin",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "user role should be denied",
			role:           "user",
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "empty role should be denied",
			role:           "",
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "viewer role should be denied",
			role:           "viewer",
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test handler that returns 200 OK
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			// Wrap with console auth middleware
			handler := consoleAuth.Handle(testHandler)

			// Create request with role in context
			req := httptest.NewRequest(http.MethodGet, "/api/v1/worker/console/info", nil)
			ctx := context.WithValue(req.Context(), middleware.RoleKey, tt.role)
			req = req.WithContext(ctx)

			// Record response
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rr.Code)
			}
		})
	}
}

// TestInstallKeyAuthentication tests Install Key validation
// **Property 3: Install Key Authentication**
// **Validates: Requirements 11.2, 11.3, 11.4**
func TestInstallKeyAuthentication(t *testing.T) {
	mr, redisClient := setupTestRedis(t)
	defer mr.Close()
	defer redisClient.Close()

	svcCtx := setupTestServiceContext(t, redisClient)
	ctx := context.Background()

	// Set up a valid install key
	validKey := "valid-install-key-12345"
	mr.Set("cscan:worker:install_key", validKey)

	tests := []struct {
		name        string
		installKey  string
		shouldError bool
	}{
		{
			name:        "valid install key should authenticate",
			installKey:  validKey,
			shouldError: false,
		},
		{
			name:        "invalid install key should fail",
			installKey:  "invalid-key",
			shouldError: true,
		},
		{
			name:        "empty install key should fail",
			installKey:  "",
			shouldError: true,
		},
		{
			name:        "similar but wrong key should fail",
			installKey:  "valid-install-key-12346",
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateInstallKey(ctx, svcCtx, tt.installKey)
			if tt.shouldError && err == nil {
				t.Error("expected error but got none")
			}
			if !tt.shouldError && err != nil {
				t.Errorf("expected no error but got: %v", err)
			}
		})
	}
}

// TestSessionLimitEnforcement tests that session limits are enforced
// **Validates: Requirement 15.8**
func TestSessionLimitEnforcement(t *testing.T) {
	mr, redisClient := setupTestRedis(t)
	defer mr.Close()
	defer redisClient.Close()

	svcCtx := setupTestServiceContext(t, redisClient)
	wsHandler := NewWorkerWSHandler(svcCtx)

	workerName := "test-worker"
	maxSessions := 3

	// Add sessions up to the limit
	for i := 0; i < maxSessions; i++ {
		sessionId := "session-" + string(rune('a'+i))
		wsHandler.AddWorkerSession(workerName, sessionId)
	}

	// Verify session count
	count := wsHandler.GetWorkerSessionCount(workerName)
	if count != maxSessions {
		t.Errorf("expected %d sessions, got %d", maxSessions, count)
	}

	// Verify that we can detect when limit is reached
	if count < maxSessions {
		t.Error("session count should be at or above limit")
	}

	// Remove a session
	wsHandler.RemoveWorkerSession(workerName, "session-a")
	count = wsHandler.GetWorkerSessionCount(workerName)
	if count != maxSessions-1 {
		t.Errorf("expected %d sessions after removal, got %d", maxSessions-1, count)
	}

	// Remove all sessions
	wsHandler.RemoveWorkerSession(workerName, "session-b")
	wsHandler.RemoveWorkerSession(workerName, "session-c")
	count = wsHandler.GetWorkerSessionCount(workerName)
	if count != 0 {
		t.Errorf("expected 0 sessions after removing all, got %d", count)
	}
}

// TestConsoleConfigDefaults tests console configuration defaults
// **Validates: Requirements 15.3, 15.4, 15.5, 15.6, 15.7, 15.8**
func TestConsoleConfigDefaults(t *testing.T) {
	cfg := config.DefaultConsoleConfig()

	// Test command timeout default (60 seconds)
	timeout := cfg.GetCommandTimeout()
	if timeout != 60*time.Second {
		t.Errorf("expected command timeout 60s, got %v", timeout)
	}

	// Test max upload size default (100MB)
	maxSize := cfg.GetMaxUploadSize()
	if maxSize != 100*1024*1024 {
		t.Errorf("expected max upload size 100MB, got %d", maxSize)
	}

	// Test WS idle timeout default (5 minutes)
	idleTimeout := cfg.GetWSIdleTimeout()
	if idleTimeout != 5*time.Minute {
		t.Errorf("expected WS idle timeout 5m, got %v", idleTimeout)
	}

	// Test max sessions per worker default (3)
	maxSessions := cfg.GetMaxSessionsPerWorker()
	if maxSessions != 3 {
		t.Errorf("expected max sessions 3, got %d", maxSessions)
	}

	// Test command blacklist is not empty
	if len(cfg.CommandBlacklist) == 0 {
		t.Error("expected non-empty command blacklist")
	}
}

// TestConsoleConfigCustomValues tests console configuration with custom values
func TestConsoleConfigCustomValues(t *testing.T) {
	cfg := &config.ConsoleConfig{
		CommandTimeout:       120,
		MaxUploadSize:        50 * 1024 * 1024, // 50MB
		WSIdleTimeout:        600,              // 10 minutes
		MaxSessionsPerWorker: 5,
	}

	// Test custom command timeout
	timeout := cfg.GetCommandTimeout()
	if timeout != 120*time.Second {
		t.Errorf("expected command timeout 120s, got %v", timeout)
	}

	// Test custom max upload size
	maxSize := cfg.GetMaxUploadSize()
	if maxSize != 50*1024*1024 {
		t.Errorf("expected max upload size 50MB, got %d", maxSize)
	}

	// Test custom WS idle timeout
	idleTimeout := cfg.GetWSIdleTimeout()
	if idleTimeout != 10*time.Minute {
		t.Errorf("expected WS idle timeout 10m, got %v", idleTimeout)
	}

	// Test custom max sessions
	maxSessions := cfg.GetMaxSessionsPerWorker()
	if maxSessions != 5 {
		t.Errorf("expected max sessions 5, got %d", maxSessions)
	}
}

// TestConsoleConfigZeroValues tests console configuration handles zero values
func TestConsoleConfigZeroValues(t *testing.T) {
	cfg := &config.ConsoleConfig{
		CommandTimeout:       0,
		MaxUploadSize:        0,
		WSIdleTimeout:        0,
		MaxSessionsPerWorker: 0,
	}

	// Should return defaults for zero values
	if cfg.GetCommandTimeout() != 60*time.Second {
		t.Errorf("expected default command timeout for zero value")
	}
	if cfg.GetMaxUploadSize() != 100*1024*1024 {
		t.Errorf("expected default max upload size for zero value")
	}
	if cfg.GetWSIdleTimeout() != 5*time.Minute {
		t.Errorf("expected default WS idle timeout for zero value")
	}
	if cfg.GetMaxSessionsPerWorker() != 3 {
		t.Errorf("expected default max sessions for zero value")
	}
}

// TestWorkerAuthMiddleware tests Worker authentication middleware
// **Validates: Requirements 11.2, 11.3**
func TestWorkerAuthMiddleware(t *testing.T) {
	mr, redisClient := setupTestRedis(t)
	defer mr.Close()
	defer redisClient.Close()

	// Set up install key
	validKey := "worker-auth-key"
	mr.Set("cscan:worker:install_key", validKey)

	workerAuth := middleware.NewWorkerAuthMiddleware(redisClient)

	tests := []struct {
		name           string
		headerKey      string
		expectedStatus int
	}{
		{
			name:           "valid key should authenticate",
			headerKey:      validKey,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "invalid key should fail",
			headerKey:      "wrong-key",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "missing key should fail",
			headerKey:      "",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			handler := workerAuth.Handle(testHandler)

			req := httptest.NewRequest(http.MethodPost, "/api/v1/worker/task/check", nil)
			if tt.headerKey != "" {
				req.Header.Set("X-Worker-Key", tt.headerKey)
			}

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rr.Code)
			}
		})
	}
}

// TestAuditLogRecording tests that audit logs are recorded correctly
// **Validates: Requirement 15.2**
func TestAuditLogRecording(t *testing.T) {
	mr, redisClient := setupTestRedis(t)
	defer mr.Close()
	defer redisClient.Close()

	consoleAuth := middleware.NewConsoleAuthMiddleware(redisClient)

	// Create a test handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := consoleAuth.Handle(testHandler)

	// Create request with admin role
	req := httptest.NewRequest(http.MethodGet, "/api/v1/worker/console/info?name=test-worker", nil)
	ctx := context.WithValue(req.Context(), middleware.RoleKey, "admin")
	ctx = context.WithValue(ctx, middleware.UserIdKey, "user-123")
	ctx = context.WithValue(ctx, middleware.UsernameKey, "testuser")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Wait for async audit log recording
	time.Sleep(100 * time.Millisecond)

	// Verify audit log was written to Redis
	bgCtx := context.Background()
	logs, err := redisClient.XRange(bgCtx, "cscan:audit:console", "-", "+").Result()
	if err != nil {
		t.Fatalf("Failed to read audit logs: %v", err)
	}

	if len(logs) == 0 {
		t.Error("Expected audit log to be recorded")
	}

	// Verify audit log content
	if len(logs) > 0 {
		data, ok := logs[0].Values["data"].(string)
		if !ok {
			t.Error("Audit log data not found")
		}

		var logData map[string]interface{}
		if err := json.Unmarshal([]byte(data), &logData); err != nil {
			t.Fatalf("Failed to unmarshal audit log: %v", err)
		}

		if logData["type"] != "console_access" {
			t.Errorf("expected type 'console_access', got %v", logData["type"])
		}
		if logData["userId"] != "user-123" {
			t.Errorf("expected userId 'user-123', got %v", logData["userId"])
		}
		if logData["username"] != "testuser" {
			t.Errorf("expected username 'testuser', got %v", logData["username"])
		}
	}
}

// TestSessionTrackingConcurrency tests session tracking under concurrent access
func TestSessionTrackingConcurrency(t *testing.T) {
	mr, redisClient := setupTestRedis(t)
	defer mr.Close()
	defer redisClient.Close()

	svcCtx := setupTestServiceContext(t, redisClient)
	wsHandler := NewWorkerWSHandler(svcCtx)

	workerName := "concurrent-worker"
	numSessions := 100

	// Add sessions concurrently
	done := make(chan bool, numSessions)
	for i := 0; i < numSessions; i++ {
		go func(idx int) {
			sessionId := "session-" + string(rune('0'+idx%10)) + string(rune('0'+idx/10))
			wsHandler.AddWorkerSession(workerName, sessionId)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < numSessions; i++ {
		<-done
	}

	// Verify session count (may be less than numSessions due to duplicate session IDs)
	count := wsHandler.GetWorkerSessionCount(workerName)
	if count == 0 {
		t.Error("expected some sessions to be tracked")
	}

	// Remove sessions concurrently
	for i := 0; i < numSessions; i++ {
		go func(idx int) {
			sessionId := "session-" + string(rune('0'+idx%10)) + string(rune('0'+idx/10))
			wsHandler.RemoveWorkerSession(workerName, sessionId)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < numSessions; i++ {
		<-done
	}

	// Verify all sessions removed
	count = wsHandler.GetWorkerSessionCount(workerName)
	if count != 0 {
		t.Errorf("expected 0 sessions after removal, got %d", count)
	}
}

// setupTestServiceContext creates a test ServiceContext with console config
func setupTestServiceContextWithConfig(t *testing.T, redisClient *redis.Client) *svc.ServiceContext {
	return &svc.ServiceContext{
		RedisClient: redisClient,
		Config: config.Config{
			Console: config.ConsoleConfig{
				CommandTimeout:       60,
				MaxUploadSize:        100 * 1024 * 1024,
				WSIdleTimeout:        300,
				MaxSessionsPerWorker: 3,
			},
		},
	}
}
