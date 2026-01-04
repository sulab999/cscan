package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
)

// ==================== Test Helpers ====================

// 测试用错误定义
var errConnectionClosed = fmt.Errorf("connection closed")

// mockWSServer 创建一个模拟的WebSocket服务器
type mockWSServer struct {
	server       *httptest.Server
	installKey   string
	connections  sync.Map
	onMessage    func(conn net.Conn, msg *WSMessage)
	authDelay    time.Duration
	rejectAuth   bool
}

func newMockWSServer(installKey string) *mockWSServer {
	m := &mockWSServer{
		installKey: installKey,
	}
	m.server = httptest.NewServer(http.HandlerFunc(m.handleWS))
	return m
}

func (m *mockWSServer) handleWS(w http.ResponseWriter, r *http.Request) {
	conn, _, _, err := ws.UpgradeHTTP(r, w)
	if err != nil {
		return
	}
	defer conn.Close()

	// 等待认证消息
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	data, _, err := wsutil.ReadClientData(conn)
	if err != nil {
		return
	}

	var authMsg WSMessage
	if err := json.Unmarshal(data, &authMsg); err != nil {
		return
	}

	if authMsg.Type != WSTypeAuth {
		return
	}

	var authPayload WSAuthPayload
	if err := json.Unmarshal(authMsg.Payload, &authPayload); err != nil {
		return
	}

	// 模拟认证延迟
	if m.authDelay > 0 {
		time.Sleep(m.authDelay)
	}

	// 验证Install Key
	if m.rejectAuth || authPayload.InstallKey != m.installKey {
		failMsg := WSMessage{Type: WSTypeAuthFail}
		failPayload, _ := json.Marshal(map[string]string{"reason": "invalid key"})
		failMsg.Payload = failPayload
		failData, _ := json.Marshal(failMsg)
		wsutil.WriteServerMessage(conn, ws.OpText, failData)
		return
	}

	// 认证成功
	okMsg := WSMessage{Type: WSTypeAuthOK}
	okData, _ := json.Marshal(okMsg)
	wsutil.WriteServerMessage(conn, ws.OpText, okData)

	// 存储连接
	m.connections.Store(authPayload.WorkerName, conn)
	defer m.connections.Delete(authPayload.WorkerName)

	// 消息循环
	for {
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		data, _, err := wsutil.ReadClientData(conn)
		if err != nil {
			return
		}

		var msg WSMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}

		// 处理PING
		if msg.Type == WSTypePing {
			pongMsg := WSMessage{Type: WSTypePong}
			pongData, _ := json.Marshal(pongMsg)
			wsutil.WriteServerMessage(conn, ws.OpText, pongData)
			continue
		}

		// 调用自定义处理器
		if m.onMessage != nil {
			m.onMessage(conn, &msg)
		}
	}
}

func (m *mockWSServer) URL() string {
	return "ws" + strings.TrimPrefix(m.server.URL, "http")
}

func (m *mockWSServer) Close() {
	m.server.Close()
}

func (m *mockWSServer) SendControl(workerName, taskId, action string) error {
	connI, ok := m.connections.Load(workerName)
	if !ok {
		return errConnectionClosed
	}
	conn := connI.(net.Conn)

	payload := WSControlPayload{TaskId: taskId, Action: action}
	payloadData, _ := json.Marshal(payload)
	msg := WSMessage{Type: WSTypeControl, Payload: payloadData}
	msgData, _ := json.Marshal(msg)

	return wsutil.WriteServerMessage(conn, ws.OpText, msgData)
}

// ==================== Unit Tests ====================

// TestWSClientConfig 测试客户端配置
func TestWSClientConfig(t *testing.T) {
	config := DefaultWSClientConfig("http://localhost:8888", "test-worker", "test-key")

	if config.ServerURL != "http://localhost:8888" {
		t.Errorf("ServerURL = %s, want http://localhost:8888", config.ServerURL)
	}
	if config.WorkerName != "test-worker" {
		t.Errorf("WorkerName = %s, want test-worker", config.WorkerName)
	}
	if config.InstallKey != "test-key" {
		t.Errorf("InstallKey = %s, want test-key", config.InstallKey)
	}
	if config.ReconnectDelay != 1*time.Second {
		t.Errorf("ReconnectDelay = %v, want 1s", config.ReconnectDelay)
	}
	if config.MaxReconnect != 30*time.Second {
		t.Errorf("MaxReconnect = %v, want 30s", config.MaxReconnect)
	}
}

// TestBuildWSURL 测试WebSocket URL构建
func TestBuildWSURL(t *testing.T) {
	tests := []struct {
		name      string
		serverURL string
		expected  string
	}{
		{"http URL", "http://localhost:8888", "ws://localhost:8888/api/v1/worker/ws"},
		{"https URL", "https://localhost:8888", "wss://localhost:8888/api/v1/worker/ws"},
		{"ws URL", "ws://localhost:8888/api/v1/worker/ws", "ws://localhost:8888/api/v1/worker/ws"},
		{"wss URL", "wss://localhost:8888/api/v1/worker/ws", "wss://localhost:8888/api/v1/worker/ws"},
		{"no scheme", "localhost:8888", "ws://localhost:8888/api/v1/worker/ws"},
		{"with path", "http://localhost:8888/", "ws://localhost:8888/api/v1/worker/ws"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := DefaultWSClientConfig(tt.serverURL, "worker", "key")
			client := NewWorkerWSClient(config)
			result := client.buildWSURL()
			if result != tt.expected {
				t.Errorf("buildWSURL() = %s, want %s", result, tt.expected)
			}
		})
	}
}

// TestWSClientConnect 测试WebSocket连接
func TestWSClientConnect(t *testing.T) {
	server := newMockWSServer("valid-key")
	defer server.Close()

	config := DefaultWSClientConfig(server.URL(), "test-worker", "valid-key")
	config.PingInterval = 100 * time.Millisecond
	client := NewWorkerWSClient(config)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := client.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer client.Close()

	if !client.IsConnected() {
		t.Error("Client should be connected after Connect()")
	}
}

// TestWSClientAuthFailure 测试认证失败
func TestWSClientAuthFailure(t *testing.T) {
	server := newMockWSServer("valid-key")
	defer server.Close()

	config := DefaultWSClientConfig(server.URL(), "test-worker", "wrong-key")
	client := NewWorkerWSClient(config)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := client.Connect(ctx)
	if err == nil {
		t.Error("Connect() should fail with wrong key")
		client.Close()
	}

	if client.IsConnected() {
		t.Error("Client should not be connected after auth failure")
	}
}

// TestWSClientSendLog 测试日志发送
func TestWSClientSendLog(t *testing.T) {
	var receivedLogs []WSLogPayload
	var mu sync.Mutex

	server := newMockWSServer("valid-key")
	server.onMessage = func(conn net.Conn, msg *WSMessage) {
		if msg.Type == WSTypeLog {
			var log WSLogPayload
			json.Unmarshal(msg.Payload, &log)
			mu.Lock()
			receivedLogs = append(receivedLogs, log)
			mu.Unlock()
		}
	}
	defer server.Close()

	config := DefaultWSClientConfig(server.URL(), "test-worker", "valid-key")
	config.LogBatchSize = 1 // 立即发送
	config.LogFlushTimeout = 50 * time.Millisecond
	client := NewWorkerWSClient(config)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := client.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer client.Close()

	// 发送日志
	client.SendLogImmediate("task-123", "INFO", "Test message")

	// 等待日志被接收
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(receivedLogs) == 0 {
		t.Error("Server should receive log message")
	}
}

// TestWSClientControlHandler 测试控制信号处理
func TestWSClientControlHandler(t *testing.T) {
	server := newMockWSServer("valid-key")
	defer server.Close()

	config := DefaultWSClientConfig(server.URL(), "test-worker", "valid-key")
	client := NewWorkerWSClient(config)

	var receivedTaskId, receivedAction string
	var handlerCalled atomic.Bool

	client.SetControlHandler(func(taskId, action string) {
		receivedTaskId = taskId
		receivedAction = action
		handlerCalled.Store(true)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := client.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer client.Close()

	// 等待连接稳定
	time.Sleep(100 * time.Millisecond)

	// 服务器发送控制信号
	err = server.SendControl("test-worker", "task-456", "STOP")
	if err != nil {
		t.Fatalf("SendControl() error = %v", err)
	}

	// 等待处理
	time.Sleep(200 * time.Millisecond)

	if !handlerCalled.Load() {
		t.Error("Control handler should be called")
	}
	if receivedTaskId != "task-456" {
		t.Errorf("TaskId = %s, want task-456", receivedTaskId)
	}
	if receivedAction != "STOP" {
		t.Errorf("Action = %s, want STOP", receivedAction)
	}
}

// TestWSClientClose 测试客户端关闭
func TestWSClientClose(t *testing.T) {
	server := newMockWSServer("valid-key")
	defer server.Close()

	config := DefaultWSClientConfig(server.URL(), "test-worker", "valid-key")
	client := NewWorkerWSClient(config)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := client.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	if !client.IsConnected() {
		t.Error("Client should be connected")
	}

	client.Close()

	if client.IsConnected() {
		t.Error("Client should not be connected after Close()")
	}

	// 再次关闭不应panic
	client.Close()
}

// TestWSClientWaitForConnection 测试等待连接
func TestWSClientWaitForConnection(t *testing.T) {
	server := newMockWSServer("valid-key")
	defer server.Close()

	config := DefaultWSClientConfig(server.URL(), "test-worker", "valid-key")
	client := NewWorkerWSClient(config)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := client.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer client.Close()

	// 应该立即返回true
	if !client.WaitForConnection(1 * time.Second) {
		t.Error("WaitForConnection should return true when connected")
	}
}

// TestWSClientBatchLog 测试批量日志发送
func TestWSClientBatchLog(t *testing.T) {
	var receivedBatches []WSLogBatchPayload
	var mu sync.Mutex

	server := newMockWSServer("valid-key")
	server.onMessage = func(conn net.Conn, msg *WSMessage) {
		if msg.Type == WSTypeLogBatch {
			var batch WSLogBatchPayload
			json.Unmarshal(msg.Payload, &batch)
			mu.Lock()
			receivedBatches = append(receivedBatches, batch)
			mu.Unlock()
		}
	}
	defer server.Close()

	config := DefaultWSClientConfig(server.URL(), "test-worker", "valid-key")
	config.LogBatchSize = 3
	config.LogFlushTimeout = 100 * time.Millisecond
	client := NewWorkerWSClient(config)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := client.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer client.Close()

	// 发送多条日志触发批量发送
	for i := 0; i < 5; i++ {
		client.SendLog("task-123", "INFO", "Message")
	}

	// 等待批量发送
	time.Sleep(300 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(receivedBatches) == 0 {
		t.Error("Server should receive batch log messages")
	}
}

// ==================== Property Tests ====================

// TestProperty4_TaskControlSignalDelivery 测试Property 4: Task Control Signal Delivery
// **Property 4: Task Control Signal Delivery**
// **Validates: Requirements 8.1, 8.2, 8.3, 8.4**
// For any task control signal (STOP, PAUSE), when published through the system,
// the corresponding Worker should receive and process it within 1 second.
func TestProperty4_TaskControlSignalDelivery(t *testing.T) {
	server := newMockWSServer("valid-key")
	defer server.Close()

	config := DefaultWSClientConfig(server.URL(), "test-worker", "valid-key")
	client := NewWorkerWSClient(config)

	// 记录收到的控制信号
	type controlSignal struct {
		taskId    string
		action    string
		timestamp time.Time
	}
	var signals []controlSignal
	var mu sync.Mutex

	client.SetControlHandler(func(taskId, action string) {
		mu.Lock()
		signals = append(signals, controlSignal{taskId, action, time.Now()})
		mu.Unlock()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := client.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer client.Close()

	// 等待连接稳定
	time.Sleep(100 * time.Millisecond)

	// 测试用例：不同的控制信号
	testCases := []struct {
		taskId string
		action string
	}{
		{"task-001", "STOP"},
		{"task-002", "PAUSE"},
		{"task-003", "STOP"},
		{"task-004", "PAUSE"},
		{"task-005", "RESUME"},
	}

	for _, tc := range testCases {
		sendTime := time.Now()

		err := server.SendControl("test-worker", tc.taskId, tc.action)
		if err != nil {
			t.Errorf("SendControl(%s, %s) error = %v", tc.taskId, tc.action, err)
			continue
		}

		// 等待信号被处理（最多1秒）
		deadline := time.Now().Add(1 * time.Second)
		var received bool
		for time.Now().Before(deadline) {
			mu.Lock()
			for _, sig := range signals {
				if sig.taskId == tc.taskId && sig.action == tc.action {
					received = true
					// 验证延迟在1秒内
					latency := sig.timestamp.Sub(sendTime)
					if latency > 1*time.Second {
						t.Errorf("Control signal latency %v > 1s for task %s", latency, tc.taskId)
					}
					break
				}
			}
			mu.Unlock()
			if received {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}

		if !received {
			t.Errorf("Control signal not received within 1s: taskId=%s, action=%s", tc.taskId, tc.action)
		}
	}

	// 验证所有信号都被接收
	mu.Lock()
	defer mu.Unlock()
	if len(signals) != len(testCases) {
		t.Errorf("Received %d signals, want %d", len(signals), len(testCases))
	}
}

// TestProperty4_ControlSignalWithMultipleWorkers 测试多Worker场景下的控制信号
func TestProperty4_ControlSignalWithMultipleWorkers(t *testing.T) {
	server := newMockWSServer("valid-key")
	defer server.Close()

	// 创建多个Worker客户端
	workers := make([]*WorkerWSClient, 3)
	signalCounts := make([]int32, 3)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for i := 0; i < 3; i++ {
		workerName := "worker-" + string(rune('A'+i))
		config := DefaultWSClientConfig(server.URL(), workerName, "valid-key")
		client := NewWorkerWSClient(config)

		idx := i
		client.SetControlHandler(func(taskId, action string) {
			atomic.AddInt32(&signalCounts[idx], 1)
		})

		err := client.Start(ctx)
		if err != nil {
			t.Fatalf("Worker %s Start() error = %v", workerName, err)
		}
		workers[i] = client
		defer client.Close()
	}

	// 等待所有连接稳定
	time.Sleep(200 * time.Millisecond)

	// 向特定Worker发送控制信号
	err := server.SendControl("worker-B", "task-100", "STOP")
	if err != nil {
		t.Fatalf("SendControl error = %v", err)
	}

	// 等待处理
	time.Sleep(200 * time.Millisecond)

	// 验证只有worker-B收到信号
	if atomic.LoadInt32(&signalCounts[0]) != 0 {
		t.Error("worker-A should not receive signal")
	}
	if atomic.LoadInt32(&signalCounts[1]) != 1 {
		t.Error("worker-B should receive exactly 1 signal")
	}
	if atomic.LoadInt32(&signalCounts[2]) != 0 {
		t.Error("worker-C should not receive signal")
	}
}

// TestWSClientMessageTypes 测试消息类型常量
func TestWSClientMessageTypes(t *testing.T) {
	// 验证消息类型常量与服务端一致
	if WSTypeAuth != "AUTH" {
		t.Errorf("WSTypeAuth = %s, want AUTH", WSTypeAuth)
	}
	if WSTypeAuthOK != "AUTH_OK" {
		t.Errorf("WSTypeAuthOK = %s, want AUTH_OK", WSTypeAuthOK)
	}
	if WSTypeAuthFail != "AUTH_FAIL" {
		t.Errorf("WSTypeAuthFail = %s, want AUTH_FAIL", WSTypeAuthFail)
	}
	if WSTypePing != "PING" {
		t.Errorf("WSTypePing = %s, want PING", WSTypePing)
	}
	if WSTypePong != "PONG" {
		t.Errorf("WSTypePong = %s, want PONG", WSTypePong)
	}
	if WSTypeLog != "LOG" {
		t.Errorf("WSTypeLog = %s, want LOG", WSTypeLog)
	}
	if WSTypeLogBatch != "LOG_BATCH" {
		t.Errorf("WSTypeLogBatch = %s, want LOG_BATCH", WSTypeLogBatch)
	}
	if WSTypeControl != "CONTROL" {
		t.Errorf("WSTypeControl = %s, want CONTROL", WSTypeControl)
	}
}

// TestWSMessageSerialization 测试消息序列化
func TestWSMessageSerialization(t *testing.T) {
	// 测试AUTH消息
	authPayload := WSAuthPayload{
		WorkerName: "test-worker",
		InstallKey: "test-key",
	}
	payloadBytes, _ := json.Marshal(authPayload)
	msg := WSMessage{
		Type:    WSTypeAuth,
		Payload: payloadBytes,
	}

	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("Marshal error = %v", err)
	}

	var decoded WSMessage
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}

	if decoded.Type != WSTypeAuth {
		t.Errorf("Type = %s, want %s", decoded.Type, WSTypeAuth)
	}

	var decodedPayload WSAuthPayload
	if err := json.Unmarshal(decoded.Payload, &decodedPayload); err != nil {
		t.Fatalf("Unmarshal payload error = %v", err)
	}

	if decodedPayload.WorkerName != authPayload.WorkerName {
		t.Errorf("WorkerName = %s, want %s", decodedPayload.WorkerName, authPayload.WorkerName)
	}
}

// TestWSLogPayloadSerialization 测试日志载荷序列化
func TestWSLogPayloadSerialization(t *testing.T) {
	payload := WSLogPayload{
		TaskId:    "task-123",
		Level:     "INFO",
		Message:   "Test message",
		Timestamp: time.Now().UnixMilli(),
	}

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Marshal error = %v", err)
	}

	var decoded WSLogPayload
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}

	if decoded.TaskId != payload.TaskId {
		t.Errorf("TaskId = %s, want %s", decoded.TaskId, payload.TaskId)
	}
	if decoded.Level != payload.Level {
		t.Errorf("Level = %s, want %s", decoded.Level, payload.Level)
	}
	if decoded.Message != payload.Message {
		t.Errorf("Message = %s, want %s", decoded.Message, payload.Message)
	}
}

// TestWSControlPayloadSerialization 测试控制信号载荷序列化
func TestWSControlPayloadSerialization(t *testing.T) {
	payload := WSControlPayload{
		TaskId: "task-456",
		Action: "STOP",
	}

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Marshal error = %v", err)
	}

	var decoded WSControlPayload
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}

	if decoded.TaskId != payload.TaskId {
		t.Errorf("TaskId = %s, want %s", decoded.TaskId, payload.TaskId)
	}
	if decoded.Action != payload.Action {
		t.Errorf("Action = %s, want %s", decoded.Action, payload.Action)
	}
}

// TestWSClientNotConnected 测试未连接状态下的操作
func TestWSClientNotConnected(t *testing.T) {
	config := DefaultWSClientConfig("ws://localhost:9999", "test-worker", "key")
	client := NewWorkerWSClient(config)

	// 未连接时IsConnected应返回false
	if client.IsConnected() {
		t.Error("IsConnected should return false before Connect")
	}

	// 未连接时发送日志应失败
	err := client.SendLogImmediate("task", "INFO", "msg")
	if err == nil {
		t.Error("SendLogImmediate should fail when not connected")
	}
}
