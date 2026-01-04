package worker

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cscan/api/internal/svc"

	"github.com/alicebob/miniredis/v2"
	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/redis/go-redis/v9"
)

// setupTestRedis 创建测试用的Redis实例
func setupTestRedis(t *testing.T) (*miniredis.Miniredis, *redis.Client) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Failed to start miniredis: %v", err)
	}

	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})

	return mr, client
}

// setupTestServiceContext 创建测试用的ServiceContext
func setupTestServiceContext(t *testing.T, redisClient *redis.Client) *svc.ServiceContext {
	return &svc.ServiceContext{
		RedisClient: redisClient,
	}
}

// TestWSMessageTypes 测试WebSocket消息类型常量
func TestWSMessageTypes(t *testing.T) {
	// 验证消息类型常量定义正确
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
	if WSTypeControl != "CONTROL" {
		t.Errorf("WSTypeControl = %s, want CONTROL", WSTypeControl)
	}
}

// TestWSMessageSerialization 测试消息序列化
func TestWSMessageSerialization(t *testing.T) {
	// 测试AUTH消息序列化
	authPayload := AuthPayload{
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
		t.Fatalf("Failed to marshal WSMessage: %v", err)
	}

	var decoded WSMessage
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal WSMessage: %v", err)
	}

	if decoded.Type != WSTypeAuth {
		t.Errorf("decoded.Type = %s, want %s", decoded.Type, WSTypeAuth)
	}

	var decodedPayload AuthPayload
	if err := json.Unmarshal(decoded.Payload, &decodedPayload); err != nil {
		t.Fatalf("Failed to unmarshal AuthPayload: %v", err)
	}

	if decodedPayload.WorkerName != authPayload.WorkerName {
		t.Errorf("WorkerName = %s, want %s", decodedPayload.WorkerName, authPayload.WorkerName)
	}
	if decodedPayload.InstallKey != authPayload.InstallKey {
		t.Errorf("InstallKey = %s, want %s", decodedPayload.InstallKey, authPayload.InstallKey)
	}
}

// TestWorkerConnectionSend 测试WorkerConnection发送消息
func TestWorkerConnectionSend(t *testing.T) {
	mr, redisClient := setupTestRedis(t)
	defer mr.Close()
	defer redisClient.Close()

	svcCtx := setupTestServiceContext(t, redisClient)

	// 创建mock连接
	conn := &mockNetConn{}
	wc := NewWorkerConnection(conn, "test-worker", svcCtx)

	// 测试发送消息
	msg := &WSMessage{Type: WSTypePong}
	err := wc.Send(msg)
	if err != nil {
		t.Errorf("Send() error = %v", err)
	}

	// 验证消息在发送通道中
	select {
	case data := <-wc.sendChan:
		var decoded WSMessage
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("Failed to unmarshal sent message: %v", err)
		}
		if decoded.Type != WSTypePong {
			t.Errorf("sent message type = %s, want %s", decoded.Type, WSTypePong)
		}
	default:
		t.Error("No message in send channel")
	}
}

// TestWorkerConnectionClose 测试WorkerConnection关闭
func TestWorkerConnectionClose(t *testing.T) {
	mr, redisClient := setupTestRedis(t)
	defer mr.Close()
	defer redisClient.Close()

	svcCtx := setupTestServiceContext(t, redisClient)
	conn := &mockNetConn{}
	wc := NewWorkerConnection(conn, "test-worker", svcCtx)

	// 关闭连接
	wc.Close()

	// 验证closeChan已关闭
	select {
	case <-wc.closeChan:
		// 预期行为
	default:
		t.Error("closeChan should be closed")
	}

	// 再次关闭不应panic
	wc.Close()
}

// TestWorkerConnectionLastPing 测试心跳时间更新
func TestWorkerConnectionLastPing(t *testing.T) {
	mr, redisClient := setupTestRedis(t)
	defer mr.Close()
	defer redisClient.Close()

	svcCtx := setupTestServiceContext(t, redisClient)
	conn := &mockNetConn{}
	wc := NewWorkerConnection(conn, "test-worker", svcCtx)

	initialPing := wc.GetLastPing()
	time.Sleep(10 * time.Millisecond)
	wc.UpdateLastPing()
	updatedPing := wc.GetLastPing()

	if !updatedPing.After(initialPing) {
		t.Error("UpdateLastPing should update the timestamp")
	}
}

// TestWorkerWSHandler 测试WebSocket处理器
func TestWorkerWSHandler(t *testing.T) {
	mr, redisClient := setupTestRedis(t)
	defer mr.Close()
	defer redisClient.Close()

	svcCtx := setupTestServiceContext(t, redisClient)
	handler := NewWorkerWSHandler(svcCtx)

	// 测试GetConnection - 不存在的连接
	_, ok := handler.GetConnection("non-existent")
	if ok {
		t.Error("GetConnection should return false for non-existent worker")
	}

	// 测试GetConnectedWorkers - 空列表
	workers := handler.GetConnectedWorkers()
	if len(workers) != 0 {
		t.Errorf("GetConnectedWorkers should return empty list, got %d workers", len(workers))
	}
}

// TestValidateInstallKey 测试Install Key验证
func TestValidateInstallKey(t *testing.T) {
	mr, redisClient := setupTestRedis(t)
	defer mr.Close()
	defer redisClient.Close()

	svcCtx := setupTestServiceContext(t, redisClient)
	ctx := context.Background()

	// 设置Install Key
	testKey := "test-install-key-12345"
	mr.Set("cscan:worker:install_key", testKey)

	// 测试有效的Key
	err := validateInstallKey(ctx, svcCtx, testKey)
	if err != nil {
		t.Errorf("validateInstallKey with valid key should not error: %v", err)
	}

	// 测试无效的Key
	err = validateInstallKey(ctx, svcCtx, "invalid-key")
	if err == nil {
		t.Error("validateInstallKey with invalid key should error")
	}

	// 测试空Key
	err = validateInstallKey(ctx, svcCtx, "")
	if err == nil {
		t.Error("validateInstallKey with empty key should error")
	}
}

// TestExtractTaskIdFromChannel 测试从频道名提取taskId
func TestExtractTaskIdFromChannel(t *testing.T) {
	tests := []struct {
		channel  string
		expected string
	}{
		{"cscan:task:ctrl:task-123", "task-123"},
		{"cscan:task:ctrl:abc-def-ghi", "abc-def-ghi"},
		{"cscan:task:ctrl:", ""},
		{"invalid:channel", ""},
		{"", ""},
	}

	for _, tt := range tests {
		result := extractTaskIdFromChannel(tt.channel)
		if result != tt.expected {
			t.Errorf("extractTaskIdFromChannel(%s) = %s, want %s", tt.channel, result, tt.expected)
		}
	}
}

// TestLogPayloadSerialization 测试日志载荷序列化
func TestLogPayloadSerialization(t *testing.T) {
	payload := LogPayload{
		TaskId:    "task-123",
		Level:     "INFO",
		Message:   "Test message",
		Timestamp: time.Now().UnixMilli(),
	}

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Failed to marshal LogPayload: %v", err)
	}

	var decoded LogPayload
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal LogPayload: %v", err)
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

// TestControlPayloadSerialization 测试控制信号载荷序列化
func TestControlPayloadSerialization(t *testing.T) {
	payload := ControlPayload{
		TaskId: "task-456",
		Action: "STOP",
	}

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Failed to marshal ControlPayload: %v", err)
	}

	var decoded ControlPayload
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal ControlPayload: %v", err)
	}

	if decoded.TaskId != payload.TaskId {
		t.Errorf("TaskId = %s, want %s", decoded.TaskId, payload.TaskId)
	}
	if decoded.Action != payload.Action {
		t.Errorf("Action = %s, want %s", decoded.Action, payload.Action)
	}
}


// TestWriteLogToRedis 测试日志写入Redis
// **Property 2: WebSocket to Redis Proxy Consistency**
// **Validates: Requirements 7.4, 7.5**
func TestWriteLogToRedis(t *testing.T) {
	mr, redisClient := setupTestRedis(t)
	defer mr.Close()
	defer redisClient.Close()

	svcCtx := setupTestServiceContext(t, redisClient)
	ctx := context.Background()

	// 写入日志
	logPayload := &LogPayload{
		TaskId:    "task-789",
		Level:     "INFO",
		Message:   "Test log message",
		Timestamp: time.Now().UnixMilli(),
	}

	writeLogToRedis(ctx, svcCtx, "test-worker", logPayload)

	// 验证日志写入全局流
	logs, err := redisClient.XRange(ctx, "cscan:worker:logs", "-", "+").Result()
	if err != nil {
		t.Fatalf("Failed to read logs from Redis: %v", err)
	}

	if len(logs) == 0 {
		t.Error("No logs found in Redis stream")
	}

	// 验证日志内容
	if len(logs) > 0 {
		data, ok := logs[0].Values["data"].(string)
		if !ok {
			t.Error("Log data not found in stream entry")
		}

		var logData map[string]interface{}
		if err := json.Unmarshal([]byte(data), &logData); err != nil {
			t.Fatalf("Failed to unmarshal log data: %v", err)
		}

		if logData["workerName"] != "test-worker" {
			t.Errorf("workerName = %v, want test-worker", logData["workerName"])
		}
		if logData["level"] != "INFO" {
			t.Errorf("level = %v, want INFO", logData["level"])
		}
		if logData["message"] != "Test log message" {
			t.Errorf("message = %v, want 'Test log message'", logData["message"])
		}
		if logData["taskId"] != "task-789" {
			t.Errorf("taskId = %v, want task-789", logData["taskId"])
		}
	}

	// 验证任务专属日志流
	taskLogs, err := redisClient.XRange(ctx, "cscan:task:logs:task-789", "-", "+").Result()
	if err != nil {
		t.Fatalf("Failed to read task logs from Redis: %v", err)
	}

	if len(taskLogs) == 0 {
		t.Error("No logs found in task-specific Redis stream")
	}
}

// TestBroadcastControl 测试控制信号广播
func TestBroadcastControl(t *testing.T) {
	mr, redisClient := setupTestRedis(t)
	defer mr.Close()
	defer redisClient.Close()

	svcCtx := setupTestServiceContext(t, redisClient)
	handler := NewWorkerWSHandler(svcCtx)

	// 测试向不存在的Worker发送控制信号
	err := handler.BroadcastControl("non-existent", "task-123", "STOP")
	if err != ErrConnectionClosed {
		t.Errorf("BroadcastControl to non-existent worker should return ErrConnectionClosed, got %v", err)
	}
}

// TestWSError 测试错误类型
func TestWSError(t *testing.T) {
	err := ErrConnectionClosed
	if err.Error() != "connection closed" {
		t.Errorf("ErrConnectionClosed.Error() = %s, want 'connection closed'", err.Error())
	}

	err = ErrSendBufferFull
	if err.Error() != "send buffer full" {
		t.Errorf("ErrSendBufferFull.Error() = %s, want 'send buffer full'", err.Error())
	}

	err = ErrAuthFailed
	if err.Error() != "authentication failed" {
		t.Errorf("ErrAuthFailed.Error() = %s, want 'authentication failed'", err.Error())
	}

	err = ErrInvalidMessage
	if err.Error() != "invalid message" {
		t.Errorf("ErrInvalidMessage.Error() = %s, want 'invalid message'", err.Error())
	}
}

// mockNetConn 模拟net.Conn接口
type mockNetConn struct {
	readData  []byte
	writeData []byte
	closed    bool
}

func (m *mockNetConn) Read(b []byte) (n int, err error) {
	if len(m.readData) == 0 {
		return 0, nil
	}
	n = copy(b, m.readData)
	m.readData = m.readData[n:]
	return n, nil
}

func (m *mockNetConn) Write(b []byte) (n int, err error) {
	m.writeData = append(m.writeData, b...)
	return len(b), nil
}

func (m *mockNetConn) Close() error {
	m.closed = true
	return nil
}

func (m *mockNetConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8888}
}

func (m *mockNetConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
}

func (m *mockNetConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *mockNetConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockNetConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// TestWebSocketEndToEnd 端到端WebSocket测试
func TestWebSocketEndToEnd(t *testing.T) {
	mr, redisClient := setupTestRedis(t)
	defer mr.Close()
	defer redisClient.Close()

	// 设置Install Key
	testKey := "test-install-key"
	mr.Set("cscan:worker:install_key", testKey)

	svcCtx := setupTestServiceContext(t, redisClient)
	wsHandler := NewWorkerWSHandler(svcCtx)

	// 创建测试服务器
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		WorkerWSEndpointHandler(svcCtx, wsHandler)(w, r)
	}))
	defer server.Close()

	// 将HTTP URL转换为WebSocket URL
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/api/v1/worker/ws"

	// 连接WebSocket
	conn, _, _, err := ws.Dial(context.Background(), wsURL)
	if err != nil {
		t.Fatalf("Failed to connect to WebSocket: %v", err)
	}
	defer conn.Close()

	// 发送认证消息
	authPayload := AuthPayload{
		WorkerName: "test-worker-e2e",
		InstallKey: testKey,
	}
	payloadBytes, _ := json.Marshal(authPayload)
	authMsg := WSMessage{
		Type:    WSTypeAuth,
		Payload: payloadBytes,
	}
	authData, _ := json.Marshal(authMsg)

	err = wsutil.WriteClientMessage(conn, ws.OpText, authData)
	if err != nil {
		t.Fatalf("Failed to send auth message: %v", err)
	}

	// 读取认证响应
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	respData, _, err := wsutil.ReadServerData(conn)
	if err != nil {
		t.Fatalf("Failed to read auth response: %v", err)
	}

	var respMsg WSMessage
	if err := json.Unmarshal(respData, &respMsg); err != nil {
		t.Fatalf("Failed to unmarshal auth response: %v", err)
	}

	if respMsg.Type != WSTypeAuthOK {
		t.Errorf("Expected AUTH_OK, got %s", respMsg.Type)
	}

	// 等待连接注册
	time.Sleep(100 * time.Millisecond)

	// 验证Worker已连接
	workers := wsHandler.GetConnectedWorkers()
	found := false
	for _, w := range workers {
		if w == "test-worker-e2e" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Worker should be registered after authentication")
	}

	// 发送日志消息
	logPayload := LogPayload{
		TaskId:    "e2e-task",
		Level:     "INFO",
		Message:   "E2E test log",
		Timestamp: time.Now().UnixMilli(),
	}
	logPayloadBytes, _ := json.Marshal(logPayload)
	logMsg := WSMessage{
		Type:    WSTypeLog,
		Payload: logPayloadBytes,
	}
	logData, _ := json.Marshal(logMsg)

	err = wsutil.WriteClientMessage(conn, ws.OpText, logData)
	if err != nil {
		t.Fatalf("Failed to send log message: %v", err)
	}

	// 等待日志写入Redis
	time.Sleep(100 * time.Millisecond)

	// 验证日志已写入Redis
	ctx := context.Background()
	logs, err := redisClient.XRange(ctx, "cscan:worker:logs", "-", "+").Result()
	if err != nil {
		t.Fatalf("Failed to read logs: %v", err)
	}

	foundLog := false
	for _, log := range logs {
		if data, ok := log.Values["data"].(string); ok {
			if strings.Contains(data, "E2E test log") {
				foundLog = true
				break
			}
		}
	}
	if !foundLog {
		t.Error("Log message should be written to Redis")
	}

	// 发送PING消息
	pingMsg := WSMessage{Type: WSTypePing}
	pingData, _ := json.Marshal(pingMsg)
	err = wsutil.WriteClientMessage(conn, ws.OpText, pingData)
	if err != nil {
		t.Fatalf("Failed to send ping: %v", err)
	}

	// 读取PONG响应
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	pongData, _, err := wsutil.ReadServerData(conn)
	if err != nil {
		t.Fatalf("Failed to read pong: %v", err)
	}

	var pongMsg WSMessage
	if err := json.Unmarshal(pongData, &pongMsg); err != nil {
		t.Fatalf("Failed to unmarshal pong: %v", err)
	}

	if pongMsg.Type != WSTypePong {
		t.Errorf("Expected PONG, got %s", pongMsg.Type)
	}
}

// TestAuthenticationFailure 测试认证失败场景
func TestAuthenticationFailure(t *testing.T) {
	mr, redisClient := setupTestRedis(t)
	defer mr.Close()
	defer redisClient.Close()

	// 设置Install Key
	testKey := "correct-key"
	mr.Set("cscan:worker:install_key", testKey)

	svcCtx := setupTestServiceContext(t, redisClient)
	wsHandler := NewWorkerWSHandler(svcCtx)

	// 创建测试服务器
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		WorkerWSEndpointHandler(svcCtx, wsHandler)(w, r)
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	// 连接WebSocket
	conn, _, _, err := ws.Dial(context.Background(), wsURL)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// 发送错误的认证消息
	authPayload := AuthPayload{
		WorkerName: "test-worker",
		InstallKey: "wrong-key",
	}
	payloadBytes, _ := json.Marshal(authPayload)
	authMsg := WSMessage{
		Type:    WSTypeAuth,
		Payload: payloadBytes,
	}
	authData, _ := json.Marshal(authMsg)

	err = wsutil.WriteClientMessage(conn, ws.OpText, authData)
	if err != nil {
		t.Fatalf("Failed to send auth: %v", err)
	}

	// 读取认证响应
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	respData, _, err := wsutil.ReadServerData(conn)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	var respMsg WSMessage
	if err := json.Unmarshal(respData, &respMsg); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if respMsg.Type != WSTypeAuthFail {
		t.Errorf("Expected AUTH_FAIL, got %s", respMsg.Type)
	}
}
