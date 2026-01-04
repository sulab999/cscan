package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"cscan/api/internal/svc"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/redis/go-redis/v9"
	"github.com/zeromicro/go-zero/core/logx"
)

// ==================== WebSocket Message Types ====================

const (
	WSTypeAuth           = "AUTH"            // 认证请求
	WSTypeAuthOK         = "AUTH_OK"         // 认证成功
	WSTypeAuthFail       = "AUTH_FAIL"       // 认证失败
	WSTypePing           = "PING"            // 心跳请求
	WSTypePong           = "PONG"            // 心跳响应
	WSTypeLog            = "LOG"             // 日志消息
	WSTypeLogBatch       = "LOG_BATCH"       // 批量日志消息
	WSTypeControl        = "CONTROL"         // 控制信号
	WSTypeTerminalOpen   = "TERMINAL_OPEN"   // 打开终端
	WSTypeTerminalClose  = "TERMINAL_CLOSE"  // 关闭终端
	WSTypeTerminalInput  = "TERMINAL_INPUT"  // 终端输入
	WSTypeTerminalOutput = "TERMINAL_OUTPUT" // 终端输出
	WSTypeTerminalResize = "TERMINAL_RESIZE" // 终端大小调整
	WSTypeFileList       = "FILE_LIST"       // 文件列表
	WSTypeFileUpload     = "FILE_UPLOAD"     // 文件上传
	WSTypeFileDownload   = "FILE_DOWNLOAD"   // 文件下载
	WSTypeFileDelete     = "FILE_DELETE"     // 文件删除
	WSTypeFileMkdir      = "FILE_MKDIR"      // 创建目录
	WSTypeWorkerInfo     = "WORKER_INFO"     // Worker信息
)

// WSMessage WebSocket消息结构
type WSMessage struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// AuthPayload 认证消息载荷
type AuthPayload struct {
	WorkerName string `json:"workerName"`
	InstallKey string `json:"installKey"`
}

// LogPayload 日志消息载荷
type LogPayload struct {
	TaskId    string `json:"taskId"`
	Level     string `json:"level"`
	Message   string `json:"message"`
	Timestamp int64  `json:"timestamp"`
}

// LogBatchPayload 批量日志消息载荷
type LogBatchPayload struct {
	Logs []LogPayload `json:"logs"`
}

// ControlPayload 控制信号载荷
type ControlPayload struct {
	TaskId string `json:"taskId"`
	Action string `json:"action"` // STOP, PAUSE, RESUME
}

// WorkerInfoRequest Worker信息请求载荷
type WorkerInfoRequest struct {
	RequestId string `json:"requestId"`
}

// WorkerInfoPayload Worker详细信息载荷
type WorkerInfoPayload struct {
	Name         string          `json:"name"`
	IP           string          `json:"ip"`
	OS           string          `json:"os"`
	Arch         string          `json:"arch"`
	Version      string          `json:"version"`
	Hostname     string          `json:"hostname"`
	Uptime       int64           `json:"uptime"`
	SystemUptime int64           `json:"systemUptime"`
	CpuCores     int             `json:"cpuCores"`
	CpuLoad      float64         `json:"cpuLoad"`
	MemTotal     uint64          `json:"memTotal"`
	MemUsed      uint64          `json:"memUsed"`
	MemPercent   float64         `json:"memPercent"`
	DiskTotal    uint64          `json:"diskTotal"`
	DiskUsed     uint64          `json:"diskUsed"`
	DiskPercent  float64         `json:"diskPercent"`
	Concurrency  int             `json:"concurrency"`
	TaskStarted  int             `json:"taskStarted"`
	TaskRunning  int             `json:"taskRunning"`
	Tools        map[string]bool `json:"tools"`
}

// WorkerInfoResponse Worker信息响应载荷
type WorkerInfoResponse struct {
	RequestId string             `json:"requestId"`
	Info      *WorkerInfoPayload `json:"info"`
	Error     string             `json:"error,omitempty"`
}

// ==================== File Operation Types ====================

// FileInfo 文件信息
type FileInfo struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	Mode    string `json:"mode"`
	ModTime int64  `json:"modTime"`
	IsDir   bool   `json:"isDir"`
}

// FileListRequest 文件列表请求
type FileListRequest struct {
	RequestId string `json:"requestId"`
	Path      string `json:"path"`
}

// FileListResponse 文件列表响应
type FileListResponse struct {
	RequestId string     `json:"requestId"`
	Path      string     `json:"path"`
	Files     []FileInfo `json:"files,omitempty"`
	Error     string     `json:"error,omitempty"`
}

// FileUploadRequest 文件上传请求
type FileUploadRequest struct {
	RequestId string `json:"requestId"`
	Path      string `json:"path"`
	Data      string `json:"data"` // Base64编码的文件内容
}

// FileUploadResponse 文件上传响应
type FileUploadResponse struct {
	RequestId string `json:"requestId"`
	Path      string `json:"path"`
	Success   bool   `json:"success"`
	Error     string `json:"error,omitempty"`
}

// FileDownloadRequest 文件下载请求
type FileDownloadRequest struct {
	RequestId string `json:"requestId"`
	Path      string `json:"path"`
}

// FileDownloadResponse 文件下载响应
type FileDownloadResponse struct {
	RequestId string `json:"requestId"`
	Path      string `json:"path"`
	Data      string `json:"data,omitempty"` // Base64编码的文件内容
	Size      int64  `json:"size,omitempty"`
	Error     string `json:"error,omitempty"`
}

// FileDeleteRequest 文件删除请求
type FileDeleteRequest struct {
	RequestId string `json:"requestId"`
	Path      string `json:"path"`
}

// FileDeleteResponse 文件删除响应
type FileDeleteResponse struct {
	RequestId string `json:"requestId"`
	Path      string `json:"path"`
	Success   bool   `json:"success"`
	Error     string `json:"error,omitempty"`
}

// FileMkdirRequest 创建目录请求
type FileMkdirRequest struct {
	RequestId string `json:"requestId"`
	Path      string `json:"path"`
}

// FileMkdirResponse 创建目录响应
type FileMkdirResponse struct {
	RequestId string `json:"requestId"`
	Path      string `json:"path"`
	Success   bool   `json:"success"`
	Error     string `json:"error,omitempty"`
}

// ==================== Terminal Operation Types ====================

// TerminalOpenRequest 打开终端请求
type TerminalOpenRequest struct {
	RequestId string `json:"requestId"`
	SessionId string `json:"sessionId"`
	Cols      int    `json:"cols,omitempty"`
	Rows      int    `json:"rows,omitempty"`
}

// TerminalOpenResponse 打开终端响应
type TerminalOpenResponse struct {
	RequestId string `json:"requestId"`
	SessionId string `json:"sessionId"`
	Success   bool   `json:"success"`
	Error     string `json:"error,omitempty"`
}

// TerminalCloseRequest 关闭终端请求
type TerminalCloseRequest struct {
	RequestId string `json:"requestId"`
	SessionId string `json:"sessionId"`
}

// TerminalCloseResponse 关闭终端响应
type TerminalCloseResponse struct {
	RequestId string `json:"requestId"`
	SessionId string `json:"sessionId"`
	Success   bool   `json:"success"`
	Error     string `json:"error,omitempty"`
}

// TerminalInputRequest 终端输入请求
type TerminalInputRequest struct {
	RequestId string `json:"requestId"`
	SessionId string `json:"sessionId"`
	Data      string `json:"data"`             // Base64编码的输入数据
	Command   string `json:"command,omitempty"` // 可选：直接执行的命令
}

// TerminalInputResponse 终端输入响应
type TerminalInputResponse struct {
	RequestId string `json:"requestId"`
	SessionId string `json:"sessionId"`
	Success   bool   `json:"success"`
	Error     string `json:"error,omitempty"`
}

// TerminalOutputPayload 终端输出载荷
type TerminalOutputPayload struct {
	SessionId string `json:"sessionId"`
	Data      string `json:"data"` // Base64编码的输出数据
}

// TerminalResizeRequest 终端大小调整请求
type TerminalResizeRequest struct {
	RequestId string `json:"requestId"`
	SessionId string `json:"sessionId"`
	Cols      int    `json:"cols"`
	Rows      int    `json:"rows"`
}

// TerminalResizeResponse 终端大小调整响应
type TerminalResizeResponse struct {
	RequestId string `json:"requestId"`
	SessionId string `json:"sessionId"`
	Success   bool   `json:"success"`
	Error     string `json:"error,omitempty"`
}


// ==================== Worker Connection ====================

// WorkerConnection 单个Worker的WebSocket连接
type WorkerConnection struct {
	conn            net.Conn
	workerName      string
	svcCtx          *svc.ServiceContext
	sendChan        chan []byte
	closeChan       chan struct{}
	closeOnce       sync.Once
	lastPing        time.Time
	mu              sync.RWMutex
	pendingRequests sync.Map // requestId -> chan *WorkerInfoResponse
}

// NewWorkerConnection 创建新的Worker连接
func NewWorkerConnection(conn net.Conn, workerName string, svcCtx *svc.ServiceContext) *WorkerConnection {
	return &WorkerConnection{
		conn:       conn,
		workerName: workerName,
		svcCtx:     svcCtx,
		sendChan:   make(chan []byte, 256),
		closeChan:  make(chan struct{}),
		lastPing:   time.Now(),
	}
}

// Send 发送消息到Worker
func (wc *WorkerConnection) Send(msg *WSMessage) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	select {
	case wc.sendChan <- data:
		return nil
	case <-wc.closeChan:
		return ErrConnectionClosed
	default:
		return ErrSendBufferFull
	}
}

// Close 关闭连接
func (wc *WorkerConnection) Close() {
	wc.closeOnce.Do(func() {
		close(wc.closeChan)
	})
}

// UpdateLastPing 更新最后心跳时间
func (wc *WorkerConnection) UpdateLastPing() {
	wc.mu.Lock()
	wc.lastPing = time.Now()
	wc.mu.Unlock()
}

// GetLastPing 获取最后心跳时间
func (wc *WorkerConnection) GetLastPing() time.Time {
	wc.mu.RLock()
	defer wc.mu.RUnlock()
	return wc.lastPing
}

// RequestWorkerInfo 请求Worker信息（同步等待响应）
func (wc *WorkerConnection) RequestWorkerInfo(timeout time.Duration) (*WorkerInfoPayload, error) {
	// 生成唯一请求ID
	requestId := fmt.Sprintf("%d", time.Now().UnixNano())

	// 创建响应通道
	respChan := make(chan *WorkerInfoResponse, 1)
	wc.pendingRequests.Store(requestId, respChan)
	defer wc.pendingRequests.Delete(requestId)

	// 发送请求
	payload, _ := json.Marshal(&WorkerInfoRequest{RequestId: requestId})
	if err := wc.Send(&WSMessage{Type: WSTypeWorkerInfo, Payload: payload}); err != nil {
		return nil, err
	}

	// 等待响应
	select {
	case resp := <-respChan:
		if resp.Error != "" {
			return nil, fmt.Errorf("%s", resp.Error)
		}
		return resp.Info, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("request timeout")
	case <-wc.closeChan:
		return nil, ErrConnectionClosed
	}
}

// HandleWorkerInfoResponse 处理Worker信息响应
func (wc *WorkerConnection) HandleWorkerInfoResponse(payload json.RawMessage) {
	var resp WorkerInfoResponse
	if err := json.Unmarshal(payload, &resp); err != nil {
		logx.Errorf("[WorkerWS] Invalid worker info response: %v", err)
		return
	}

	// 查找对应的请求通道
	if ch, ok := wc.pendingRequests.Load(resp.RequestId); ok {
		if respChan, ok := ch.(chan *WorkerInfoResponse); ok {
			select {
			case respChan <- &resp:
			default:
			}
		}
	}
}

// ==================== File Operation Methods ====================

// RequestFileList 请求文件列表（同步等待响应）
func (wc *WorkerConnection) RequestFileList(path string, timeout time.Duration) (*FileListResponse, error) {
	requestId := fmt.Sprintf("%d", time.Now().UnixNano())

	respChan := make(chan *FileListResponse, 1)
	wc.pendingRequests.Store("file_list_"+requestId, respChan)
	defer wc.pendingRequests.Delete("file_list_" + requestId)

	payload, _ := json.Marshal(&FileListRequest{RequestId: requestId, Path: path})
	if err := wc.Send(&WSMessage{Type: WSTypeFileList, Payload: payload}); err != nil {
		return nil, err
	}

	select {
	case resp := <-respChan:
		return resp, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("request timeout")
	case <-wc.closeChan:
		return nil, ErrConnectionClosed
	}
}

// HandleFileListResponse 处理文件列表响应
func (wc *WorkerConnection) HandleFileListResponse(payload json.RawMessage) {
	var resp FileListResponse
	if err := json.Unmarshal(payload, &resp); err != nil {
		logx.Errorf("[WorkerWS] Invalid file list response: %v", err)
		return
	}

	if ch, ok := wc.pendingRequests.Load("file_list_" + resp.RequestId); ok {
		if respChan, ok := ch.(chan *FileListResponse); ok {
			select {
			case respChan <- &resp:
			default:
			}
		}
	}
}

// RequestFileUpload 请求文件上传（同步等待响应）
func (wc *WorkerConnection) RequestFileUpload(path, data string, timeout time.Duration) (*FileUploadResponse, error) {
	requestId := fmt.Sprintf("%d", time.Now().UnixNano())

	respChan := make(chan *FileUploadResponse, 1)
	wc.pendingRequests.Store("file_upload_"+requestId, respChan)
	defer wc.pendingRequests.Delete("file_upload_" + requestId)

	payload, _ := json.Marshal(&FileUploadRequest{RequestId: requestId, Path: path, Data: data})
	if err := wc.Send(&WSMessage{Type: WSTypeFileUpload, Payload: payload}); err != nil {
		return nil, err
	}

	select {
	case resp := <-respChan:
		return resp, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("request timeout")
	case <-wc.closeChan:
		return nil, ErrConnectionClosed
	}
}

// HandleFileUploadResponse 处理文件上传响应
func (wc *WorkerConnection) HandleFileUploadResponse(payload json.RawMessage) {
	var resp FileUploadResponse
	if err := json.Unmarshal(payload, &resp); err != nil {
		logx.Errorf("[WorkerWS] Invalid file upload response: %v", err)
		return
	}

	if ch, ok := wc.pendingRequests.Load("file_upload_" + resp.RequestId); ok {
		if respChan, ok := ch.(chan *FileUploadResponse); ok {
			select {
			case respChan <- &resp:
			default:
			}
		}
	}
}

// RequestFileDownload 请求文件下载（同步等待响应）
func (wc *WorkerConnection) RequestFileDownload(path string, timeout time.Duration) (*FileDownloadResponse, error) {
	requestId := fmt.Sprintf("%d", time.Now().UnixNano())

	respChan := make(chan *FileDownloadResponse, 1)
	wc.pendingRequests.Store("file_download_"+requestId, respChan)
	defer wc.pendingRequests.Delete("file_download_" + requestId)

	payload, _ := json.Marshal(&FileDownloadRequest{RequestId: requestId, Path: path})
	if err := wc.Send(&WSMessage{Type: WSTypeFileDownload, Payload: payload}); err != nil {
		return nil, err
	}

	select {
	case resp := <-respChan:
		return resp, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("request timeout")
	case <-wc.closeChan:
		return nil, ErrConnectionClosed
	}
}

// HandleFileDownloadResponse 处理文件下载响应
func (wc *WorkerConnection) HandleFileDownloadResponse(payload json.RawMessage) {
	var resp FileDownloadResponse
	if err := json.Unmarshal(payload, &resp); err != nil {
		logx.Errorf("[WorkerWS] Invalid file download response: %v", err)
		return
	}

	if ch, ok := wc.pendingRequests.Load("file_download_" + resp.RequestId); ok {
		if respChan, ok := ch.(chan *FileDownloadResponse); ok {
			select {
			case respChan <- &resp:
			default:
			}
		}
	}
}

// RequestFileDelete 请求文件删除（同步等待响应）
func (wc *WorkerConnection) RequestFileDelete(path string, timeout time.Duration) (*FileDeleteResponse, error) {
	requestId := fmt.Sprintf("%d", time.Now().UnixNano())

	respChan := make(chan *FileDeleteResponse, 1)
	wc.pendingRequests.Store("file_delete_"+requestId, respChan)
	defer wc.pendingRequests.Delete("file_delete_" + requestId)

	payload, _ := json.Marshal(&FileDeleteRequest{RequestId: requestId, Path: path})
	if err := wc.Send(&WSMessage{Type: WSTypeFileDelete, Payload: payload}); err != nil {
		return nil, err
	}

	select {
	case resp := <-respChan:
		return resp, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("request timeout")
	case <-wc.closeChan:
		return nil, ErrConnectionClosed
	}
}

// HandleFileDeleteResponse 处理文件删除响应
func (wc *WorkerConnection) HandleFileDeleteResponse(payload json.RawMessage) {
	var resp FileDeleteResponse
	if err := json.Unmarshal(payload, &resp); err != nil {
		logx.Errorf("[WorkerWS] Invalid file delete response: %v", err)
		return
	}

	if ch, ok := wc.pendingRequests.Load("file_delete_" + resp.RequestId); ok {
		if respChan, ok := ch.(chan *FileDeleteResponse); ok {
			select {
			case respChan <- &resp:
			default:
			}
		}
	}
}

// RequestFileMkdir 请求创建目录（同步等待响应）
func (wc *WorkerConnection) RequestFileMkdir(path string, timeout time.Duration) (*FileMkdirResponse, error) {
	requestId := fmt.Sprintf("%d", time.Now().UnixNano())

	respChan := make(chan *FileMkdirResponse, 1)
	wc.pendingRequests.Store("file_mkdir_"+requestId, respChan)
	defer wc.pendingRequests.Delete("file_mkdir_" + requestId)

	payload, _ := json.Marshal(&FileMkdirRequest{RequestId: requestId, Path: path})
	if err := wc.Send(&WSMessage{Type: WSTypeFileMkdir, Payload: payload}); err != nil {
		return nil, err
	}

	select {
	case resp := <-respChan:
		return resp, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("request timeout")
	case <-wc.closeChan:
		return nil, ErrConnectionClosed
	}
}

// HandleFileMkdirResponse 处理创建目录响应
func (wc *WorkerConnection) HandleFileMkdirResponse(payload json.RawMessage) {
	var resp FileMkdirResponse
	if err := json.Unmarshal(payload, &resp); err != nil {
		logx.Errorf("[WorkerWS] Invalid file mkdir response: %v", err)
		return
	}

	if ch, ok := wc.pendingRequests.Load("file_mkdir_" + resp.RequestId); ok {
		if respChan, ok := ch.(chan *FileMkdirResponse); ok {
			select {
			case respChan <- &resp:
			default:
			}
		}
	}
}

// ==================== Terminal Operation Methods ====================

// RequestTerminalOpen 请求打开终端（同步等待响应）
func (wc *WorkerConnection) RequestTerminalOpen(sessionId string, cols, rows int, timeout time.Duration) (*TerminalOpenResponse, error) {
	requestId := fmt.Sprintf("%d", time.Now().UnixNano())

	respChan := make(chan *TerminalOpenResponse, 1)
	wc.pendingRequests.Store("terminal_open_"+requestId, respChan)
	defer wc.pendingRequests.Delete("terminal_open_" + requestId)

	payload, _ := json.Marshal(&TerminalOpenRequest{RequestId: requestId, SessionId: sessionId, Cols: cols, Rows: rows})
	if err := wc.Send(&WSMessage{Type: WSTypeTerminalOpen, Payload: payload}); err != nil {
		return nil, err
	}

	select {
	case resp := <-respChan:
		return resp, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("request timeout")
	case <-wc.closeChan:
		return nil, ErrConnectionClosed
	}
}

// HandleTerminalOpenResponse 处理打开终端响应
func (wc *WorkerConnection) HandleTerminalOpenResponse(payload json.RawMessage) {
	var resp TerminalOpenResponse
	if err := json.Unmarshal(payload, &resp); err != nil {
		logx.Errorf("[WorkerWS] Invalid terminal open response: %v", err)
		return
	}

	if ch, ok := wc.pendingRequests.Load("terminal_open_" + resp.RequestId); ok {
		if respChan, ok := ch.(chan *TerminalOpenResponse); ok {
			select {
			case respChan <- &resp:
			default:
			}
		}
	}
}

// RequestTerminalClose 请求关闭终端（同步等待响应）
func (wc *WorkerConnection) RequestTerminalClose(sessionId string, timeout time.Duration) (*TerminalCloseResponse, error) {
	requestId := fmt.Sprintf("%d", time.Now().UnixNano())

	respChan := make(chan *TerminalCloseResponse, 1)
	wc.pendingRequests.Store("terminal_close_"+requestId, respChan)
	defer wc.pendingRequests.Delete("terminal_close_" + requestId)

	payload, _ := json.Marshal(&TerminalCloseRequest{RequestId: requestId, SessionId: sessionId})
	if err := wc.Send(&WSMessage{Type: WSTypeTerminalClose, Payload: payload}); err != nil {
		return nil, err
	}

	select {
	case resp := <-respChan:
		return resp, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("request timeout")
	case <-wc.closeChan:
		return nil, ErrConnectionClosed
	}
}

// HandleTerminalCloseResponse 处理关闭终端响应
func (wc *WorkerConnection) HandleTerminalCloseResponse(payload json.RawMessage) {
	var resp TerminalCloseResponse
	if err := json.Unmarshal(payload, &resp); err != nil {
		logx.Errorf("[WorkerWS] Invalid terminal close response: %v", err)
		return
	}

	if ch, ok := wc.pendingRequests.Load("terminal_close_" + resp.RequestId); ok {
		if respChan, ok := ch.(chan *TerminalCloseResponse); ok {
			select {
			case respChan <- &resp:
			default:
			}
		}
	}
}

// RequestTerminalInput 请求终端输入（同步等待响应）
func (wc *WorkerConnection) RequestTerminalInput(sessionId, data, command string, timeout time.Duration) (*TerminalInputResponse, error) {
	requestId := fmt.Sprintf("%d", time.Now().UnixNano())

	respChan := make(chan *TerminalInputResponse, 1)
	wc.pendingRequests.Store("terminal_input_"+requestId, respChan)
	defer wc.pendingRequests.Delete("terminal_input_" + requestId)

	payload, _ := json.Marshal(&TerminalInputRequest{RequestId: requestId, SessionId: sessionId, Data: data, Command: command})
	if err := wc.Send(&WSMessage{Type: WSTypeTerminalInput, Payload: payload}); err != nil {
		return nil, err
	}

	select {
	case resp := <-respChan:
		return resp, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("request timeout")
	case <-wc.closeChan:
		return nil, ErrConnectionClosed
	}
}

// HandleTerminalInputResponse 处理终端输入响应
func (wc *WorkerConnection) HandleTerminalInputResponse(payload json.RawMessage) {
	var resp TerminalInputResponse
	if err := json.Unmarshal(payload, &resp); err != nil {
		logx.Errorf("[WorkerWS] Invalid terminal input response: %v", err)
		return
	}

	if ch, ok := wc.pendingRequests.Load("terminal_input_" + resp.RequestId); ok {
		if respChan, ok := ch.(chan *TerminalInputResponse); ok {
			select {
			case respChan <- &resp:
			default:
			}
		}
	}
}

// RequestTerminalResize 请求终端大小调整（同步等待响应）
func (wc *WorkerConnection) RequestTerminalResize(sessionId string, cols, rows int, timeout time.Duration) (*TerminalResizeResponse, error) {
	requestId := fmt.Sprintf("%d", time.Now().UnixNano())

	respChan := make(chan *TerminalResizeResponse, 1)
	wc.pendingRequests.Store("terminal_resize_"+requestId, respChan)
	defer wc.pendingRequests.Delete("terminal_resize_" + requestId)

	payload, _ := json.Marshal(&TerminalResizeRequest{RequestId: requestId, SessionId: sessionId, Cols: cols, Rows: rows})
	if err := wc.Send(&WSMessage{Type: WSTypeTerminalResize, Payload: payload}); err != nil {
		return nil, err
	}

	select {
	case resp := <-respChan:
		return resp, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("request timeout")
	case <-wc.closeChan:
		return nil, ErrConnectionClosed
	}
}

// HandleTerminalResizeResponse 处理终端大小调整响应
func (wc *WorkerConnection) HandleTerminalResizeResponse(payload json.RawMessage) {
	var resp TerminalResizeResponse
	if err := json.Unmarshal(payload, &resp); err != nil {
		logx.Errorf("[WorkerWS] Invalid terminal resize response: %v", err)
		return
	}

	if ch, ok := wc.pendingRequests.Load("terminal_resize_" + resp.RequestId); ok {
		if respChan, ok := ch.(chan *TerminalResizeResponse); ok {
			select {
			case respChan <- &resp:
			default:
			}
		}
	}
}

// ==================== WebSocket Handler ====================

// WorkerWSHandler WebSocket处理器
type WorkerWSHandler struct {
	svcCtx         *svc.ServiceContext
	connections    sync.Map // workerName -> *WorkerConnection
	workerSessions sync.Map // workerName -> map[sessionId]bool
	sessionMu      sync.RWMutex
}

// 错误定义
var (
	ErrConnectionClosed = &WSError{Code: 1000, Message: "connection closed"}
	ErrSendBufferFull   = &WSError{Code: 1001, Message: "send buffer full"}
	ErrAuthFailed       = &WSError{Code: 1002, Message: "authentication failed"}
	ErrInvalidMessage   = &WSError{Code: 1003, Message: "invalid message"}
)

type WSError struct {
	Code    int
	Message string
}

func (e *WSError) Error() string {
	return e.Message
}

// NewWorkerWSHandler 创建WebSocket处理器
func NewWorkerWSHandler(svcCtx *svc.ServiceContext) *WorkerWSHandler {
	h := &WorkerWSHandler{
		svcCtx: svcCtx,
	}
	
	// 启动 Worker 控制命令订阅
	go h.subscribeWorkerControl()
	
	return h
}

// subscribeWorkerControl 订阅 Worker 控制命令频道
func (h *WorkerWSHandler) subscribeWorkerControl() {
	ctx := context.Background()
	pubsub := h.svcCtx.RedisClient.Subscribe(ctx, "cscan:worker:control")
	defer pubsub.Close()

	ch := pubsub.Channel()
	logx.Info("[WorkerWS] Started subscribing to worker control channel")

	for msg := range ch {
		// 解析控制命令
		var cmd struct {
			Action      string `json:"action"`
			WorkerName  string `json:"workerName"`
			NewName     string `json:"newName,omitempty"`
			Concurrency int    `json:"concurrency,omitempty"`
		}
		if err := json.Unmarshal([]byte(msg.Payload), &cmd); err != nil {
			logx.Errorf("[WorkerWS] Invalid control command: %v", err)
			continue
		}

		logx.Infof("[WorkerWS] Received control command: action=%s, worker=%s", cmd.Action, cmd.WorkerName)

		// 获取 Worker 连接
		conn, ok := h.GetConnection(cmd.WorkerName)
		if !ok {
			logx.Infof("[WorkerWS] Worker %s not connected, skipping control command", cmd.WorkerName)
			continue
		}

		// 构造并发送控制消息
		var payload []byte
		switch cmd.Action {
		case "stop":
			payload, _ = json.Marshal(map[string]interface{}{
				"action": "WORKER_STOP",
			})
		case "restart":
			payload, _ = json.Marshal(map[string]interface{}{
				"action": "WORKER_RESTART",
			})
		case "rename":
			payload, _ = json.Marshal(map[string]interface{}{
				"action":  "WORKER_RENAME",
				"newName": cmd.NewName,
			})
		case "setConcurrency":
			payload, _ = json.Marshal(map[string]interface{}{
				"action":      "WORKER_SET_CONCURRENCY",
				"concurrency": cmd.Concurrency,
			})
		default:
			logx.Infof("[WorkerWS] Unknown control action: %s", cmd.Action)
			continue
		}

		// 发送控制消息给 Worker
		if err := conn.Send(&WSMessage{
			Type:    WSTypeControl,
			Payload: payload,
		}); err != nil {
			logx.Errorf("[WorkerWS] Failed to send control command to %s: %v", cmd.WorkerName, err)
		} else {
			logx.Infof("[WorkerWS] Sent control command to %s: %s", cmd.WorkerName, cmd.Action)
		}
	}
}

// GetWorkerSessionCount 获取Worker当前会话数
func (h *WorkerWSHandler) GetWorkerSessionCount(workerName string) int {
	h.sessionMu.RLock()
	defer h.sessionMu.RUnlock()

	if sessions, ok := h.workerSessions.Load(workerName); ok {
		if sessionMap, ok := sessions.(map[string]bool); ok {
			return len(sessionMap)
		}
	}
	return 0
}

// AddWorkerSession 添加Worker会话
func (h *WorkerWSHandler) AddWorkerSession(workerName, sessionId string) {
	h.sessionMu.Lock()
	defer h.sessionMu.Unlock()

	var sessionMap map[string]bool
	if sessions, ok := h.workerSessions.Load(workerName); ok {
		sessionMap = sessions.(map[string]bool)
	} else {
		sessionMap = make(map[string]bool)
	}
	sessionMap[sessionId] = true
	h.workerSessions.Store(workerName, sessionMap)
}

// RemoveWorkerSession 移除Worker会话
func (h *WorkerWSHandler) RemoveWorkerSession(workerName, sessionId string) {
	h.sessionMu.Lock()
	defer h.sessionMu.Unlock()

	if sessions, ok := h.workerSessions.Load(workerName); ok {
		if sessionMap, ok := sessions.(map[string]bool); ok {
			delete(sessionMap, sessionId)
			if len(sessionMap) == 0 {
				h.workerSessions.Delete(workerName)
			} else {
				h.workerSessions.Store(workerName, sessionMap)
			}
		}
	}
}

// GetConnection 获取Worker连接
func (h *WorkerWSHandler) GetConnection(workerName string) (*WorkerConnection, bool) {
	if conn, ok := h.connections.Load(workerName); ok {
		return conn.(*WorkerConnection), true
	}
	return nil, false
}

// BroadcastControl 向指定Worker发送控制信号
func (h *WorkerWSHandler) BroadcastControl(workerName, taskId, action string) error {
	conn, ok := h.GetConnection(workerName)
	if !ok {
		return ErrConnectionClosed
	}

	payload, _ := json.Marshal(&ControlPayload{
		TaskId: taskId,
		Action: action,
	})

	return conn.Send(&WSMessage{
		Type:    WSTypeControl,
		Payload: payload,
	})
}

// BroadcastControlToAll 向所有Worker广播控制信号
func (h *WorkerWSHandler) BroadcastControlToAll(taskId, action string) {
	payload, _ := json.Marshal(&ControlPayload{
		TaskId: taskId,
		Action: action,
	})

	msg := &WSMessage{
		Type:    WSTypeControl,
		Payload: payload,
	}

	h.connections.Range(func(key, value interface{}) bool {
		if conn, ok := value.(*WorkerConnection); ok {
			conn.Send(msg)
		}
		return true
	})
}

// GetConnectedWorkers 获取所有已连接的Worker名称
func (h *WorkerWSHandler) GetConnectedWorkers() []string {
	var workers []string
	h.connections.Range(func(key, value interface{}) bool {
		if name, ok := key.(string); ok {
			workers = append(workers, name)
		}
		return true
	})
	return workers
}


// ==================== HTTP Handler ====================

// WorkerWSEndpointHandler WebSocket端点处理器
// GET /api/v1/worker/ws
func WorkerWSEndpointHandler(svcCtx *svc.ServiceContext, wsHandler *WorkerWSHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 升级HTTP连接为WebSocket
		conn, _, _, err := ws.UpgradeHTTP(r, w)
		if err != nil {
			logx.Errorf("[WorkerWS] Failed to upgrade connection: %v", err)
			return
		}

		// 创建连接上下文
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()

		// 处理连接
		handleWebSocketConnection(ctx, conn, svcCtx, wsHandler)
	}
}

// handleWebSocketConnection 处理WebSocket连接
func handleWebSocketConnection(ctx context.Context, conn net.Conn, svcCtx *svc.ServiceContext, wsHandler *WorkerWSHandler) {
	defer conn.Close()

	// 等待认证消息（超时30秒）
	authCtx, authCancel := context.WithTimeout(ctx, 30*time.Second)
	defer authCancel()

	workerName, err := waitForAuth(authCtx, conn, svcCtx)
	if err != nil {
		logx.Errorf("[WorkerWS] Authentication failed: %v", err)
		sendAuthFail(conn, err.Error())
		return
	}

	// 认证成功，发送AUTH_OK
	sendAuthOK(conn)
	logx.Infof("[WorkerWS] Worker authenticated: %s", workerName)

	// 创建Worker连接
	wc := NewWorkerConnection(conn, workerName, svcCtx)

	// 检查是否已有同名连接，如果有则关闭旧连接
	if oldConn, ok := wsHandler.connections.Load(workerName); ok {
		if old, ok := oldConn.(*WorkerConnection); ok {
			old.Close()
		}
	}

	// 注册连接
	wsHandler.connections.Store(workerName, wc)
	defer func() {
		wsHandler.connections.Delete(workerName)
		wc.Close()
		logx.Infof("[WorkerWS] Worker disconnected: %s", workerName)
	}()

	// 启动控制信号订阅
	go subscribeControlSignals(ctx, wc, svcCtx)

	// 启动发送协程
	go writePump(ctx, conn, wc)

	// 启动心跳检测
	go heartbeatChecker(ctx, wc)

	// 主循环：读取消息
	readPump(ctx, conn, wc, svcCtx)
}

// ==================== Authentication ====================

// waitForAuth 等待认证消息
func waitForAuth(ctx context.Context, conn net.Conn, svcCtx *svc.ServiceContext) (string, error) {
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	// 读取认证消息
	data, _, err := wsutil.ReadClientData(conn)
	if err != nil {
		return "", err
	}

	var msg WSMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return "", ErrInvalidMessage
	}

	if msg.Type != WSTypeAuth {
		return "", ErrAuthFailed
	}

	var authPayload AuthPayload
	if err := json.Unmarshal(msg.Payload, &authPayload); err != nil {
		return "", ErrInvalidMessage
	}

	// 验证Install Key
	if err := validateInstallKey(ctx, svcCtx, authPayload.InstallKey); err != nil {
		return "", err
	}

	if authPayload.WorkerName == "" {
		return "", ErrAuthFailed
	}

	return authPayload.WorkerName, nil
}

// validateInstallKey 验证Install Key
func validateInstallKey(ctx context.Context, svcCtx *svc.ServiceContext, installKey string) error {
	if installKey == "" {
		return ErrAuthFailed
	}

	// 从Redis获取存储的Install Key
	installKeyKey := "cscan:worker:install_key"
	storedKey, err := svcCtx.RedisClient.Get(ctx, installKeyKey).Result()
	if err != nil || storedKey == "" {
		logx.Error("[WorkerWS] Install key not configured in Redis")
		return ErrAuthFailed
	}

	if installKey != storedKey {
		logx.Errorf("[WorkerWS] Invalid install key: %s", installKey)
		return ErrAuthFailed
	}

	return nil
}

// sendAuthOK 发送认证成功消息
func sendAuthOK(conn io.Writer) {
	msg := &WSMessage{Type: WSTypeAuthOK}
	data, _ := json.Marshal(msg)
	wsutil.WriteServerMessage(conn, ws.OpText, data)
}

// sendAuthFail 发送认证失败消息
func sendAuthFail(conn io.Writer, reason string) {
	payload, _ := json.Marshal(map[string]string{"reason": reason})
	msg := &WSMessage{Type: WSTypeAuthFail, Payload: payload}
	data, _ := json.Marshal(msg)
	wsutil.WriteServerMessage(conn, ws.OpText, data)
}


// ==================== Message Pumps ====================

// readPump 读取消息循环
func readPump(ctx context.Context, conn net.Conn, wc *WorkerConnection, svcCtx *svc.ServiceContext) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-wc.closeChan:
			return
		default:
		}

		// 设置读取超时
		conn.SetReadDeadline(time.Now().Add(90 * time.Second))

		data, _, err := wsutil.ReadClientData(conn)
		if err != nil {
			logx.Errorf("[WorkerWS] Read error for %s: %v", wc.workerName, err)
			return
		}

		var msg WSMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			logx.Errorf("[WorkerWS] Invalid message from %s: %v, data: %s", wc.workerName, err, string(data))
			continue
		}

		// 调试：打印收到的消息类型
		logx.Infof("[WorkerWS] Received message from %s: type=%s", wc.workerName, msg.Type)

		// 路由消息
		handleMessage(ctx, wc, svcCtx, &msg)
	}
}

// writePump 发送消息循环
func writePump(ctx context.Context, conn net.Conn, wc *WorkerConnection) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-wc.closeChan:
			return
		case data := <-wc.sendChan:
			if err := wsutil.WriteServerMessage(conn, ws.OpText, data); err != nil {
				logx.Errorf("[WorkerWS] Write error for %s: %v", wc.workerName, err)
				return
			}
		case <-ticker.C:
			// 发送PING保活
			msg := &WSMessage{Type: WSTypePing}
			data, _ := json.Marshal(msg)
			if err := wsutil.WriteServerMessage(conn, ws.OpText, data); err != nil {
				logx.Errorf("[WorkerWS] Ping error for %s: %v", wc.workerName, err)
				return
			}
		}
	}
}

// heartbeatChecker 心跳检测
func heartbeatChecker(ctx context.Context, wc *WorkerConnection) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-wc.closeChan:
			return
		case <-ticker.C:
			// 检查最后心跳时间，超过90秒未收到心跳则断开
			if time.Since(wc.GetLastPing()) > 90*time.Second {
				logx.Infof("[WorkerWS] Heartbeat timeout for %s", wc.workerName)
				wc.Close()
				return
			}
		}
	}
}

// ==================== Message Routing ====================

// handleMessage 处理消息路由
func handleMessage(ctx context.Context, wc *WorkerConnection, svcCtx *svc.ServiceContext, msg *WSMessage) {
	switch msg.Type {
	case WSTypePing:
		handlePing(wc)
	case WSTypePong:
		handlePong(wc)
	case WSTypeLog:
		handleLog(ctx, wc, svcCtx, msg.Payload)
	case WSTypeLogBatch:
		handleLogBatch(ctx, wc, svcCtx, msg.Payload)
	case WSTypeWorkerInfo:
		// Worker信息响应
		wc.HandleWorkerInfoResponse(msg.Payload)
	case WSTypeFileList:
		// 文件列表响应
		wc.HandleFileListResponse(msg.Payload)
	case WSTypeFileUpload:
		// 文件上传响应
		wc.HandleFileUploadResponse(msg.Payload)
	case WSTypeFileDownload:
		// 文件下载响应
		wc.HandleFileDownloadResponse(msg.Payload)
	case WSTypeFileDelete:
		// 文件删除响应
		wc.HandleFileDeleteResponse(msg.Payload)
	case WSTypeFileMkdir:
		// 创建目录响应
		wc.HandleFileMkdirResponse(msg.Payload)
	case WSTypeTerminalOpen:
		// 打开终端响应
		wc.HandleTerminalOpenResponse(msg.Payload)
	case WSTypeTerminalClose:
		// 关闭终端响应
		wc.HandleTerminalCloseResponse(msg.Payload)
	case WSTypeTerminalInput:
		// 终端输入响应
		wc.HandleTerminalInputResponse(msg.Payload)
	case WSTypeTerminalOutput:
		// 终端输出（从Worker发来的输出，需要转发给前端）
		handleTerminalOutput(ctx, wc, svcCtx, msg.Payload)
	case WSTypeTerminalResize:
		// 终端大小调整响应
		wc.HandleTerminalResizeResponse(msg.Payload)
	default:
		logx.Infof("[WorkerWS] Unknown message type from %s: %s", wc.workerName, msg.Type)
	}
}

// handlePing 处理PING消息
func handlePing(wc *WorkerConnection) {
	wc.UpdateLastPing()
	// 发送PONG响应
	wc.Send(&WSMessage{Type: WSTypePong})
}

// handlePong 处理PONG消息
func handlePong(wc *WorkerConnection) {
	wc.UpdateLastPing()
}

// handleLog 处理单条日志消息
func handleLog(ctx context.Context, wc *WorkerConnection, svcCtx *svc.ServiceContext, payload json.RawMessage) {
	var logPayload LogPayload
	if err := json.Unmarshal(payload, &logPayload); err != nil {
		logx.Errorf("[WorkerWS] Invalid log payload from %s: %v", wc.workerName, err)
		return
	}

	// 补充时间戳
	if logPayload.Timestamp == 0 {
		logPayload.Timestamp = time.Now().UnixMilli()
	}

	logx.Infof("[WorkerWS] Received log from %s: taskId=%s, level=%s, msg=%s", 
		wc.workerName, logPayload.TaskId, logPayload.Level, logPayload.Message)

	// 写入Redis日志流
	writeLogToRedis(ctx, svcCtx, wc.workerName, &logPayload)
}

// handleLogBatch 处理批量日志消息
func handleLogBatch(ctx context.Context, wc *WorkerConnection, svcCtx *svc.ServiceContext, payload json.RawMessage) {
	var batchPayload LogBatchPayload
	if err := json.Unmarshal(payload, &batchPayload); err != nil {
		logx.Errorf("[WorkerWS] Invalid log batch payload from %s: %v", wc.workerName, err)
		return
	}

	logx.Infof("[WorkerWS] Received log batch from %s: count=%d", wc.workerName, len(batchPayload.Logs))

	for _, logPayload := range batchPayload.Logs {
		if logPayload.Timestamp == 0 {
			logPayload.Timestamp = time.Now().UnixMilli()
		}
		writeLogToRedis(ctx, svcCtx, wc.workerName, &logPayload)
	}
}

// writeLogToRedis 写入日志到Redis
func writeLogToRedis(ctx context.Context, svcCtx *svc.ServiceContext, workerName string, logPayload *LogPayload) {
	// 构建日志数据
	logData := map[string]interface{}{
		"level":      logPayload.Level,
		"message":    logPayload.Message,
		"timestamp":  time.UnixMilli(logPayload.Timestamp).Local().Format("2006-01-02 15:04:05"),
		"workerName": workerName,
		"taskId":     logPayload.TaskId,
	}

	logJSON, err := json.Marshal(logData)
	if err != nil {
		logx.Errorf("[WorkerWS] Failed to marshal log: %v", err)
		return
	}

	// 写入全局Worker日志流
	globalStreamKey := "cscan:worker:logs"
	svcCtx.RedisClient.XAdd(ctx, &redis.XAddArgs{
		Stream: globalStreamKey,
		MaxLen: 10000,
		Approx: true,
		Values: map[string]interface{}{"data": string(logJSON)},
	})

	// 发布到实时频道
	svcCtx.RedisClient.Publish(ctx, "cscan:worker:logs:realtime", string(logJSON))

	// 如果有taskId，也写入任务专属日志流
	if logPayload.TaskId != "" {
		taskStreamKey := "cscan:task:logs:" + logPayload.TaskId
		svcCtx.RedisClient.XAdd(ctx, &redis.XAddArgs{
			Stream: taskStreamKey,
			MaxLen: 5000,
			Approx: true,
			Values: map[string]interface{}{"data": string(logJSON)},
		})

		// 发布到任务专属实时频道
		taskPubsubChannel := "cscan:task:logs:realtime:" + logPayload.TaskId
		svcCtx.RedisClient.Publish(ctx, taskPubsubChannel, string(logJSON))
	}
}


// ==================== Control Signal Subscription ====================

// subscribeControlSignals 订阅Redis控制信号
func subscribeControlSignals(ctx context.Context, wc *WorkerConnection, svcCtx *svc.ServiceContext) {
	// 使用模式订阅所有任务控制信号
	pubsub := svcCtx.RedisClient.PSubscribe(ctx, "cscan:task:ctrl:*")
	defer pubsub.Close()

	ch := pubsub.Channel()

	for {
		select {
		case <-ctx.Done():
			return
		case <-wc.closeChan:
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}
			// 解析频道名获取taskId
			// 频道格式: cscan:task:ctrl:{taskId}
			taskId := extractTaskIdFromChannel(msg.Channel)
			if taskId == "" {
				continue
			}

			// 转发控制信号给Worker
			action := msg.Payload // STOP, PAUSE, RESUME
			payload, _ := json.Marshal(&ControlPayload{
				TaskId: taskId,
				Action: action,
			})

			wc.Send(&WSMessage{
				Type:    WSTypeControl,
				Payload: payload,
			})

			logx.Infof("[WorkerWS] Forwarded control signal to %s: taskId=%s, action=%s",
				wc.workerName, taskId, action)
		}
	}
}

// extractTaskIdFromChannel 从频道名提取taskId
func extractTaskIdFromChannel(channel string) string {
	// 频道格式: cscan:task:ctrl:{taskId}
	const prefix = "cscan:task:ctrl:"
	if len(channel) > len(prefix) {
		return channel[len(prefix):]
	}
	return ""
}


// ==================== Terminal Output Handling ====================

// handleTerminalOutput 处理终端输出（从Worker发来的输出）
func handleTerminalOutput(ctx context.Context, wc *WorkerConnection, svcCtx *svc.ServiceContext, payload json.RawMessage) {
	var outputPayload TerminalOutputPayload
	if err := json.Unmarshal(payload, &outputPayload); err != nil {
		logx.Errorf("[WorkerWS] Invalid terminal output payload from %s: %v", wc.workerName, err)
		return
	}

	// 将终端输出发布到Redis频道，供前端WebSocket订阅
	outputJSON, _ := json.Marshal(map[string]interface{}{
		"workerName": wc.workerName,
		"sessionId":  outputPayload.SessionId,
		"data":       outputPayload.Data,
		"timestamp":  time.Now().UnixMilli(),
	})

	// 发布到终端输出频道
	channel := fmt.Sprintf("cscan:worker:terminal:%s:%s", wc.workerName, outputPayload.SessionId)
	svcCtx.RedisClient.Publish(ctx, channel, string(outputJSON))
}
