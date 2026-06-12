package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	defaultMaxOutputBytes = 2 * 1024 * 1024
	defaultTimeout        = 120 * time.Second
	maxFilterLength       = 4096
	maxExprLength         = 4096
	maxPathLength         = 1024
	rateLimitWindow       = time.Second
	maxRequestsPerWindow  = 30
)

func main() {
	log.SetOutput(os.Stderr)
	log.SetFlags(0)

	transport := flag.String("transport", "stdio", "MCP transport: stdio or http")
	listen := flag.String("listen", ":8002", "HTTP listen address when --transport=http")
	endpoint := flag.String("endpoint", "/mcp", "HTTP MCP endpoint path when --transport=http")
	token := flag.String("token", "", "Optional bearer token for HTTP authentication")
	flag.Parse()

	srv := newMCPServer()
	var err error
	switch *transport {
	case "stdio":
		err = srv.Run(context.Background(), &mcp.StdioTransport{})
	case "http", "streamable_http":
		err = runHTTPServer(srv, *listen, *endpoint, *token)
	default:
		err = fmt.Errorf("unsupported transport %q; expected stdio or http", *transport)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}

// rateLimiter is a sliding window rate limiter
type rateLimiter struct {
	mu          sync.Mutex
	window      time.Duration
	maxRequests int
	requests    []time.Time
}

func newRateLimiter(window time.Duration, maxRequests int) *rateLimiter {
	return &rateLimiter{
		window:      window,
		maxRequests: maxRequests,
		requests:    make([]time.Time, 0, maxRequests),
	}
}

func (rl *rateLimiter) allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)
	i := 0
	for ; i < len(rl.requests) && rl.requests[i].Before(cutoff); i++ {
	}
	rl.requests = rl.requests[i:]
	if len(rl.requests) < rl.maxRequests {
		rl.requests = append(rl.requests, now)
		return true
	}
	return false
}

var globalRateLimiter = newRateLimiter(rateLimitWindow, maxRequestsPerWindow)

func runHTTPServer(srv *mcp.Server, addr, endpoint, token string) error {
	if endpoint == "" {
		endpoint = "/mcp"
	}
	innerHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		return srv
	}, nil)

	mux := http.NewServeMux()
	// Health check does not require auth or rate limiting
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","service":"epan"}`))
	})

	// Wrapped MCP endpoint with auth and rate limiting
	mux.Handle(endpoint, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Bearer token authentication (if configured)
		if token != "" {
			authHeader := r.Header.Get("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				http.Error(w, `{"error": "unauthorized: missing or invalid Authorization header"}`, http.StatusUnauthorized)
				log.Printf("request rejected: missing auth token")
				return
			}
			providedToken := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
			if providedToken != token {
				http.Error(w, `{"error": "unauthorized: invalid token"}`, http.StatusUnauthorized)
				log.Printf("request rejected: invalid auth token")
				return
			}
		}

		// Rate limiting
		if !globalRateLimiter.allow() {
			http.Error(w, `{"error": "too many requests"}`, http.StatusTooManyRequests)
			log.Printf("request rejected: rate limit exceeded")
			return
		}

		innerHandler.ServeHTTP(w, r)
	}))

	log.Printf("epan MCP HTTP endpoint listening on %s%s", addr, endpoint)
	if token != "" {
		log.Printf("authentication enabled (bearer token required)")
	}
	return http.ListenAndServe(addr, mux)
}

func newMCPServer() *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{Name: "epan", Version: "1.0.0"}, nil)

	addTool(srv, &mcp.Tool{
		Name:        "get_version",
		Description: "Get runtime version information",
	}, handleVersion)

	addTool(srv, &mcp.Tool{
		Name:        "validate_filter",
		Description: "Validate a display filter expression (returns true/false)",
		InputSchema: toolInputSchema("validate_filter"),
	}, handleFilterValidate)

	addTool(srv, &mcp.Tool{
		Name:        "validate_filter_detailed",
		Description: "Validate a display filter with detailed field-level feedback",
		InputSchema: toolInputSchema("validate_filter_detailed"),
	}, handleFilterValidateDetailed)

	addTool(srv, &mcp.Tool{
		Name:        "suggest_filter",
		Description: "Suggest display filter field names by prefix (e.g. 'tcp.' or 'ip.')",
		InputSchema: toolInputSchema("suggest_filter"),
	}, handleFilterSuggest)

	addTool(srv, &mcp.Tool{
		Name:        "list_protocols",
		Description: "List all supported protocols",
	}, handleMetadataProtocols)

	addTool(srv, &mcp.Tool{
		Name:        "list_fields",
		Description: "List all display filter fields",
	}, handleMetadataFields)

	addTool(srv, &mcp.Tool{
		Name:        "get_field_info",
		Description: "Get metadata for a display filter field",
		InputSchema: toolInputSchema("get_field_info"),
	}, handleMetadataField)

	addTool(srv, &mcp.Tool{
		Name:        "count_frames",
		Description: "Count frames in a PCAP file",
		InputSchema: toolInputSchema("count_frames"),
	}, handleFramesCount)

	addTool(srv, &mcp.Tool{
		Name:        "list_frames",
		Description: "Get paginated frames from a PCAP file",
		InputSchema: toolInputSchema("list_frames"),
	}, handleFramesPage)

	addTool(srv, &mcp.Tool{
		Name:        "get_frame",
		Description: "Get a single frame by frame number",
		InputSchema: toolInputSchema("get_frame"),
	}, handleFramesGet)

	addTool(srv, &mcp.Tool{
		Name:        "get_frames_batch",
		Description: "Get frames by comma-separated frame numbers (e.g. '1,5,10')",
		InputSchema: toolInputSchema("get_frames_batch"),
	}, handleFramesBatch)

	addTool(srv, &mcp.Tool{
		Name:        "get_frame_hex",
		Description: "Get hex dump for a frame",
		InputSchema: toolInputSchema("get_frame_hex"),
	}, handleFramesHex)

	addTool(srv, &mcp.Tool{
		Name:        "get_frame_fields",
		Description: "Export display filter fields from frames as JSON",
		InputSchema: toolInputSchema("get_frame_fields"),
	}, handleFramesFields)

	addTool(srv, &mcp.Tool{
		Name:        "list_streams",
		Description: "List TCP/UDP streams with stream IDs",
		InputSchema: toolInputSchema("list_streams"),
	}, handleStreamsList)

	addTool(srv, &mcp.Tool{
		Name:        "list_conversations",
		Description: "List network conversations from a PCAP file",
		InputSchema: toolInputSchema("list_conversations"),
	}, handleConversationsList)

	addTool(srv, &mcp.Tool{
		Name:        "timeline_summary",
		Description: "Get traffic timeline from a PCAP file",
		InputSchema: toolInputSchema("timeline_summary"),
	}, handleTimelineSummary)

	addTool(srv, &mcp.Tool{
		Name:        "list_files",
		Description: "List files detected in network traffic",
		InputSchema: toolInputSchema("list_files"),
	}, handleFilesList)

	addTool(srv, &mcp.Tool{
		Name:        "list_expert_findings",
		Description: "Get expert analysis findings (anomalies, warnings, violations)",
		InputSchema: toolInputSchema("list_expert_findings"),
	}, handleExpertList)

	addTool(srv, &mcp.Tool{
		Name:        "follow_stream",
		Description: "Follow and reconstruct a TCP/UDP stream",
		InputSchema: toolInputSchema("follow_stream"),
	}, handleFollowStream)

	addTool(srv, &mcp.Tool{
		Name:        "create_pcap_slice",
		Description: "Slice a PCAP file. Output goes to OUTPUT_DIR.",
		InputSchema: toolInputSchema("create_pcap_slice"),
	}, handleSlicePcap)

	addTool(srv, &mcp.Tool{
		Name:        "create_evidence_bundle",
		Description: "Build a forensic evidence bundle (conversations, expert infos, protocol hierarchy)",
		InputSchema: toolInputSchema("create_evidence_bundle"),
	}, handleEvidenceBundle)

	addTool(srv, &mcp.Tool{
		Name:        "verify_zeek_alert",
		Description: "Verify a Zeek alert against packet evidence",
		InputSchema: toolInputSchema("verify_zeek_alert"),
	}, handleVerifyZeekAlert)

	addTool(srv, &mcp.Tool{
		Name:        "tap_conversations",
		Description: "Get conversation stats. Type: eth|ip|tcp|udp.",
		InputSchema: toolInputSchema("tap_conversations"),
	}, handleTapConversations)

	addTool(srv, &mcp.Tool{
		Name:        "tap_endpoints",
		Description: "Get endpoint stats. Type: eth|ip|tcp|udp.",
		InputSchema: toolInputSchema("tap_endpoints"),
	}, handleTapEndpoints)

	addTool(srv, &mcp.Tool{
		Name:        "service_response_times",
		Description: "Get service response times for a protocol",
		InputSchema: toolInputSchema("service_response_times"),
	}, handleSRTList)

	addTool(srv, &mcp.Tool{
		Name:        "exportable_objects",
		Description: "List exportable objects for a protocol",
		InputSchema: toolInputSchema("exportable_objects"),
	}, handleExportObjectList)

	addTool(srv, &mcp.Tool{
		Name:        "write_exportable_object",
		Description: "Write an export object to a file",
		InputSchema: toolInputSchema("write_exportable_object"),
	}, handleExportObjectWrite)

	addTool(srv, &mcp.Tool{
		Name:        "stats_summary",
		Description: "Get statistical summary of a PCAP file",
		InputSchema: toolInputSchema("stats_summary"),
	}, handleStatsSummary)

	addTool(srv, &mcp.Tool{
		Name:        "extract_files",
		Description: "Extract files from network traffic to a directory",
		InputSchema: toolInputSchema("extract_files"),
	}, handleExtractFiles)

	addTool(srv, &mcp.Tool{
		Name:        "health_check",
		Description: "Check runtime environment health",
	}, handleDoctor)

	registerResources(srv)
	registerPrompts(srv)

	return srv
}

func addTool[In any](srv *mcp.Server, tool *mcp.Tool, handler mcp.ToolHandlerFor[In, map[string]any]) {
	mcp.AddTool[In, any](srv, tool, tracedTool(tool.Name, handler))
}

// successResult wraps buildResult and discards the structured output so the SDK
// does not set StructuredContent on the wire. Clients that cannot handle
// structuredContent without an advertised outputSchema (e.g. Trae) will see
// only the text content. Error envelopes still set StructuredContent explicitly.
func successResult(out *epanOutput) (*mcp.CallToolResult, map[string]any, error) {
	return buildResult(out.Text, out), nil, nil
}

func tracedTool[In any](toolName string, handler mcp.ToolHandlerFor[In, map[string]any]) mcp.ToolHandlerFor[In, any] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in In) (result *mcp.CallToolResult, structured any, err error) {
		start := time.Now()
		traceID := newTraceID()
		status := "success"
		errorCode := ""
		defer func() {
			if r := recover(); r != nil {
				err = nil
				status = "exception"
				errorCode = "INTERNAL_EXCEPTION"
				envelope := errorEnvelope(toolName, traceID, errorCode, fmt.Sprintf("panic: %v", r), false)
				result = errorEnvelopeResult(envelope, traceID)
				// Do not return envelope as structured output; errorEnvelopeResult
				// already sets result.StructuredContent. Returning nil prevents
				// the SDK from re-marshaling or triggering schema validation.
				structured = nil
			}
			if result != nil {
				if result.Meta == nil {
					result.Meta = mcp.Meta{}
				}
				result.Meta["trace_id"] = traceID
			}
			writeToolCallLog(toolName, traceID, in, status, errorCode, result, time.Since(start))
			auditLog(toolName, time.Since(start), status == "semantic_failure" || status == "exception")
		}()

		result, structured, err = handler(ctx, req, in)
		if err != nil {
			status = "semantic_failure"
			errorCode = errorCodeFor(err)
			envelope := errorEnvelope(toolName, traceID, errorCode, err.Error(), retryableError(err))
			result = errorEnvelopeResult(envelope, traceID)
			// Do not pass envelope as structured output; errorEnvelopeResult
			// already sets result.StructuredContent directly. Returning nil
			// prevents the SDK from overwriting it or triggering schema validation.
			err = nil
			return result, nil, nil
		}
		// Guard against typed nil: a nil map[string]any assigned to any is
		// non-nil in Go, which would cause the SDK to marshal "null" into
		// StructuredContent. Explicitly clear it.
		if result != nil && result.IsError {
			status = "semantic_failure"
			errorCode = "TOOL_ERROR"
		}
		return result, nil, nil
	}
}

func toolInputSchema(name string) map[string]any {
	file := map[string]any{"type": "string", "minLength": 1, "description": "PCAP path. Relative paths resolve under PCAP_DIR when set."}
	filter := map[string]any{"type": "string", "description": "Wireshark display filter expression."}
	out := map[string]any{"type": "string", "minLength": 1, "description": "Output path. Relative paths resolve under OUTPUT_DIR."}

	switch name {
	case "validate_filter":
		return objectSchema([]string{"expr"}, map[string]any{
			"expr": map[string]any{"type": "string", "minLength": 1, "description": "Wireshark display filter expression to validate."},
		})
	case "validate_filter_detailed":
		return objectSchema([]string{"expr"}, map[string]any{
			"expr": map[string]any{"type": "string", "minLength": 1, "description": "Wireshark display filter expression to validate with detailed feedback."},
		})
	case "suggest_filter":
		return objectSchema([]string{"prefix"}, map[string]any{
			"prefix": map[string]any{"type": "string", "minLength": 1, "description": "Field name prefix to search, e.g. 'tcp.', 'ip.'."},
			"limit":  map[string]any{"type": "integer", "minimum": 1, "maximum": 500, "default": 50},
		})
	case "get_field_info":
		return objectSchema([]string{"name"}, map[string]any{
			"name": map[string]any{"type": "string", "minLength": 1, "description": "Wireshark display filter field name, e.g. 'tcp.stream'."},
		})
	case "count_frames":
		return objectSchema([]string{"file"}, map[string]any{
			"file":   file,
			"filter": filter,
		})
	case "list_frames":
		return objectSchema([]string{"file"}, map[string]any{
			"file":   file,
			"filter": filter,
			"page":   map[string]any{"type": "integer", "minimum": 1, "default": 1},
			"size":   map[string]any{"type": "integer", "minimum": 1, "default": 20},
		})
	case "get_frame":
		return objectSchema([]string{"file", "index"}, map[string]any{
			"file":  file,
			"index": map[string]any{"type": "integer", "minimum": 1},
		})
	case "follow_stream":
		return objectSchema([]string{"file"}, map[string]any{
			"file":     file,
			"protocol": map[string]any{"type": "string", "enum": []string{"tcp", "udp"}, "default": "tcp"},
			"filter":   filter,
		})
	case "create_pcap_slice":
		return objectSchema([]string{"file", "out"}, map[string]any{
			"file":    file,
			"out":     out,
			"filter":  filter,
			"indices": map[string]any{"type": "string", "description": "Comma-separated frame numbers."},
		})
	case "tap_conversations":
		return objectSchema([]string{"file"}, map[string]any{
			"file":   file,
			"type":   map[string]any{"type": "string", "enum": []string{"eth", "ip", "tcp", "udp"}, "default": "tcp"},
			"filter": filter,
		})
	case "tap_endpoints":
		return objectSchema([]string{"file"}, map[string]any{
			"file":   file,
			"type":   map[string]any{"type": "string", "enum": []string{"eth", "ip", "tcp", "udp"}, "default": "ip"},
			"filter": filter,
		})
	case "write_exportable_object":
		return objectSchema([]string{"file", "protocol", "packetNum", "out"}, map[string]any{
			"file":      file,
			"protocol":  map[string]any{"type": "string", "minLength": 1},
			"packetNum": map[string]any{"type": "integer", "minimum": 1},
			"out":       out,
			"filter":    filter,
		})
	case "get_frame_fields":
		return objectSchema([]string{"file", "fields"}, map[string]any{
			"file":   file,
			"fields": map[string]any{"type": "string", "minLength": 1, "description": "Comma-separated Wireshark field names, e.g. 'ip.src,ip.dst,tcp.port'."},
			"filter": filter,
		})
	case "stats_summary":
		return objectSchema([]string{"file"}, map[string]any{
			"file":   file,
			"filter": filter,
		})
	case "extract_files":
		return objectSchema([]string{"file", "out"}, map[string]any{
			"file": file,
			"out":  out,
		})
	case "verify_zeek_alert":
		return objectSchema([]string{"file"}, map[string]any{
			"file":     file,
			"filter":   filter,
			"alert":    map[string]any{"type": "object", "description": "Zeek alert object, for example id.orig_h/id.resp_h/proto/id.orig_p/id.resp_p."},
			"src_ip":   map[string]any{"type": "string", "description": "Optional source IP when alert is not supplied."},
			"dst_ip":   map[string]any{"type": "string", "description": "Optional destination IP when alert is not supplied."},
			"src_port": map[string]any{"type": "integer", "minimum": 1, "maximum": 65535},
			"dst_port": map[string]any{"type": "integer", "minimum": 1, "maximum": 65535},
			"protocol": map[string]any{"type": "string", "enum": []string{"tcp", "udp"}},
		})
	case "get_frames_batch":
		return objectSchema([]string{"file", "indices"}, map[string]any{
			"file":    file,
			"indices": map[string]any{"type": "string", "minLength": 1, "description": "Comma-separated frame numbers, e.g. '1,5,10'."},
			"filter":  filter,
		})
	case "get_frame_hex":
		return objectSchema([]string{"file", "index"}, map[string]any{
			"file":  file,
			"index": map[string]any{"type": "integer", "minimum": 1},
		})
	case "list_streams":
		return objectSchema([]string{"file"}, map[string]any{
			"file":   file,
			"filter": filter,
		})
	case "list_conversations":
		return objectSchema([]string{"file"}, map[string]any{
			"file":   file,
			"filter": filter,
		})
	case "timeline_summary":
		return objectSchema([]string{"file"}, map[string]any{
			"file":   file,
			"filter": filter,
		})
	case "list_files":
		return objectSchema([]string{"file"}, map[string]any{
			"file":   file,
			"filter": filter,
		})
	case "list_expert_findings":
		return objectSchema([]string{"file"}, map[string]any{
			"file":   file,
			"filter": filter,
		})
	case "create_evidence_bundle":
		return objectSchema([]string{"file"}, map[string]any{
			"file":   file,
			"filter": filter,
		})
	case "exportable_objects":
		return objectSchema([]string{"file", "protocol"}, map[string]any{
			"file":     file,
			"protocol": map[string]any{"type": "string", "minLength": 1, "description": "Protocol name, e.g. 'http'."},
			"filter":   filter,
		})
	case "service_response_times":
		return objectSchema([]string{"file", "protocol"}, map[string]any{
			"file":     file,
			"protocol": map[string]any{"type": "string", "minLength": 1, "description": "Protocol name, e.g. 'smb', 'dns', 'http'."},
			"filter":   filter,
		})
	default:
		return objectSchema(nil, map[string]any{})
	}
}

func objectSchema(required []string, properties map[string]any) map[string]any {
	schema := map[string]any{
		"type":                 "object",
		"properties":           properties,
		"additionalProperties": false,
	}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

// --- Audit logging ---

func auditLog(tool string, duration time.Duration, failed bool) {
	status := "ok"
	if failed {
		status = "error"
	}
	log.Printf("audit tool=%s duration=%v status=%s", tool, duration.Round(time.Millisecond), status)
}

// --- Input validation helpers ---

func validateStringMax(s, label string, maxLen int) error {
	if len(s) > maxLen {
		return fmt.Errorf("%s too long (%d bytes, max %d)", label, len(s), maxLen)
	}
	return nil
}

// --- Environment helpers ---

func epanBin() string {
	if v := os.Getenv("EPAN_BIN"); v != "" {
		return v
	}
	return "epan"
}

func pcapDir() string {
	return os.Getenv("EPAN_PCAP_DIR")
}

func outputDir() string {
	if v := os.Getenv("EPAN_OUTPUT_DIR"); v != "" {
		return v
	}
	return os.TempDir()
}

func timeout() time.Duration {
	if v := os.Getenv("EPAN_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return 120 * time.Second
}

func maxOutputBytes() int64 {
	if v := os.Getenv("EPAN_MAX_OUTPUT_BYTES"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			return n
		}
	}
	return defaultMaxOutputBytes
}

// --- Path validation ---

func resolvePCAPPath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("file path is required")
	}
	dir := pcapDir()
	if dir == "" {
		absPath, err := filepath.Abs(filepath.Clean(path))
		if err != nil {
			return "", fmt.Errorf("cannot resolve path: %w", err)
		}
		return absPath, nil
	}

	resolved := filepath.Clean(path)
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(dir, resolved)
	}
	absPath, err := filepath.Abs(resolved)
	if err != nil {
		return "", fmt.Errorf("cannot resolve path: %w", err)
	}
	if err := ensureWithinDir(absPath, dir, "pcap"); err != nil {
		return "", err
	}
	return absPath, nil
}

func validatePCAPPath(path string) error {
	_, err := resolvePCAPPath(path)
	return err
}

func resolveOutputPath(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	dir := outputDir()
	resolved := filepath.Clean(path)
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(dir, resolved)
	}
	absPath, err := filepath.Abs(resolved)
	if err != nil {
		return "", fmt.Errorf("cannot resolve path: %w", err)
	}
	if err := ensureWithinDir(absPath, dir, "output"); err != nil {
		return "", err
	}
	return absPath, nil
}

func validateOutputPath(path string) error {
	_, err := resolveOutputPath(path)
	return err
}

func ensureWithinDir(path, dir, label string) error {
	if path == "" {
		return nil
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("cannot resolve %s dir: %w", label, err)
	}
	absDir = filepath.Clean(absDir)
	absPath := filepath.Clean(path)
	if err := ensureLexicallyWithinDir(absPath, absDir); err != nil {
		return fmt.Errorf("%s path %q is outside allowed directory %q", label, path, dir)
	}

	realDir, dirErr := filepath.EvalSymlinks(absDir)
	if dirErr != nil {
		return nil
	}
	if realPath, pathErr := filepath.EvalSymlinks(absPath); pathErr == nil {
		if err := ensureLexicallyWithinDir(filepath.Clean(realPath), filepath.Clean(realDir)); err != nil {
			return fmt.Errorf("%s path %q resolves outside allowed directory %q", label, path, dir)
		}
	} else if realPath, pathErr := evalSymlinkAwarePath(absPath); pathErr == nil {
		if err := ensureLexicallyWithinDir(filepath.Clean(realPath), filepath.Clean(realDir)); err != nil {
			return fmt.Errorf("%s path %q resolves outside allowed directory %q", label, path, dir)
		}
	}
	return nil
}

func evalSymlinkAwarePath(path string) (string, error) {
	current := filepath.Clean(path)
	missing := []string{}
	for {
		real, err := filepath.EvalSymlinks(current)
		if err == nil {
			for i := len(missing) - 1; i >= 0; i-- {
				real = filepath.Join(real, missing[i])
			}
			return filepath.Clean(real), nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", err
		}
		missing = append(missing, filepath.Base(current))
		current = parent
	}
}

func ensureLexicallyWithinDir(path, dir string) error {
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("outside directory")
	}
	return nil
}

func validateProtocol(protocol string, allowed ...string) error {
	for _, a := range allowed {
		if protocol == a {
			return nil
		}
	}
	return fmt.Errorf("invalid protocol %q, must be one of: %s", protocol, strings.Join(allowed, ", "))
}

func validateTapType(tapType string, allowed ...string) error {
	for _, a := range allowed {
		if tapType == a {
			return nil
		}
	}
	return fmt.Errorf("invalid tap type %q, must be one of: %s", tapType, strings.Join(allowed, ", "))
}

// --- Output truncation ---

type epanOutput struct {
	Text              string
	Raw               []byte
	Truncated         bool
	MaxOutputBytes    int64
	OriginalBytes     int64
	SuggestedNextTool string
}

type limitedBuffer struct {
	buf   []byte
	limit int64
	total int64
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	b.total += int64(len(p))
	if int64(len(b.buf)) < b.limit {
		remaining := int(b.limit - int64(len(b.buf)))
		if remaining > len(p) {
			remaining = len(p)
		}
		b.buf = append(b.buf, p[:remaining]...)
	}
	return len(p), nil
}

func runEpan(ctx context.Context, args ...string) (*epanOutput, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, timeout())
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, epanBin(), args...)
	// subprocess isolation: create new process group so cleanup on timeout kills the whole tree
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout := &limitedBuffer{limit: maxOutputBytes()}
	stderr := &limitedBuffer{limit: 64 * 1024}
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	err := cmd.Run()
	if err != nil {
		if stderr.total > 0 {
			return nil, fmt.Errorf("command failed: %s", string(stderr.buf))
		}
		return nil, fmt.Errorf("command failed: %w", err)
	}

	out := &epanOutput{
		Raw:            stdout.buf,
		MaxOutputBytes: stdout.limit,
		OriginalBytes:  stdout.total,
		Truncated:      stdout.total > stdout.limit,
	}

	var rawJSON json.RawMessage
	if err := json.Unmarshal(out.Raw, &rawJSON); err != nil {
		out.Text = string(out.Raw)
	} else {
		pretty, _ := json.MarshalIndent(rawJSON, "", "  ")
		out.Text = string(pretty)
	}

	if out.Truncated {
		out.Text = fmt.Sprintf("%s\n\n[output truncated: %d/%d bytes, max=%d]",
			out.Text, out.MaxOutputBytes, out.OriginalBytes, out.MaxOutputBytes)
	}

	return out, nil
}

func (o *epanOutput) suggestTool(tool string) {
	o.SuggestedNextTool = tool
}

// --- Result builders ---

func buildResult(text string, out *epanOutput) *mcp.CallToolResult {
	result := &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}
	if out != nil && (out.Truncated || out.SuggestedNextTool != "") {
		meta := mcp.Meta{}
		if out.Truncated {
			meta["truncated"] = true
			meta["maxOutputBytes"] = out.MaxOutputBytes
			meta["originalBytes"] = out.OriginalBytes
		}
		if out.SuggestedNextTool != "" {
			meta["suggestedNextTool"] = out.SuggestedNextTool
		}
		result.Meta = meta
	}
	return result
}

func newTraceID() string {
	if v := os.Getenv("MCP_TRACE_ID"); v != "" {
		return v
	}
	return fmt.Sprintf("ep-%d-%d", time.Now().UnixNano(), os.Getpid())
}

func errorEnvelope(toolName, traceID, code, message string, retryable bool) map[string]any {
	envelope := map[string]any{
		"ok":            false,
		"status":        "semantic_failure",
		"tool":          toolName,
		"error_code":    code,
		"error_message": message,
		"suggestion":    suggestionForError(code, message),
		"retryable":     retryable,
		"retry_with":    map[string]any{},
		"trace_id":      traceID,
	}
	if next := nextToolForError(code, message); next != "" {
		envelope["next_tool"] = next
	}
	return envelope
}

func errorEnvelopeResult(envelope map[string]any, traceID string) *mcp.CallToolResult {
	text, _ := json.MarshalIndent(envelope, "", "  ")
	return &mcp.CallToolResult{
		Meta:              mcp.Meta{"trace_id": traceID},
		Content:           []mcp.Content{&mcp.TextContent{Text: string(text)}},
		StructuredContent: envelope,
		IsError:           true,
	}
}

func errorCodeFor(err error) string {
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "outside allowed directory"), strings.Contains(msg, "cannot resolve path"):
		return "INVALID_PATH"
	case strings.Contains(msg, "required"):
		return "MISSING_REQUIRED_PARAM"
	case strings.Contains(msg, "invalid protocol"), strings.Contains(msg, "invalid tap type"), strings.Contains(msg, "must be"):
		return "INVALID_ARGUMENT"
	case strings.Contains(msg, "context deadline exceeded"), strings.Contains(msg, "timed out"):
		return "TIMEOUT"
	case strings.Contains(msg, "command failed"):
		return "CLI_ERROR"
	default:
		return "TOOL_ERROR"
	}
}

func retryableError(err error) bool {
	code := errorCodeFor(err)
	return code == "TIMEOUT"
}

func suggestionForError(code, message string) string {
	switch code {
	case "INVALID_PATH":
		return "Use the epan://pcaps resource to get an allowed path, or pass a relative PCAP name under PCAP_DIR."
	case "MISSING_REQUIRED_PARAM":
		return "Check the tool input schema and provide the required parameter before retrying."
	case "INVALID_ARGUMENT":
		return "Use schema enum values and numeric minimums exactly as advertised by list tools."
	case "TIMEOUT":
		return "Retry with a narrower display filter or increase TIMEOUT for large captures."
	case "CLI_ERROR":
		if strings.Contains(strings.ToLower(message), "filter") {
			return "Call validate_filter or suggest_filter before reusing this display filter."
		}
		return "Call health_check to verify the runtime, then retry with a narrower query."
	default:
		return "Inspect error_message and retry with corrected parameters."
	}
}

func nextToolForError(code, message string) string {
	switch code {
	case "INVALID_PATH":
		return "health_check"
	case "CLI_ERROR":
		if strings.Contains(strings.ToLower(message), "filter") {
			return "validate_filter"
		}
		return "health_check"
	default:
		return ""
	}
}

func writeToolCallLog(toolName, traceID string, input any, status, errorCode string, result *mcp.CallToolResult, duration time.Duration) {
	path := os.Getenv("MCP_CALL_LOG_PATH")
	if path == "" {
		return
	}
	record := map[string]any{
		"timestamp":        time.Now().UTC().Format(time.RFC3339Nano),
		"trace_id":         traceID,
		"tool_name":        toolName,
		"normalized_input": input,
		"status":           status,
		"error_code":       errorCode,
		"duration_ms":      duration.Milliseconds(),
		"output_bytes":     resultTextBytes(result),
		"artifact_paths":   []string{},
	}
	data, err := json.Marshal(record)
	if err != nil {
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(data, '\n'))
}

func resultTextBytes(result *mcp.CallToolResult) int {
	if result == nil {
		return 0
	}
	total := 0
	for _, content := range result.Content {
		if text, ok := content.(*mcp.TextContent); ok {
			total += len(text.Text)
		}
	}
	return total
}

func textResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}
}

func fileFilterCLI(args []string, file string, filter *string) []string {
	out := append(args, "--file", file)
	if filter != nil && *filter != "" {
		out = append(out, "--filter", *filter)
	}
	return out
}

func parseOutput(out *epanOutput) map[string]any {
	if out == nil || out.Truncated {
		return nil
	}
	var parsed map[string]any
	if err := json.Unmarshal(out.Raw, &parsed); err != nil {
		return nil
	}
	return parsed
}

// --- Input types ---

type emptyIn struct{}

type filterValidateIn struct {
	Expr string `json:"expr"`
}

type filterValidateDetailedIn struct {
	Expr string `json:"expr"`
}

type filterSuggestIn struct {
	Prefix string `json:"prefix"`
	Limit  int    `json:"limit,omitempty"`
}

type metadataFieldIn struct {
	Name string `json:"name"`
}

type framesCountIn struct {
	File   string  `json:"file"`
	Filter *string `json:"filter,omitempty"`
}

type framesPageIn struct {
	File   string  `json:"file"`
	Filter *string `json:"filter,omitempty"`
	Page   int     `json:"page,omitempty"`
	Size   int     `json:"size,omitempty"`
}

type framesGetIn struct {
	File  string `json:"file"`
	Index int    `json:"index"`
}

type framesBatchIn struct {
	File    string  `json:"file"`
	Indices string  `json:"indices"`
	Filter  *string `json:"filter,omitempty"`
}

type framesHexIn struct {
	File  string `json:"file"`
	Index int    `json:"index"`
}

type framesFieldsIn struct {
	File   string  `json:"file"`
	Fields string  `json:"fields"`
	Filter *string `json:"filter,omitempty"`
}

type streamsListIn struct {
	File   string  `json:"file"`
	Filter *string `json:"filter,omitempty"`
}

type conversationsListIn struct {
	File   string  `json:"file"`
	Filter *string `json:"filter,omitempty"`
}

type timelineSummaryIn struct {
	File   string  `json:"file"`
	Filter *string `json:"filter,omitempty"`
}

type filesListIn struct {
	File   string  `json:"file"`
	Filter *string `json:"filter,omitempty"`
}

type expertListIn struct {
	File   string  `json:"file"`
	Filter *string `json:"filter,omitempty"`
}

type followStreamIn struct {
	File     string  `json:"file"`
	Protocol *string `json:"protocol,omitempty"`
	Filter   *string `json:"filter,omitempty"`
}

type slicePcapIn struct {
	File    string  `json:"file"`
	Out     string  `json:"out"`
	Filter  *string `json:"filter,omitempty"`
	Indices *string `json:"indices,omitempty"`
}

type evidenceBundleIn struct {
	File   string  `json:"file"`
	Filter *string `json:"filter,omitempty"`
}

type verifyZeekAlertIn struct {
	File    string         `json:"file"`
	Filter  *string        `json:"filter,omitempty"`
	Alert   map[string]any `json:"alert,omitempty"`
	SrcIP   *string        `json:"src_ip,omitempty"`
	DstIP   *string        `json:"dst_ip,omitempty"`
	SrcPort *int           `json:"src_port,omitempty"`
	DstPort *int           `json:"dst_port,omitempty"`
	Proto   *string        `json:"protocol,omitempty"`
}

type tapConversationsIn struct {
	File   string  `json:"file"`
	Type   *string `json:"type,omitempty"`
	Filter *string `json:"filter,omitempty"`
}

type tapEndpointsIn struct {
	File   string  `json:"file"`
	Type   *string `json:"type,omitempty"`
	Filter *string `json:"filter,omitempty"`
}

type srtListIn struct {
	File     string  `json:"file"`
	Protocol string  `json:"protocol"`
	Filter   *string `json:"filter,omitempty"`
}

type exportObjectListIn struct {
	File     string  `json:"file"`
	Protocol string  `json:"protocol"`
	Filter   *string `json:"filter,omitempty"`
}

type exportObjectWriteIn struct {
	File      string  `json:"file"`
	Protocol  string  `json:"protocol"`
	PacketNum int     `json:"packetNum"`
	Out       string  `json:"out"`
	Filter    *string `json:"filter,omitempty"`
}

type statsSummaryIn struct {
	File   string  `json:"file"`
	Filter *string `json:"filter,omitempty"`
}

type extractFilesIn struct {
	File string `json:"file"`
	Out  string `json:"out"`
}

type doctorIn struct{}

// --- Handlers ---

func handleVersion(ctx context.Context, _ *mcp.CallToolRequest, _ emptyIn) (*mcp.CallToolResult, map[string]any, error) {
	out, err := runEpan(ctx, "version")
	if err != nil {
		return nil, nil, err
	}
	return successResult(out)
}

func handleFilterValidate(ctx context.Context, _ *mcp.CallToolRequest, in filterValidateIn) (*mcp.CallToolResult, map[string]any, error) {
	if in.Expr == "" {
		return nil, nil, fmt.Errorf("expr is required")
	}
	if err := validateStringMax(in.Expr, "expr", maxExprLength); err != nil {
		return nil, nil, err
	}
	out, err := runEpan(ctx, "filter", "validate", "--expr", in.Expr)
	if err != nil {
		return nil, nil, err
	}
	return successResult(out)
}

func handleFilterValidateDetailed(ctx context.Context, _ *mcp.CallToolRequest, in filterValidateDetailedIn) (*mcp.CallToolResult, map[string]any, error) {
	if in.Expr == "" {
		return nil, nil, fmt.Errorf("expr is required")
	}
	if err := validateStringMax(in.Expr, "expr", maxExprLength); err != nil {
		return nil, nil, err
	}
	out, err := runEpan(ctx, "filter", "validate-detailed", "--expr", in.Expr)
	if err != nil {
		return nil, nil, err
	}
	return successResult(out)
}

func handleFilterSuggest(ctx context.Context, _ *mcp.CallToolRequest, in filterSuggestIn) (*mcp.CallToolResult, map[string]any, error) {
	if in.Prefix == "" {
		return nil, nil, fmt.Errorf("prefix is required")
	}
	if err := validateStringMax(in.Prefix, "prefix", 128); err != nil {
		return nil, nil, err
	}
	limit := 50
	if in.Limit > 0 {
		limit = in.Limit
	}
	out, err := runEpan(ctx, "filter", "suggest", "--prefix", in.Prefix, "--limit", strconv.Itoa(limit))
	if err != nil {
		return nil, nil, err
	}
	return successResult(out)
}

func handleMetadataProtocols(ctx context.Context, _ *mcp.CallToolRequest, _ emptyIn) (*mcp.CallToolResult, map[string]any, error) {
	out, err := runEpan(ctx, "metadata", "protocols")
	if err != nil {
		return nil, nil, err
	}
	return successResult(out)
}

func handleMetadataFields(ctx context.Context, _ *mcp.CallToolRequest, _ emptyIn) (*mcp.CallToolResult, map[string]any, error) {
	out, err := runEpan(ctx, "metadata", "fields")
	if err != nil {
		return nil, nil, err
	}
	out.suggestTool("suggest_filter")
	return successResult(out)
}

func handleMetadataField(ctx context.Context, _ *mcp.CallToolRequest, in metadataFieldIn) (*mcp.CallToolResult, map[string]any, error) {
	if in.Name == "" {
		return nil, nil, fmt.Errorf("name is required")
	}
	if err := validateStringMax(in.Name, "name", 128); err != nil {
		return nil, nil, err
	}
	out, err := runEpan(ctx, "metadata", "field", "--name", in.Name)
	if err != nil {
		return nil, nil, err
	}
	return successResult(out)
}

func handleFramesCount(ctx context.Context, _ *mcp.CallToolRequest, in framesCountIn) (*mcp.CallToolResult, map[string]any, error) {
	if err := validateStringMax(in.File, "file", maxPathLength); err != nil {
		return nil, nil, err
	}
	if in.Filter != nil && *in.Filter != "" {
		if err := validateStringMax(*in.Filter, "filter", maxFilterLength); err != nil {
			return nil, nil, err
		}
	}
	file, err := resolvePCAPPath(in.File)
	if err != nil {
		return nil, nil, err
	}
	out, err := runEpan(ctx, fileFilterCLI([]string{"frames", "count"}, file, in.Filter)...)
	if err != nil {
		return nil, nil, err
	}
	out.suggestTool("list_streams")
	return successResult(out)
}

func handleFramesPage(ctx context.Context, _ *mcp.CallToolRequest, in framesPageIn) (*mcp.CallToolResult, map[string]any, error) {
	file, err := resolvePCAPPath(in.File)
	if err != nil {
		return nil, nil, err
	}
	page := in.Page
	if page < 1 {
		page = 1
	}
	size := in.Size
	if size < 1 {
		size = 20
	}
	args := []string{"frames", "page", "--file", file, "--page", strconv.Itoa(page), "--size", strconv.Itoa(size)}
	if in.Filter != nil && *in.Filter != "" {
		args = append(args, "--filter", *in.Filter)
	}
	out, err := runEpan(ctx, args...)
	if err != nil {
		return nil, nil, err
	}
	return successResult(out)
}

func handleFramesGet(ctx context.Context, _ *mcp.CallToolRequest, in framesGetIn) (*mcp.CallToolResult, map[string]any, error) {
	file, err := resolvePCAPPath(in.File)
	if err != nil {
		return nil, nil, err
	}
	if in.Index < 1 {
		return nil, nil, fmt.Errorf("index must be >= 1, got %d", in.Index)
	}
	out, err := runEpan(ctx, "frames", "get", "--file", file, "--index", strconv.Itoa(in.Index))
	if err != nil {
		return nil, nil, err
	}
	return successResult(out)
}

func handleFramesBatch(ctx context.Context, _ *mcp.CallToolRequest, in framesBatchIn) (*mcp.CallToolResult, map[string]any, error) {
	file, err := resolvePCAPPath(in.File)
	if err != nil {
		return nil, nil, err
	}
	if in.Indices == "" {
		return nil, nil, fmt.Errorf("indices is required (comma-separated frame numbers)")
	}
	args := []string{"frames", "batch", "--file", file, "--indices", in.Indices}
	if in.Filter != nil && *in.Filter != "" {
		args = append(args, "--filter", *in.Filter)
	}
	out, err := runEpan(ctx, args...)
	if err != nil {
		return nil, nil, err
	}
	return successResult(out)
}

func handleFramesHex(ctx context.Context, _ *mcp.CallToolRequest, in framesHexIn) (*mcp.CallToolResult, map[string]any, error) {
	file, err := resolvePCAPPath(in.File)
	if err != nil {
		return nil, nil, err
	}
	if in.Index < 1 {
		return nil, nil, fmt.Errorf("index must be >= 1, got %d", in.Index)
	}
	out, err := runEpan(ctx, "frames", "hex", "--file", file, "--index", strconv.Itoa(in.Index))
	if err != nil {
		return nil, nil, err
	}
	return successResult(out)
}

func handleFramesFields(ctx context.Context, _ *mcp.CallToolRequest, in framesFieldsIn) (*mcp.CallToolResult, map[string]any, error) {
	file, err := resolvePCAPPath(in.File)
	if err != nil {
		return nil, nil, err
	}
	if in.Fields == "" {
		return nil, nil, fmt.Errorf("fields is required (comma-separated Wireshark field names)")
	}
	args := []string{"frames", "fields", "--file", file, "--fields", in.Fields}
	if in.Filter != nil && *in.Filter != "" {
		args = append(args, "--filter", *in.Filter)
	}
	out, err := runEpan(ctx, args...)
	if err != nil {
		return nil, nil, err
	}
	return successResult(out)
}

func handleStreamsList(ctx context.Context, _ *mcp.CallToolRequest, in streamsListIn) (*mcp.CallToolResult, map[string]any, error) {
	file, err := resolvePCAPPath(in.File)
	if err != nil {
		return nil, nil, err
	}
	out, err := runEpan(ctx, fileFilterCLI([]string{"streams", "list"}, file, in.Filter)...)
	if err != nil {
		return nil, nil, err
	}
	return successResult(out)
}

func handleConversationsList(ctx context.Context, _ *mcp.CallToolRequest, in conversationsListIn) (*mcp.CallToolResult, map[string]any, error) {
	file, err := resolvePCAPPath(in.File)
	if err != nil {
		return nil, nil, err
	}
	out, err := runEpan(ctx, fileFilterCLI([]string{"traffic", "conversations", "list"}, file, in.Filter)...)
	if err != nil {
		return nil, nil, err
	}
	return successResult(out)
}

func handleTimelineSummary(ctx context.Context, _ *mcp.CallToolRequest, in timelineSummaryIn) (*mcp.CallToolResult, map[string]any, error) {
	file, err := resolvePCAPPath(in.File)
	if err != nil {
		return nil, nil, err
	}
	out, err := runEpan(ctx, fileFilterCLI([]string{"traffic", "timeline", "summary"}, file, in.Filter)...)
	if err != nil {
		return nil, nil, err
	}
	return successResult(out)
}

func handleFilesList(ctx context.Context, _ *mcp.CallToolRequest, in filesListIn) (*mcp.CallToolResult, map[string]any, error) {
	file, err := resolvePCAPPath(in.File)
	if err != nil {
		return nil, nil, err
	}
	out, err := runEpan(ctx, fileFilterCLI([]string{"traffic", "files", "list"}, file, in.Filter)...)
	if err != nil {
		return nil, nil, err
	}
	return successResult(out)
}

func handleExpertList(ctx context.Context, _ *mcp.CallToolRequest, in expertListIn) (*mcp.CallToolResult, map[string]any, error) {
	file, err := resolvePCAPPath(in.File)
	if err != nil {
		return nil, nil, err
	}
	out, err := runEpan(ctx, fileFilterCLI([]string{"expert", "list"}, file, in.Filter)...)
	if err != nil {
		return nil, nil, err
	}
	return successResult(out)
}

func handleFollowStream(ctx context.Context, _ *mcp.CallToolRequest, in followStreamIn) (*mcp.CallToolResult, map[string]any, error) {
	file, err := resolvePCAPPath(in.File)
	if err != nil {
		return nil, nil, err
	}
	proto := "tcp"
	if in.Protocol != nil && *in.Protocol != "" {
		if err := validateProtocol(*in.Protocol, "tcp", "udp"); err != nil {
			return nil, nil, err
		}
		proto = *in.Protocol
	}
	args := []string{"follow", "--file", file, "--protocol", proto}
	if in.Filter != nil && *in.Filter != "" {
		args = append(args, "--filter", *in.Filter)
	}
	out, err := runEpan(ctx, args...)
	if err != nil {
		return nil, nil, err
	}
	return successResult(out)
}

func handleSlicePcap(ctx context.Context, _ *mcp.CallToolRequest, in slicePcapIn) (*mcp.CallToolResult, map[string]any, error) {
	file, err := resolvePCAPPath(in.File)
	if err != nil {
		return nil, nil, err
	}
	if in.Out == "" {
		return nil, nil, fmt.Errorf("out is required (output file path)")
	}
	outPath, err := resolveOutputPath(in.Out)
	if err != nil {
		return nil, nil, err
	}
	args := []string{"slice", "pcap", "--file", file, "--out", outPath}
	if in.Filter != nil && *in.Filter != "" {
		args = append(args, "--filter", *in.Filter)
	}
	if in.Indices != nil && *in.Indices != "" {
		args = append(args, "--indices", *in.Indices)
	}
	out, err := runEpan(ctx, args...)
	if err != nil {
		return nil, nil, err
	}
	return successResult(out)
}

func handleEvidenceBundle(ctx context.Context, _ *mcp.CallToolRequest, in evidenceBundleIn) (*mcp.CallToolResult, map[string]any, error) {
	file, err := resolvePCAPPath(in.File)
	if err != nil {
		return nil, nil, err
	}
	out, err := runEpan(ctx, fileFilterCLI([]string{"evidence", "bundle"}, file, in.Filter)...)
	if err != nil {
		return nil, nil, err
	}
	out.suggestTool("create_pcap_slice")
	return successResult(out)
}

func handleVerifyZeekAlert(ctx context.Context, _ *mcp.CallToolRequest, in verifyZeekAlertIn) (*mcp.CallToolResult, map[string]any, error) {
	file, err := resolvePCAPPath(in.File)
	if err != nil {
		return nil, nil, err
	}
	filter := strings.TrimSpace(valueOrEmpty(in.Filter))
	if filter == "" {
		filter = zeekAlertFilter(in)
	}
	if filter == "" {
		return nil, nil, fmt.Errorf("filter or Zeek alert fields are required")
	}

	resp := map[string]any{
		"tool":   "verify_zeek_alert",
		"file":   file,
		"filter": filter,
	}
	if in.Alert != nil {
		resp["alert"] = in.Alert
	}

	if out, err := runEpan(ctx, "filter", "validate-detailed", "--expr", filter); err != nil {
		resp["filter_valid"] = false
		resp["filter_error"] = err.Error()
		resp["suggestion"] = "Call suggest_filter and retry with valid Wireshark display fields."
	} else {
		resp["filter_valid"] = true
		resp["filter_validation"] = parseOutput(out)
	}
	if out, err := runEpan(ctx, "frames", "page", "--file", file, "--page", "1", "--size", "20", "--filter", filter); err != nil {
		resp["candidate_frames_error"] = err.Error()
	} else {
		resp["candidate_frames"] = parseOutput(out)
	}
	if out, err := runEpan(ctx, "streams", "list", "--file", file, "--filter", filter); err != nil {
		resp["streams_error"] = err.Error()
	} else {
		resp["streams"] = parseOutput(out)
	}
	if out, err := runEpan(ctx, "expert", "list", "--file", file, "--filter", filter); err != nil {
		resp["expert_findings_error"] = err.Error()
	} else {
		resp["expert_findings"] = parseOutput(out)
	}

	text, _ := json.MarshalIndent(resp, "", "  ")
	return textResult(string(text)), nil, nil
}

func zeekAlertFilter(in verifyZeekAlertIn) string {
	parts := []string{}
	srcIP := firstString(in.SrcIP, in.Alert, "src_ip", "source_ip", "id.orig_h", "id_orig_h")
	dstIP := firstString(in.DstIP, in.Alert, "dst_ip", "destination_ip", "id.resp_h", "id_resp_h")
	proto := strings.ToLower(firstString(in.Proto, in.Alert, "proto", "protocol"))
	srcPort := firstInt(in.SrcPort, in.Alert, "src_port", "id.orig_p", "id_orig_p")
	dstPort := firstInt(in.DstPort, in.Alert, "dst_port", "id.resp_p", "id_resp_p")
	if srcIP != "" {
		parts = append(parts, fmt.Sprintf("ip.src == %s", srcIP))
	}
	if dstIP != "" {
		parts = append(parts, fmt.Sprintf("ip.dst == %s", dstIP))
	}
	portPrefix := "tcp"
	if proto == "udp" {
		portPrefix = "udp"
	}
	if srcPort > 0 {
		parts = append(parts, fmt.Sprintf("%s.srcport == %d", portPrefix, srcPort))
	}
	if dstPort > 0 {
		parts = append(parts, fmt.Sprintf("%s.dstport == %d", portPrefix, dstPort))
	}
	if proto == "tcp" || proto == "udp" {
		parts = append(parts, proto)
	}
	return strings.Join(parts, " and ")
}

func valueOrEmpty(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

func firstString(explicit *string, alert map[string]any, keys ...string) string {
	if explicit != nil && *explicit != "" {
		return *explicit
	}
	for _, key := range keys {
		if v, ok := alert[key]; ok {
			switch val := v.(type) {
			case string:
				return val
			case fmt.Stringer:
				return val.String()
			}
		}
	}
	return ""
}

func firstInt(explicit *int, alert map[string]any, keys ...string) int {
	if explicit != nil && *explicit > 0 {
		return *explicit
	}
	for _, key := range keys {
		if v, ok := alert[key]; ok {
			switch val := v.(type) {
			case int:
				return val
			case int64:
				return int(val)
			case float64:
				return int(val)
			case string:
				n, _ := strconv.Atoi(val)
				return n
			}
		}
	}
	return 0
}

func handleTapConversations(ctx context.Context, _ *mcp.CallToolRequest, in tapConversationsIn) (*mcp.CallToolResult, map[string]any, error) {
	file, err := resolvePCAPPath(in.File)
	if err != nil {
		return nil, nil, err
	}
	convType := "tcp"
	if in.Type != nil && *in.Type != "" {
		if err := validateTapType(*in.Type, "eth", "ip", "tcp", "udp"); err != nil {
			return nil, nil, err
		}
		convType = *in.Type
	}
	args := []string{"tap", "conversations", "--file", file, "--type", convType}
	if in.Filter != nil && *in.Filter != "" {
		args = append(args, "--filter", *in.Filter)
	}
	out, err := runEpan(ctx, args...)
	if err != nil {
		return nil, nil, err
	}
	return successResult(out)
}

func handleTapEndpoints(ctx context.Context, _ *mcp.CallToolRequest, in tapEndpointsIn) (*mcp.CallToolResult, map[string]any, error) {
	file, err := resolvePCAPPath(in.File)
	if err != nil {
		return nil, nil, err
	}
	epType := "ip"
	if in.Type != nil && *in.Type != "" {
		if err := validateTapType(*in.Type, "eth", "ip", "tcp", "udp"); err != nil {
			return nil, nil, err
		}
		epType = *in.Type
	}
	args := []string{"tap", "endpoints", "--file", file, "--type", epType}
	if in.Filter != nil && *in.Filter != "" {
		args = append(args, "--filter", *in.Filter)
	}
	out, err := runEpan(ctx, args...)
	if err != nil {
		return nil, nil, err
	}
	return successResult(out)
}

func handleSRTList(ctx context.Context, _ *mcp.CallToolRequest, in srtListIn) (*mcp.CallToolResult, map[string]any, error) {
	file, err := resolvePCAPPath(in.File)
	if err != nil {
		return nil, nil, err
	}
	if in.Protocol == "" {
		return nil, nil, fmt.Errorf("protocol is required (e.g. smb, dns, http)")
	}
	args := []string{"srt", "list", "--file", file, "--protocol", in.Protocol}
	if in.Filter != nil && *in.Filter != "" {
		args = append(args, "--filter", *in.Filter)
	}
	out, err := runEpan(ctx, args...)
	if err != nil {
		return nil, nil, err
	}
	return successResult(out)
}

func handleExportObjectList(ctx context.Context, _ *mcp.CallToolRequest, in exportObjectListIn) (*mcp.CallToolResult, map[string]any, error) {
	file, err := resolvePCAPPath(in.File)
	if err != nil {
		return nil, nil, err
	}
	if in.Protocol == "" {
		return nil, nil, fmt.Errorf("protocol is required (e.g. http)")
	}
	args := []string{"export-object", "list", "--file", file, "--protocol", in.Protocol}
	if in.Filter != nil && *in.Filter != "" {
		args = append(args, "--filter", *in.Filter)
	}
	out, err := runEpan(ctx, args...)
	if err != nil {
		return nil, nil, err
	}
	return successResult(out)
}

func handleExportObjectWrite(ctx context.Context, _ *mcp.CallToolRequest, in exportObjectWriteIn) (*mcp.CallToolResult, map[string]any, error) {
	file, err := resolvePCAPPath(in.File)
	if err != nil {
		return nil, nil, err
	}
	if in.Protocol == "" {
		return nil, nil, fmt.Errorf("protocol is required (e.g. http)")
	}
	if in.PacketNum <= 0 {
		return nil, nil, fmt.Errorf("packetNum must be > 0, got %d", in.PacketNum)
	}
	if in.Out == "" {
		return nil, nil, fmt.Errorf("out is required (output file path)")
	}
	outPath, err := resolveOutputPath(in.Out)
	if err != nil {
		return nil, nil, err
	}
	args := []string{"export-object", "write", "--file", file, "--protocol", in.Protocol, "--packet-num", strconv.Itoa(in.PacketNum), "--out", outPath}
	if in.Filter != nil && *in.Filter != "" {
		args = append(args, "--filter", *in.Filter)
	}
	out, err := runEpan(ctx, args...)
	if err != nil {
		return nil, nil, err
	}
	return successResult(out)
}

func handleStatsSummary(ctx context.Context, _ *mcp.CallToolRequest, in statsSummaryIn) (*mcp.CallToolResult, map[string]any, error) {
	file, err := resolvePCAPPath(in.File)
	if err != nil {
		return nil, nil, err
	}
	out, err := runEpan(ctx, fileFilterCLI([]string{"stats"}, file, in.Filter)...)
	if err != nil {
		return nil, nil, err
	}
	out.suggestTool("create_evidence_bundle")
	return successResult(out)
}

func handleExtractFiles(ctx context.Context, _ *mcp.CallToolRequest, in extractFilesIn) (*mcp.CallToolResult, map[string]any, error) {
	file, err := resolvePCAPPath(in.File)
	if err != nil {
		return nil, nil, err
	}
	if in.Out == "" {
		return nil, nil, fmt.Errorf("out is required (output directory path)")
	}
	outPath, err := resolveOutputPath(in.Out)
	if err != nil {
		return nil, nil, err
	}
	out, err := runEpan(ctx, "extract", "--file", file, "--out", outPath)
	if err != nil {
		return nil, nil, err
	}
	return successResult(out)
}

func handleDoctor(ctx context.Context, _ *mcp.CallToolRequest, _ doctorIn) (*mcp.CallToolResult, map[string]any, error) {
	bin := epanBin()
	absBin, _ := exec.LookPath(bin)

	result := map[string]any{
		"binary":                    bin,
		"resolvedBinaryPath":        absBin,
		"pcapDir":                   pcapDir(),
		"outputDir":                 outputDir(),
		"timeout":                   timeout().String(),
		"maxOutputBytes":            maxOutputBytes(),
		"wiresharkLibDir":           os.Getenv("WIRESHARK_LIB_DIR"),
		"wiresharkDataDir":          os.Getenv("WIRESHARK_DATA_DIR"),
		"wiresharkConfDir":          os.Getenv("WIRESHARK_CONF_DIR"),
		"epanPcapDir":        os.Getenv("EPAN_PCAP_DIR"),
		"epanOutputDir":      os.Getenv("EPAN_OUTPUT_DIR"),
		"epanTimeout":        os.Getenv("EPAN_TIMEOUT"),
		"epanMaxOutputBytes": os.Getenv("EPAN_MAX_OUTPUT_BYTES"),
	}

	// List available PCAP files in the allowed directory
	if dir := pcapDir(); dir != "" {
		entries, err := os.ReadDir(dir)
		if err == nil {
			var pcaps []string
			for _, e := range entries {
				if e.IsDir() {
					continue
				}
				ext := strings.ToLower(filepath.Ext(e.Name()))
				if ext == ".pcap" || ext == ".pcapng" || ext == ".cap" {
					pcaps = append(pcaps, e.Name())
				}
			}
			result["availablePcaps"] = pcaps
			result["availablePcapCount"] = len(pcaps)
		} else {
			result["pcapDirError"] = err.Error()
		}
	} else {
		result["pcapDirNote"] = "PCAP_DIR not set; any absolute path is accepted"
	}

	verOut, verErr := runEpan(ctx, "version")
	if verErr != nil {
		result["runtimeStatus"] = fmt.Sprintf("unavailable: %v", verErr)
	} else {
		result["runtimeStatus"] = "available"
		var verParsed map[string]any
		if json.Unmarshal([]byte(verOut.Text), &verParsed) == nil {
			if v, ok := verParsed["version"]; ok {
				result["runtimeVersion"] = v
			}
		}
	}

	_, err := os.Stat(absBin)
	result["binaryFound"] = err == nil

	text, _ := json.MarshalIndent(result, "", "  ")
	return textResult(string(text)), nil, nil
}

// --- Resources ---

func registerResources(srv *mcp.Server) {
	srv.AddResource(&mcp.Resource{
		URI:         "epan://pcaps",
		Name:        "Available PCAPs",
		Description: "Lists PCAP files in the allowed PCAP_DIR directory",
		MIMEType:    "application/json",
	}, func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		dir := pcapDir()
		if dir == "" {
			return &mcp.ReadResourceResult{
				Contents: []*mcp.ResourceContents{{
					URI:      "epan://pcaps",
					MIMEType: "application/json",
					Text:     `{"pcaps":[],"error":"PCAP_DIR not set"}`,
				}},
			}, nil
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return &mcp.ReadResourceResult{
				Contents: []*mcp.ResourceContents{{
					URI:      "epan://pcaps",
					MIMEType: "application/json",
					Text:     fmt.Sprintf(`{"pcaps":[],"error":%q}`, err.Error()),
				}},
			}, nil
		}
		var pcaps []map[string]any
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			ext := strings.ToLower(filepath.Ext(name))
			if ext == ".pcap" || ext == ".pcapng" || ext == ".cap" {
				info, _ := e.Info()
				size := int64(0)
				if info != nil {
					size = info.Size()
				}
				pcapPath, _ := resolvePCAPPath(name)
				pcaps = append(pcaps, map[string]any{
					"name": e.Name(),
					"path": pcapPath,
					"size": size,
				})
			}
		}
		data, _ := json.MarshalIndent(map[string]any{"pcaps": pcaps, "directory": dir}, "", "  ")
		return &mcp.ReadResourceResult{
			Contents: []*mcp.ResourceContents{{
				URI:      "epan://pcaps",
				MIMEType: "application/json",
				Text:     string(data),
			}},
		}, nil
	})

	srv.AddResource(&mcp.Resource{
		URI:         "epan://outputs",
		Name:        "Output files",
		Description: "Lists files in the allowed OUTPUT_DIR directory",
		MIMEType:    "application/json",
	}, func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		dir := outputDir()
		entries, err := os.ReadDir(dir)
		if err != nil {
			return &mcp.ReadResourceResult{
				Contents: []*mcp.ResourceContents{{
					URI:      "epan://outputs",
					MIMEType: "application/json",
					Text:     fmt.Sprintf(`{"outputs":[],"error":%q}`, err.Error()),
				}},
			}, nil
		}
		var outputs []map[string]any
		for _, e := range entries {
			info, _ := e.Info()
			size := int64(0)
			isDir := e.IsDir()
			if info != nil {
				size = info.Size()
			}
			outputPath, _ := resolveOutputPath(e.Name())
			outputs = append(outputs, map[string]any{
				"name":  e.Name(),
				"path":  outputPath,
				"size":  size,
				"isDir": isDir,
			})
		}
		data, _ := json.MarshalIndent(map[string]any{"outputs": outputs, "directory": dir}, "", "  ")
		return &mcp.ReadResourceResult{
			Contents: []*mcp.ResourceContents{{
				URI:      "epan://outputs",
				MIMEType: "application/json",
				Text:     string(data),
			}},
		}, nil
	})

	srv.AddResource(&mcp.Resource{
		URI:         "epan://docs/cli-reference",
		Name:        "CLI Reference",
		Description: "Built-in epan CLI command reference for agent workflows",
		MIMEType:    "text/markdown",
	}, func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		ref := cliReferenceMarkdown()
		return &mcp.ReadResourceResult{
			Contents: []*mcp.ResourceContents{{
				URI:      "epan://docs/cli-reference",
				MIMEType: "text/markdown",
				Text:     ref,
			}},
		}, nil
	})

	srv.AddResourceTemplate(&mcp.ResourceTemplate{
		URITemplate: "epan://pcap/{name}/summary",
		Name:        "PCAP Summary",
		Description: "Lightweight summary (frame count, streams, expert infos) for a named PCAP file in PCAP_DIR",
		MIMEType:    "application/json",
	}, func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		return pcapSummaryResource(ctx, req.Params.URI)
	})
}

func pcapSummaryResource(ctx context.Context, uri string) (*mcp.ReadResourceResult, error) {
	const prefix = "epan://pcap/"
	const suffix = "/summary"
	if !strings.HasPrefix(uri, prefix) || !strings.HasSuffix(uri, suffix) {
		return nil, mcp.ResourceNotFoundError(uri)
	}
	name := strings.TrimSuffix(strings.TrimPrefix(uri, prefix), suffix)
	if decoded, err := url.PathUnescape(name); err == nil {
		name = decoded
	}
	file, err := resolvePCAPPath(name)
	if err != nil {
		return jsonResource(uri, map[string]any{"name": name, "error": err.Error()}), nil
	}

	summary := map[string]any{"name": name, "path": file}
	if countOut, err := runEpan(ctx, "frames", "count", "--file", file); err != nil {
		summary["frameCountError"] = err.Error()
	} else if parsed := parseOutput(countOut); parsed != nil {
		summary["frameCount"] = parsed["count"]
	}
	if streamsOut, err := runEpan(ctx, "streams", "list", "--file", file); err != nil {
		summary["streamsError"] = err.Error()
	} else if parsed := parseOutput(streamsOut); parsed != nil {
		summary["streamsCount"] = listLen(parsed["list"])
	}
	if expertOut, err := runEpan(ctx, "expert", "list", "--file", file); err != nil {
		summary["expertError"] = err.Error()
	} else if parsed := parseOutput(expertOut); parsed != nil {
		summary["expertCount"] = listLen(parsed["list"])
	}
	return jsonResource(uri, summary), nil
}

func jsonResource(uri string, v any) *mcp.ReadResourceResult {
	data, _ := json.MarshalIndent(v, "", "  ")
	return &mcp.ReadResourceResult{
		Contents: []*mcp.ResourceContents{{
			URI:      uri,
			MIMEType: "application/json",
			Text:     string(data),
		}},
	}
}

func listLen(v any) int {
	if list, ok := v.([]any); ok {
		return len(list)
	}
	return 0
}

func cliReferenceMarkdown() string {
	candidates := []string{
		filepath.Join(".codex", "skills", "epan", "references", "cli-reference.md"),
		filepath.Join("agents", "pcap-analysis-rules.md"),
	}
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(exeDir, "..", ".codex", "skills", "epan", "references", "cli-reference.md"),
			filepath.Join(exeDir, "..", "agents", "pcap-analysis-rules.md"),
		)
	}
	for _, candidate := range candidates {
		data, err := os.ReadFile(candidate)
		if err == nil {
			return string(data)
		}
	}
	return `# epan CLI Reference

## System & Discovery

` + "`" + "`" + "`" + `bash
epan version
epan filter validate --expr 'tcp.port == 80'
epan filter validate-detailed --expr 'tcp.stream'
epan filter suggest --prefix 'tcp.'
epan metadata protocols
epan metadata fields
epan metadata field --name tcp.stream
` + "`" + "`" + "`" + `

## Frame Inspection

` + "`" + "`" + "`" + `bash
epan frames count --file capture.pcap --filter 'tcp'
epan frames page --file capture.pcap --page 1 --size 20 --filter 'http'
epan frames get --file capture.pcap --index 5
epan frames batch --file capture.pcap --indices 1,5,10
epan frames hex --file capture.pcap --index 5
epan frames write --file capture.pcap --fields frame.number,ip.src,ip.dst,frame.protocols --out frames.jsonl
epan frames fields --file capture.pcap --fields ip.src,ip.dst,tcp.port
` + "`" + "`" + "`" + `

## Traffic Analysis

` + "`" + "`" + "`" + `bash
epan streams list --file capture.pcap --filter 'tcp'
epan traffic conversations list --file capture.pcap --filter 'dns'
epan traffic timeline summary --file capture.pcap
epan traffic files list --file capture.pcap
` + "`" + "`" + "`" + `

## Stream Reassembly

` + "`" + "`" + "`" + `bash
epan follow --file capture.pcap --protocol tcp --filter 'tcp.stream eq 3'
epan follow --file capture.pcap --protocol udp --filter 'udp.stream eq 1'
` + "`" + "`" + "`" + `

## Expert & Evidence

` + "`" + "`" + "`" + `bash
epan expert list --file capture.pcap --filter 'tcp'
epan slice pcap --file capture.pcap --filter 'tcp.port == 443' --out tls.pcap
epan slice pcap --file capture.pcap --indices 1,5,9 --out selected.pcap
epan evidence bundle --file capture.pcap --filter 'tcp.port == 80'
` + "`" + "`" + "`" + `

## Tap & SRT

` + "`" + "`" + "`" + `bash
epan tap conversations --file capture.pcap --type tcp --filter 'tcp'
epan tap endpoints --file capture.pcap --type ip
epan srt list --file capture.pcap --protocol smb
epan srt list --file capture.pcap --protocol dns
` + "`" + "`" + "`" + `

## Export Objects

` + "`" + "`" + "`" + `bash
epan export-object list --file capture.pcap --protocol http
epan export-object write --file capture.pcap --protocol http --packet-num 42 --out extracted.dat
` + "`" + "`" + "`" + `

## Stats & Extract

` + "`" + "`" + "`" + `bash
epan stats --file capture.pcap --filter 'tcp'
epan extract --file capture.pcap --out extracted-files/
` + "`" + "`" + "`" + `

## Guidance

- Use ` + "`" + `frames page` + "`" + ` as the default inspection command for large pcaps.
- ` + "`" + `streams list` + "`" + ` reveals followable streams (look for ` + "`" + `streamId >= 0` + "`" + `).
- ` + "`" + `follow` + "`" + ` expects a Wireshark display filter (e.g. ` + "`" + `tcp.stream eq 0` + "`" + `).
- ` + "`" + `slice pcap` + "`" + ` creates a new pcap from selected frames.
- ` + "`" + `evidence bundle` + "`" + ` produces comprehensive forensic metadata.
- ` + "`" + `export-object write` + "`" + ` extracts HTTP objects to disk.
- Always validate new display filters with ` + "`" + `epan filter validate-detailed` + "`" + ` before using them.
`
}

// --- Prompts ---

func registerPrompts(srv *mcp.Server) {
	srv.AddPrompt(&mcp.Prompt{
		Name:        "pcap_triage",
		Description: "Quick initial triage of a PCAP file: gauge size, map traffic, check anomalies",
	}, func(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		return &mcp.GetPromptResult{
			Description: "PCAP Triage workflow",
			Messages: []*mcp.PromptMessage{{
				Role: "user",
				Content: &mcp.TextContent{
					Text: `I need to perform initial triage on a PCAP file. Please follow this workflow:

1. First, gauge the capture size:
   - Use count_frames to count frames

2. Map the traffic structure:
   - Use list_streams to see TCP/UDP streams

3. Check for anomalies:
   - Use list_expert_findings to find protocol violations, warnings

4. Get protocol distribution:
   - Use stats_summary for a statistical overview

5. Summarize your findings: protocol distribution, stream count, notable anomalies.

IMPORTANT: Do NOT dump all frames. Use paginated frame inspection (list_frames) only when you need to inspect specific packets.`,
				},
			}},
		}, nil
	})

	srv.AddPrompt(&mcp.Prompt{
		Name:        "stream_deep_dive",
		Description: "Deep-dive analysis of a specific TCP/UDP stream: follow, inspect frames, extract objects",
	}, func(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		return &mcp.GetPromptResult{
			Description: "Stream deep-dive workflow",
			Messages: []*mcp.PromptMessage{{
				Role: "user",
				Content: &mcp.TextContent{
					Text: `I need to perform a deep-dive analysis on a specific network stream. Please follow this workflow:

1. First, identify the stream ID:
   - Use list_streams to list all streams
   - Note: only follow streams where streamId >= 0

2. Follow the stream to get reassembled payload:
   - Use follow_stream with protocol=tcp|udp and filter='tcp.stream eq N'

3. Inspect key frames in the stream:
   - Use list_frames with filter='tcp.stream eq N'
   - Look at frame content using get_frame

4. Check for any objects embedded in the stream:
   - Use exportable_objects with protocol=http (if HTTP)

5. If HTTP objects found, extract relevant ones:
   - Use write_exportable_object

6. Summarize what the stream contains: protocol type, payload content, any extracted objects.`,
				},
			}},
		}, nil
	})

	srv.AddPrompt(&mcp.Prompt{
		Name:        "evidence_bundle_workflow",
		Description: "Produce forensic evidence: slice captures, build evidence bundles, validate filters",
	}, func(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		return &mcp.GetPromptResult{
			Description: "Evidence bundle production workflow",
			Messages: []*mcp.PromptMessage{{
				Role: "user",
				Content: &mcp.TextContent{
					Text: `I need to produce forensic evidence from a PCAP file. Please follow this workflow:

1. Start with triage to understand the capture:
   - Use count_frames, list_streams, list_expert_findings
   - Use stats_summary for statistical overview

2. Narrow scope with validated filters:
   - Construct a display filter for the traffic of interest
   - ALWAYS validate: use validate_filter with your filter expression
   - DO NOT guess Wireshark display filter syntax

3. Slice the PCAP to isolate evidence:
   - Use create_pcap_slice with your validated filter
   - Verify the slice with count_frames on the output

4. Build the evidence bundle:
   - Use create_evidence_bundle with your validated filter
   - This produces conversations, expert infos, protocol hierarchy

5. Present findings:
   - Frame count in the slice
   - Key conversations and endpoints
   - Expert analysis findings
   - Protocol breakdown`,
				},
			}},
		}, nil
	})

	srv.AddPrompt(&mcp.Prompt{
		Name:        "extract_http_objects",
		Description: "Extract HTTP objects (files, images, documents) from network traffic",
	}, func(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		return &mcp.GetPromptResult{
			Description: "HTTP object extraction workflow",
			Messages: []*mcp.PromptMessage{{
				Role: "user",
				Content: &mcp.TextContent{
					Text: `I need to extract HTTP objects from a PCAP file. Please follow this workflow:

1. List all exportable HTTP objects:
   - Use exportable_objects with protocol=http

2. Review the object list for interesting items:
   - Look at content types, sizes, filenames
   - Identify objects relevant to the investigation

3. Extract specific objects:
   - Use write_exportable_object for each interesting object
   - Provide the packetNum (packet number) for each object to extract
   - Output must go to OUTPUT_DIR

4. For bulk extraction of all detected files:
   - Use extract_files with the out directory

5. Report what was extracted: object types, filenames, sizes, and where they were saved.`,
				},
			}},
		}, nil
	})
}
