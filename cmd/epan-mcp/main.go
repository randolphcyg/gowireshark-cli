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
	mcpCacheTTL           = 5 * time.Minute
	mcpCacheCleanInterval = 10 * time.Minute
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

// mcpCache is a simple in-memory cache for high-frequency read-only MCP tools
// (list_protocols, list_fields, get_version, etc.) to reduce epan CLI fork overhead.
type mcpCache struct {
	mu       sync.Mutex
	entries  map[string]*mcpCacheEntry
	stopCh   chan struct{}
	stopOnce sync.Once
}

type mcpCacheEntry struct {
	value     *epanOutput
	expiresAt time.Time
}

var globalCache = newMCPCache()

func newMCPCache() *mcpCache {
	c := &mcpCache{
		entries: make(map[string]*mcpCacheEntry),
		stopCh:  make(chan struct{}),
	}
	go c.cleanLoop()
	return c
}

func (c *mcpCache) get(key string) *epanOutput {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok || time.Now().After(entry.expiresAt) {
		return nil
	}
	return entry.value
}

func (c *mcpCache) set(key string, value *epanOutput) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = &mcpCacheEntry{
		value:     value,
		expiresAt: time.Now().Add(mcpCacheTTL),
	}
}

func (c *mcpCache) cleanLoop() {
	ticker := time.NewTicker(mcpCacheCleanInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.mu.Lock()
			now := time.Now()
			for k, v := range c.entries {
				if now.After(v.expiresAt) {
					delete(c.entries, k)
				}
			}
			c.mu.Unlock()
		case <-c.stopCh:
			return
		}
	}
}

func (c *mcpCache) stop() {
	c.stopOnce.Do(func() {
		close(c.stopCh)
	})
}

// cachedRunEpan runs epan with caching. If the same key is used and a valid
// cached result exists, it returns the cached result without forking epan CLI.
// The key should be a unique string combining the tool name and input parameters.
func cachedRunEpan(ctx context.Context, key string, args ...string) (*epanOutput, error) {
	if cached := globalCache.get(key); cached != nil {
		return cached, nil
	}
	out, err := runEpan(ctx, args...)
	if err != nil {
		return nil, err
	}
	globalCache.set(key, out)
	return out, nil
}

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

	// --- Core analysis ---
	addTool(srv, &mcp.Tool{
		Name:        "triage_pcap",
		Description: "Quick triage of a PCAP: frame count, streams, expert findings, stats, conversations, and timeline — all in one call.",
		InputSchema: toolInputSchema("triage_pcap"),
	}, handleTriagePcap)

	addTool(srv, &mcp.Tool{
		Name:        "search_frames",
		Description: "Search frames with display filter, pagination, field extraction, or batch indices. Use filter for display filter, page/size for pagination, fields for field export, indices for batch retrieval by frame numbers.",
		InputSchema: toolInputSchema("search_frames"),
	}, handleSearchFrames)

	addTool(srv, &mcp.Tool{
		Name:        "get_frame",
		Description: "Get a single frame by number, with optional hex dump and field extraction.",
		InputSchema: toolInputSchema("get_frame"),
	}, handleGetFrame)

	addTool(srv, &mcp.Tool{
		Name:        "inspect_stream",
		Description: "Follow and reconstruct a TCP/UDP stream with payload and metadata.",
		InputSchema: toolInputSchema("inspect_stream"),
	}, handleInspectStream)

	// --- Filter helpers ---
	addTool(srv, &mcp.Tool{
		Name:        "validate_filter",
		Description: "Validate a Wireshark display filter. Set detailed=true for field-level feedback.",
		InputSchema: toolInputSchema("validate_filter"),
	}, handleValidateFilter)

	addTool(srv, &mcp.Tool{
		Name:        "suggest_filter",
		Description: "Suggest display filter field names by prefix (e.g. 'tcp.', 'ip.')",
		InputSchema: toolInputSchema("suggest_filter"),
	}, handleSuggestFilter)

	// --- Metadata ---
	addTool(srv, &mcp.Tool{
		Name:        "get_field_info",
		Description: "Get metadata for a Wireshark display filter field (e.g. 'tcp.stream')",
		InputSchema: toolInputSchema("get_field_info"),
	}, handleGetFieldInfo)

	// --- Evidence & export ---
	addTool(srv, &mcp.Tool{
		Name:        "slice_pcap",
		Description: "Slice a PCAP file by display filter or frame indices. Output goes to OUTPUT_DIR.",
		InputSchema: toolInputSchema("slice_pcap"),
	}, handleSlicePcap)

	addTool(srv, &mcp.Tool{
		Name:        "build_evidence",
		Description: "Gather all forensic artifacts (conversations, endpoints, expert infos, protocol hierarchy) into an evidence bundle.",
		InputSchema: toolInputSchema("build_evidence"),
	}, handleBuildEvidence)

	addTool(srv, &mcp.Tool{
		Name:        "export_objects",
		Description: "List or extract files/objects from network traffic. Use action='list' to enumerate, action='extract' to save files to a directory.",
		InputSchema: toolInputSchema("export_objects"),
	}, handleExportObjects)

	addTool(srv, &mcp.Tool{
		Name:        "verify_zeek_alert",
		Description: "Verify a Zeek alert against packet evidence: validates filter, finds candidate frames, streams, and expert findings.",
		InputSchema: toolInputSchema("verify_zeek_alert"),
	}, handleVerifyZeekAlert)

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
	case "triage_pcap":
		return objectSchema([]string{"file"}, map[string]any{
			"file":   file,
			"filter": filter,
		})
	case "search_frames":
		return objectSchema([]string{"file"}, map[string]any{
			"file":    file,
			"filter":  filter,
			"page":    map[string]any{"type": "integer", "minimum": 1, "default": 1},
			"size":    map[string]any{"type": "integer", "minimum": 1, "maximum": 100, "default": 20},
			"fields":  map[string]any{"type": "string", "description": "Comma-separated Wireshark field names for field extraction."},
			"indices": map[string]any{"type": "string", "description": "Comma-separated frame numbers for batch retrieval."},
		})
	case "get_frame":
		return objectSchema([]string{"file", "index"}, map[string]any{
			"file":        file,
			"index":       map[string]any{"type": "integer", "minimum": 1},
			"include_hex": map[string]any{"type": "boolean", "default": false, "description": "Include hex dump of the frame."},
			"fields":      map[string]any{"type": "string", "description": "Comma-separated Wireshark field names."},
		})
	case "inspect_stream":
		return objectSchema([]string{"file"}, map[string]any{
			"file":     file,
			"protocol": map[string]any{"type": "string", "enum": []string{"tcp", "udp"}, "default": "tcp"},
			"filter":   filter,
		})
	case "validate_filter":
		return objectSchema([]string{"expr"}, map[string]any{
			"expr":     map[string]any{"type": "string", "minLength": 1, "description": "Wireshark display filter expression to validate."},
			"detailed": map[string]any{"type": "boolean", "default": false, "description": "Return detailed field-level validation feedback."},
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
	case "slice_pcap":
		return objectSchema([]string{"file", "out"}, map[string]any{
			"file":    file,
			"out":     out,
			"filter":  filter,
			"indices": map[string]any{"type": "string", "description": "Comma-separated frame numbers."},
		})
	case "build_evidence":
		return objectSchema([]string{"file"}, map[string]any{
			"file":   file,
			"filter": filter,
		})
	case "export_objects":
		return objectSchema([]string{"file"}, map[string]any{
			"file":       file,
			"action":     map[string]any{"type": "string", "enum": []string{"list", "extract"}, "default": "list", "description": "list to enumerate objects, extract to save files to output_dir."},
			"protocol":   map[string]any{"type": "string", "description": "Optional protocol filter, e.g. 'http', 'smb'. Leave empty for all."},
			"output_dir": map[string]any{"type": "string", "description": "Output directory (required for action=extract)."},
			"packet_num": map[string]any{"type": "integer", "minimum": 1, "description": "Packet number to extract a specific object (for action=extract with protocol set)."},
			"filter":     filter,
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
	return defaultTimeout
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
		return "Retry with corrected parameters and a narrower query."
	default:
		return "Inspect error_message and retry with corrected parameters."
	}
}

func nextToolForError(code, message string) string {
	switch code {
	case "INVALID_PATH":
		return "list_files"
	case "CLI_ERROR":
		if strings.Contains(strings.ToLower(message), "filter") {
			return "validate_filter"
		}
		return ""
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

type triagePcapIn struct {
	File   string  `json:"file"`
	Filter *string `json:"filter,omitempty"`
}

type searchFramesIn struct {
	File    string  `json:"file"`
	Filter  *string `json:"filter,omitempty"`
	Page    int     `json:"page,omitempty"`
	Size    int     `json:"size,omitempty"`
	Fields  *string `json:"fields,omitempty"`
	Indices *string `json:"indices,omitempty"`
}

type getFrameIn struct {
	File       string  `json:"file"`
	Index      int     `json:"index"`
	IncludeHex bool    `json:"include_hex,omitempty"`
	Fields     *string `json:"fields,omitempty"`
}

type inspectStreamIn struct {
	File     string  `json:"file"`
	Protocol *string `json:"protocol,omitempty"`
	Filter   *string `json:"filter,omitempty"`
}

type validateFilterIn struct {
	Expr     string `json:"expr"`
	Detailed bool   `json:"detailed,omitempty"`
}

type suggestFilterIn struct {
	Prefix string `json:"prefix"`
	Limit  int    `json:"limit,omitempty"`
}

type getFieldInfoIn struct {
	Name string `json:"name"`
}

type slicePcapIn struct {
	File    string  `json:"file"`
	Out     string  `json:"out"`
	Filter  *string `json:"filter,omitempty"`
	Indices *string `json:"indices,omitempty"`
}

type buildEvidenceIn struct {
	File   string  `json:"file"`
	Filter *string `json:"filter,omitempty"`
}

type exportObjectsIn struct {
	File      string  `json:"file"`
	Action    *string `json:"action,omitempty"`
	Protocol  *string `json:"protocol,omitempty"`
	OutputDir *string `json:"output_dir,omitempty"`
	PacketNum *int    `json:"packet_num,omitempty"`
	Filter    *string `json:"filter,omitempty"`
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

// --- Handlers ---
// Each handler delegates to the corresponding MCP-composite CLI command,
// keeping only validation and path resolution in the MCP layer.

func handleTriagePcap(ctx context.Context, _ *mcp.CallToolRequest, in triagePcapIn) (*mcp.CallToolResult, map[string]any, error) {
	file, err := resolvePCAPPath(in.File)
	if err != nil {
		return nil, nil, err
	}
	args := []string{"triage_pcap", "--file", file}
	if in.Filter != nil && *in.Filter != "" {
		args = append(args, "--filter", *in.Filter)
	}
	out, err := runEpan(ctx, args...)
	if err != nil {
		return nil, nil, err
	}
	out.suggestTool("search_frames")
	return successResult(out)
}

func handleSearchFrames(ctx context.Context, _ *mcp.CallToolRequest, in searchFramesIn) (*mcp.CallToolResult, map[string]any, error) {
	file, err := resolvePCAPPath(in.File)
	if err != nil {
		return nil, nil, err
	}
	args := []string{"search_frames", "--file", file}
	if in.Filter != nil && *in.Filter != "" {
		args = append(args, "--filter", *in.Filter)
	}
	if in.Indices != nil && *in.Indices != "" {
		args = append(args, "--indices", *in.Indices)
	} else if in.Fields != nil && *in.Fields != "" {
		args = append(args, "--fields", *in.Fields)
	} else {
		page := in.Page
		if page < 1 {
			page = 1
		}
		size := in.Size
		if size < 1 {
			size = 20
		}
		args = append(args, "--page", strconv.Itoa(page), "--size", strconv.Itoa(size))
	}
	out, err := runEpan(ctx, args...)
	if err != nil {
		return nil, nil, err
	}
	return successResult(out)
}

func handleGetFrame(ctx context.Context, _ *mcp.CallToolRequest, in getFrameIn) (*mcp.CallToolResult, map[string]any, error) {
	file, err := resolvePCAPPath(in.File)
	if err != nil {
		return nil, nil, err
	}
	if in.Index < 1 {
		return nil, nil, fmt.Errorf("index must be >= 1, got %d", in.Index)
	}
	args := []string{"get_frame", "--file", file, "--index", strconv.Itoa(in.Index)}
	if in.IncludeHex {
		args = append(args, "--include-hex")
	}
	if in.Fields != nil && *in.Fields != "" {
		args = append(args, "--fields", *in.Fields)
	}
	out, err := runEpan(ctx, args...)
	if err != nil {
		return nil, nil, err
	}
	return successResult(out)
}

func handleInspectStream(ctx context.Context, _ *mcp.CallToolRequest, in inspectStreamIn) (*mcp.CallToolResult, map[string]any, error) {
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
	args := []string{"inspect_stream", "--file", file, "--protocol", proto}
	if in.Filter != nil && *in.Filter != "" {
		args = append(args, "--filter", *in.Filter)
	}
	out, err := runEpan(ctx, args...)
	if err != nil {
		return nil, nil, err
	}
	return successResult(out)
}

func handleValidateFilter(ctx context.Context, _ *mcp.CallToolRequest, in validateFilterIn) (*mcp.CallToolResult, map[string]any, error) {
	if in.Expr == "" {
		return nil, nil, fmt.Errorf("expr is required")
	}
	if err := validateStringMax(in.Expr, "expr", maxExprLength); err != nil {
		return nil, nil, err
	}
	args := []string{"validate_filter", "--expr", in.Expr}
	if in.Detailed {
		args = append(args, "--detailed")
	}
	out, err := runEpan(ctx, args...)
	if err != nil {
		return nil, nil, err
	}
	return successResult(out)
}

func handleSuggestFilter(ctx context.Context, _ *mcp.CallToolRequest, in suggestFilterIn) (*mcp.CallToolResult, map[string]any, error) {
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
	cacheKey := fmt.Sprintf("suggest_filter:%s:%d", in.Prefix, limit)
	out, err := cachedRunEpan(ctx, cacheKey, "suggest_filter", "--prefix", in.Prefix, "--limit", strconv.Itoa(limit))
	if err != nil {
		return nil, nil, err
	}
	return successResult(out)
}

func handleGetFieldInfo(ctx context.Context, _ *mcp.CallToolRequest, in getFieldInfoIn) (*mcp.CallToolResult, map[string]any, error) {
	if in.Name == "" {
		return nil, nil, fmt.Errorf("name is required")
	}
	if err := validateStringMax(in.Name, "name", 128); err != nil {
		return nil, nil, err
	}
	cacheKey := "get_field_info:" + in.Name
	out, err := cachedRunEpan(ctx, cacheKey, "get_field_info", "--name", in.Name)
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
	args := []string{"slice_pcap", "--file", file, "--out", outPath}
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

func handleBuildEvidence(ctx context.Context, _ *mcp.CallToolRequest, in buildEvidenceIn) (*mcp.CallToolResult, map[string]any, error) {
	file, err := resolvePCAPPath(in.File)
	if err != nil {
		return nil, nil, err
	}
	args := []string{"build_evidence", "--file", file}
	if in.Filter != nil && *in.Filter != "" {
		args = append(args, "--filter", *in.Filter)
	}
	out, err := runEpan(ctx, args...)
	if err != nil {
		return nil, nil, err
	}
	out.suggestTool("slice_pcap")
	return successResult(out)
}

func handleExportObjects(ctx context.Context, _ *mcp.CallToolRequest, in exportObjectsIn) (*mcp.CallToolResult, map[string]any, error) {
	file, err := resolvePCAPPath(in.File)
	if err != nil {
		return nil, nil, err
	}
	action := "list"
	if in.Action != nil && *in.Action != "" {
		action = *in.Action
	}
	args := []string{"export_objects", "--file", file, "--action", action}
	if in.Protocol != nil && *in.Protocol != "" {
		args = append(args, "--protocol", *in.Protocol)
	}
	if in.Filter != nil && *in.Filter != "" {
		args = append(args, "--filter", *in.Filter)
	}
	if action == "extract" {
		if in.OutputDir == nil || *in.OutputDir == "" {
			return nil, nil, fmt.Errorf("output_dir is required for action=extract")
		}
		outPath, err := resolveOutputPath(*in.OutputDir)
		if err != nil {
			return nil, nil, err
		}
		args = append(args, "--out", outPath)
		if in.Protocol != nil && *in.Protocol != "" {
			if in.PacketNum == nil || *in.PacketNum <= 0 {
				return nil, nil, fmt.Errorf("packet_num is required for action=extract with protocol")
			}
			args = append(args, "--packet-num", strconv.Itoa(*in.PacketNum))
		}
	}
	out, err := runEpan(ctx, args...)
	if err != nil {
		return nil, nil, err
	}
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
	args := []string{"verify_zeek_alert", "--file", file, "--filter", filter}
	if in.Alert != nil && len(in.Alert) > 0 {
		// Extract alert type string from the map for reporting
		if alertType := firstString(nil, in.Alert, "alert", "type", "msg"); alertType != "" {
			args = append(args, "--alert", alertType)
		}
	}
	out, err := runEpan(ctx, args...)
	if err != nil {
		return nil, nil, err
	}
	return successResult(out)
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

	srv.AddResource(&mcp.Resource{
		URI:         "epan://docs/protocols",
		Name:        "Supported Protocols",
		Description: "List of all supported Wireshark protocols",
		MIMEType:    "application/json",
	}, func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		out, err := cachedRunEpan(ctx, "list_protocols_resource", "metadata", "protocols")
		if err != nil {
			return jsonResource("epan://docs/protocols", map[string]any{"error": err.Error()}), nil
		}
		parsed := parseOutput(out)
		return jsonResource("epan://docs/protocols", parsed), nil
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
	return `# epan MCP Tool Reference

## Core Analysis

` + "`" + "`" + "`" + `
triage_pcap(file, filter?)       — Frame count, streams, expert findings, stats, conversations
search_frames(file, filter?, page?, size?, fields?, indices?) — Paginated/batch/field frame search
get_frame(file, index, include_hex?, fields?) — Single frame with optional hex and fields
inspect_stream(file, protocol?, filter?) — Follow and reconstruct TCP/UDP stream
` + "`" + "`" + "`" + `

## Filter Helpers

` + "`" + "`" + "`" + `
validate_filter(expr, detailed?) — Validate display filter, set detailed=true for field feedback
suggest_filter(prefix, limit?)   — Suggest field names by prefix (e.g. 'tcp.')
` + "`" + "`" + "`" + `

## Metadata

` + "`" + "`" + "`" + `
get_field_info(name)            — Get metadata for a field (e.g. 'tcp.stream')

` + "`" + "`" + "`" + `

## Evidence & Export

` + "`" + "`" + "`" + `
slice_pcap(file, out, filter?, indices?)  — Slice PCAP by filter or indices
build_evidence(file, filter?)             — Gather forensic artifacts into a bundle
export_objects(file, action?, protocol?, output_dir?, packet_num?) — List (action=list) or extract (action=extract) files/objects
verify_zeek_alert(file, filter?, alert?, ...) — Verify Zeek alert against packet evidence
` + "`" + "`" + "`" + `

## Resources

` + "`" + "`" + "`" + `
epan://docs/protocols  — List of all supported Wireshark protocols
` + "`" + "`" + "`" + `

## Guidance

- Use ` + "`" + `triage_pcap` + "`" + ` as the first command for any new PCAP.
- ` + "`" + `search_frames` + "`" + ` is the default inspection command. Use filter for display filter, page/size for pagination, fields for field export, indices for batch retrieval.
- ` + "`" + `inspect_stream` + "`" + ` expects a Wireshark display filter (e.g. ` + "`" + `tcp.stream eq 0` + "`" + `).
- ` + "`" + `slice_pcap` + "`" + ` creates a new pcap from selected frames.
- ` + "`" + `build_evidence` + "`" + ` gathers all forensic artifacts (conversations, endpoints, expert infos, protocol hierarchy).
- ` + "`" + `export_objects` + "`" + ` with action=extract saves files/objects to output_dir.
- Always validate new display filters with ` + "`" + `validate_filter` + "`" + ` with detailed=true before using them.
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

1. Use triage_pcap to get a comprehensive overview:
   - Frame count, protocol distribution
   - TCP/UDP streams
   - Expert findings (anomalies, warnings)
   - Statistical summary

2. Optional: use search_frames (paginated) to inspect specific frames if needed.

3. Summarize your findings: protocol distribution, stream count, notable anomalies.

IMPORTANT: Do NOT dump all frames. Use triage_pcap for the high-level view and search_frames only when you need to inspect specific packets.`,
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

1. First, identify the stream of interest:
   - Use triage_pcap to see all streams and frame counts
   - Note: only follow streams where streamId >= 0

2. Follow the stream to get reassembled payload:
   - Use inspect_stream with protocol=tcp|udp and filter='tcp.stream eq N'

3. Inspect key frames in the stream:
   - Use search_frames with filter='tcp.stream eq N'
   - Look at individual frame content using get_frame

4. Check for any objects embedded in the stream:
   - Use export_objects with protocol=http, action=list (if HTTP)

5. If HTTP objects found, extract them:
   - Use export_objects with action=extract, protocol=http, packet_num=N, output_dir=OUTPUT_DIR

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
   - Use triage_pcap to get frame count, streams, expert findings, and stats

2. Narrow scope with validated filters:
   - Construct a display filter for the traffic of interest
   - ALWAYS validate: use validate_filter with detailed=true
   - DO NOT guess Wireshark display filter syntax

3. Slice the PCAP to isolate evidence:
   - Use slice_pcap with your validated filter
   - Verify the slice with triage_pcap on the output

4. Build the evidence bundle:
   - Use build_evidence with your validated filter
   - This produces conversations, endpoints, expert infos, protocol hierarchy

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
   - Use export_objects with protocol=http, action=list

2. Review the object list for interesting items:
   - Look at content types, sizes, filenames
   - Identify objects relevant to the investigation

3. Extract specific objects:
   - Use export_objects with action=extract and packet_num for individual objects
   - Or use action=extract without protocol for bulk file carving
   - Output must go to OUTPUT_DIR via output_dir parameter`,
				},
			}},
		}, nil
	})
}
