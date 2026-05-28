package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const defaultMaxOutputBytes int64 = 8 * 1024 * 1024

func main() {
	log.SetOutput(os.Stderr)
	log.SetFlags(0)

	srv := newMCPServer()
	if err := srv.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}

func newMCPServer() *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{Name: "gowireshark", Version: "1.0.0"}, nil)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_version",
		Description: "Get gowireshark runtime version information",
	}, handleVersion)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_filter_validate",
		Description: "Validate a Wireshark display filter expression. Returns whether the filter syntax is valid.",
	}, handleFilterValidate)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_filter_validate_detailed",
		Description: "Validate a display filter with detailed field-level feedback including field types and valid operators",
	}, handleFilterValidateDetailed)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_filter_suggest",
		Description: "Suggest Wireshark display filter field names by prefix (e.g. 'tcp.' or 'ip.')",
	}, handleFilterSuggest)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_metadata_protocols",
		Description: "List all protocols supported by the Wireshark runtime",
	}, handleMetadataProtocols)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_metadata_fields",
		Description: "List all display filter fields supported by the Wireshark runtime",
	}, handleMetadataFields)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_metadata_field",
		Description: "Get detailed metadata for a specific display filter field (type, description, valid operators)",
	}, handleMetadataField)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_frames_count",
		Description: "Count frames in a PCAP file, optionally filtered by a display filter expression",
	}, handleFramesCount)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_frames_page",
		Description: "Get a paginated list of frames from a PCAP file. Use page>=1 and size>=1 for pagination.",
		InputSchema: toolInputSchema("gowireshark_frames_page"),
	}, handleFramesPage)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_frames_get",
		Description: "Get a single frame by its frame number (1-based index)",
		InputSchema: toolInputSchema("gowireshark_frames_get"),
	}, handleFramesGet)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_frames_batch",
		Description: "Get multiple frames by their frame numbers (comma-separated indices, e.g. '1,5,10')",
	}, handleFramesBatch)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_frames_hex",
		Description: "Get hex dump (raw bytes) for a specific frame by its frame number",
	}, handleFramesHex)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_frames_fields",
		Description: "Export selected display filter fields from frames as JSONL. Use Wireshark field names like 'ip.src','ip.dst','tcp.port'.",
	}, handleFramesFields)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_streams_list",
		Description: "List TCP and UDP streams in a PCAP file with stream IDs for follow operations",
	}, handleStreamsList)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_conversations_list",
		Description: "List network conversations (address pair exchanges) from a PCAP file",
	}, handleConversationsList)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_timeline_summary",
		Description: "Get traffic timeline summary (packet activity over time) from a PCAP file",
	}, handleTimelineSummary)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_files_list",
		Description: "List file objects detected in network traffic (e.g. HTTP downloads, SMB transfers)",
	}, handleFilesList)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_expert_list",
		Description: "Get expert analysis entries (anomalies, warnings, protocol violations) from a PCAP file",
	}, handleExpertList)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_follow_stream",
		Description: "Follow and reconstruct a TCP or UDP stream. Use protocol=tcp|udp with a stream filter like 'tcp.stream eq 0'.",
		InputSchema: toolInputSchema("gowireshark_follow_stream"),
	}, handleFollowStream)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_slice_pcap",
		Description: "Slice a PCAP file by display filter or frame indices into a new PCAP file. Output is written to GOWIRESHARK_OUTPUT_DIR.",
		InputSchema: toolInputSchema("gowireshark_slice_pcap"),
	}, handleSlicePcap)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_evidence_bundle",
		Description: "Build a comprehensive forensic evidence bundle including conversations, expert infos, and protocol hierarchy",
	}, handleEvidenceBundle)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_tap_conversations",
		Description: "Get conversation statistics via tap interface. Type: eth|ip|tcp|udp.",
		InputSchema: toolInputSchema("gowireshark_tap_conversations"),
	}, handleTapConversations)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_tap_endpoints",
		Description: "Get endpoint statistics via tap interface. Type: eth|ip|tcp|udp.",
		InputSchema: toolInputSchema("gowireshark_tap_endpoints"),
	}, handleTapEndpoints)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_srt_list",
		Description: "Get service response time statistics for a protocol (e.g. smb, dns, http)",
	}, handleSRTList)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_export_object_list",
		Description: "List exportable objects for a protocol (e.g. http objects like files, images)",
	}, handleExportObjectList)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_export_object_write",
		Description: "Write an export object to a file. Output is restricted to GOWIRESHARK_OUTPUT_DIR.",
		InputSchema: toolInputSchema("gowireshark_export_object_write"),
	}, handleExportObjectWrite)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_stats_summary",
		Description: "Get a comprehensive statistical summary of a PCAP file including protocol distribution, packet sizes, and timing",
		InputSchema: toolInputSchema("gowireshark_stats_summary"),
	}, handleStatsSummary)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_extract_files",
		Description: "Extract files and objects detected in network traffic to a local directory. Output is restricted to GOWIRESHARK_OUTPUT_DIR.",
		InputSchema: toolInputSchema("gowireshark_extract_files"),
	}, handleExtractFiles)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_doctor",
		Description: "Diagnose the gowireshark runtime environment: version, binary path, directories, environment variables",
	}, handleDoctor)

	registerResources(srv)
	registerPrompts(srv)

	return srv
}

func toolInputSchema(name string) map[string]any {
	file := map[string]any{"type": "string", "minLength": 1, "description": "PCAP path. Relative paths resolve under GOWIRESHARK_PCAP_DIR when set."}
	filter := map[string]any{"type": "string", "description": "Wireshark display filter expression."}
	out := map[string]any{"type": "string", "minLength": 1, "description": "Output path. Relative paths resolve under GOWIRESHARK_OUTPUT_DIR."}

	switch name {
	case "gowireshark_frames_page":
		return objectSchema([]string{"file"}, map[string]any{
			"file":   file,
			"filter": filter,
			"page":   map[string]any{"type": "integer", "minimum": 1, "default": 1},
			"size":   map[string]any{"type": "integer", "minimum": 1, "default": 20},
		})
	case "gowireshark_frames_get":
		return objectSchema([]string{"file", "index"}, map[string]any{
			"file":  file,
			"index": map[string]any{"type": "integer", "minimum": 1},
		})
	case "gowireshark_follow_stream":
		return objectSchema([]string{"file"}, map[string]any{
			"file":     file,
			"protocol": map[string]any{"type": "string", "enum": []string{"tcp", "udp"}, "default": "tcp"},
			"filter":   filter,
		})
	case "gowireshark_slice_pcap":
		return objectSchema([]string{"file", "out"}, map[string]any{
			"file":    file,
			"out":     out,
			"filter":  filter,
			"indices": map[string]any{"type": "string", "description": "Comma-separated frame numbers."},
		})
	case "gowireshark_tap_conversations":
		return objectSchema([]string{"file"}, map[string]any{
			"file":   file,
			"type":   map[string]any{"type": "string", "enum": []string{"eth", "ip", "tcp", "udp"}, "default": "tcp"},
			"filter": filter,
		})
	case "gowireshark_tap_endpoints":
		return objectSchema([]string{"file"}, map[string]any{
			"file":   file,
			"type":   map[string]any{"type": "string", "enum": []string{"eth", "ip", "tcp", "udp"}, "default": "ip"},
			"filter": filter,
		})
	case "gowireshark_export_object_write":
		return objectSchema([]string{"file", "protocol", "packetNum", "out"}, map[string]any{
			"file":      file,
			"protocol":  map[string]any{"type": "string", "minLength": 1},
			"packetNum": map[string]any{"type": "integer", "minimum": 1},
			"out":       out,
			"filter":    filter,
		})
	case "gowireshark_stats_summary":
		return objectSchema([]string{"file"}, map[string]any{
			"file":   file,
			"filter": filter,
		})
	case "gowireshark_extract_files":
		return objectSchema([]string{"file", "out"}, map[string]any{
			"file": file,
			"out":  out,
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

// --- Environment helpers ---

func gowiresharkBin() string {
	if v := os.Getenv("GOWIRESHARK_BIN"); v != "" {
		return v
	}
	return "gowireshark"
}

func pcapDir() string {
	return os.Getenv("GOWIRESHARK_PCAP_DIR")
}

func outputDir() string {
	if v := os.Getenv("GOWIRESHARK_OUTPUT_DIR"); v != "" {
		return v
	}
	return os.TempDir()
}

func timeout() time.Duration {
	if v := os.Getenv("GOWIRESHARK_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return 120 * time.Second
}

func maxOutputBytes() int64 {
	if v := os.Getenv("GOWIRESHARK_MAX_OUTPUT_BYTES"); v != "" {
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

type gowiresharkOutput struct {
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

func runGowireshark(ctx context.Context, args ...string) (*gowiresharkOutput, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, timeout())
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, gowiresharkBin(), args...)
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

	out := &gowiresharkOutput{
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

func (o *gowiresharkOutput) suggestTool(tool string) {
	o.SuggestedNextTool = tool
}

// --- Result builders ---

func buildResult(text string, out *gowiresharkOutput) *mcp.CallToolResult {
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

func parseOutput(out *gowiresharkOutput) map[string]any {
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
	out, err := runGowireshark(ctx, "version")
	if err != nil {
		return nil, nil, err
	}
	parsed := parseOutput(out)
	return buildResult(out.Text, out), parsed, nil
}

func handleFilterValidate(ctx context.Context, _ *mcp.CallToolRequest, in filterValidateIn) (*mcp.CallToolResult, map[string]any, error) {
	if in.Expr == "" {
		return nil, nil, fmt.Errorf("expr is required")
	}
	out, err := runGowireshark(ctx, "filter", "validate", "--expr", in.Expr)
	if err != nil {
		return nil, nil, err
	}
	parsed := parseOutput(out)
	return buildResult(out.Text, out), parsed, nil
}

func handleFilterValidateDetailed(ctx context.Context, _ *mcp.CallToolRequest, in filterValidateDetailedIn) (*mcp.CallToolResult, map[string]any, error) {
	if in.Expr == "" {
		return nil, nil, fmt.Errorf("expr is required")
	}
	out, err := runGowireshark(ctx, "filter", "validate-detailed", "--expr", in.Expr)
	if err != nil {
		return nil, nil, err
	}
	parsed := parseOutput(out)
	return buildResult(out.Text, out), parsed, nil
}

func handleFilterSuggest(ctx context.Context, _ *mcp.CallToolRequest, in filterSuggestIn) (*mcp.CallToolResult, map[string]any, error) {
	if in.Prefix == "" {
		return nil, nil, fmt.Errorf("prefix is required")
	}
	limit := 50
	if in.Limit > 0 {
		limit = in.Limit
	}
	out, err := runGowireshark(ctx, "filter", "suggest", "--prefix", in.Prefix, "--limit", strconv.Itoa(limit))
	if err != nil {
		return nil, nil, err
	}
	parsed := parseOutput(out)
	return buildResult(out.Text, out), parsed, nil
}

func handleMetadataProtocols(ctx context.Context, _ *mcp.CallToolRequest, _ emptyIn) (*mcp.CallToolResult, map[string]any, error) {
	out, err := runGowireshark(ctx, "metadata", "protocols")
	if err != nil {
		return nil, nil, err
	}
	parsed := parseOutput(out)
	return buildResult(out.Text, out), parsed, nil
}

func handleMetadataFields(ctx context.Context, _ *mcp.CallToolRequest, _ emptyIn) (*mcp.CallToolResult, map[string]any, error) {
	out, err := runGowireshark(ctx, "metadata", "fields")
	if err != nil {
		return nil, nil, err
	}
	out.suggestTool("gowireshark_filter_suggest")
	parsed := parseOutput(out)
	return buildResult(out.Text, out), parsed, nil
}

func handleMetadataField(ctx context.Context, _ *mcp.CallToolRequest, in metadataFieldIn) (*mcp.CallToolResult, map[string]any, error) {
	if in.Name == "" {
		return nil, nil, fmt.Errorf("name is required")
	}
	out, err := runGowireshark(ctx, "metadata", "field", "--name", in.Name)
	if err != nil {
		return nil, nil, err
	}
	parsed := parseOutput(out)
	return buildResult(out.Text, out), parsed, nil
}

func handleFramesCount(ctx context.Context, _ *mcp.CallToolRequest, in framesCountIn) (*mcp.CallToolResult, map[string]any, error) {
	file, err := resolvePCAPPath(in.File)
	if err != nil {
		return nil, nil, err
	}
	out, err := runGowireshark(ctx, fileFilterCLI([]string{"frames", "count"}, file, in.Filter)...)
	if err != nil {
		return nil, nil, err
	}
	out.suggestTool("gowireshark_streams_list")
	parsed := parseOutput(out)
	return buildResult(out.Text, out), parsed, nil
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
	out, err := runGowireshark(ctx, args...)
	if err != nil {
		return nil, nil, err
	}
	parsed := parseOutput(out)
	return buildResult(out.Text, out), parsed, nil
}

func handleFramesGet(ctx context.Context, _ *mcp.CallToolRequest, in framesGetIn) (*mcp.CallToolResult, map[string]any, error) {
	file, err := resolvePCAPPath(in.File)
	if err != nil {
		return nil, nil, err
	}
	if in.Index < 1 {
		return nil, nil, fmt.Errorf("index must be >= 1, got %d", in.Index)
	}
	out, err := runGowireshark(ctx, "frames", "get", "--file", file, "--index", strconv.Itoa(in.Index))
	if err != nil {
		return nil, nil, err
	}
	parsed := parseOutput(out)
	return buildResult(out.Text, out), parsed, nil
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
	out, err := runGowireshark(ctx, args...)
	if err != nil {
		return nil, nil, err
	}
	parsed := parseOutput(out)
	return buildResult(out.Text, out), parsed, nil
}

func handleFramesHex(ctx context.Context, _ *mcp.CallToolRequest, in framesHexIn) (*mcp.CallToolResult, map[string]any, error) {
	file, err := resolvePCAPPath(in.File)
	if err != nil {
		return nil, nil, err
	}
	if in.Index < 1 {
		return nil, nil, fmt.Errorf("index must be >= 1, got %d", in.Index)
	}
	out, err := runGowireshark(ctx, "frames", "hex", "--file", file, "--index", strconv.Itoa(in.Index))
	if err != nil {
		return nil, nil, err
	}
	parsed := parseOutput(out)
	return buildResult(out.Text, out), parsed, nil
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
	out, err := runGowireshark(ctx, args...)
	if err != nil {
		return nil, nil, err
	}
	parsed := parseOutput(out)
	return buildResult(out.Text, out), parsed, nil
}

func handleStreamsList(ctx context.Context, _ *mcp.CallToolRequest, in streamsListIn) (*mcp.CallToolResult, map[string]any, error) {
	file, err := resolvePCAPPath(in.File)
	if err != nil {
		return nil, nil, err
	}
	out, err := runGowireshark(ctx, fileFilterCLI([]string{"streams", "list"}, file, in.Filter)...)
	if err != nil {
		return nil, nil, err
	}
	parsed := parseOutput(out)
	return buildResult(out.Text, out), parsed, nil
}

func handleConversationsList(ctx context.Context, _ *mcp.CallToolRequest, in conversationsListIn) (*mcp.CallToolResult, map[string]any, error) {
	file, err := resolvePCAPPath(in.File)
	if err != nil {
		return nil, nil, err
	}
	out, err := runGowireshark(ctx, fileFilterCLI([]string{"traffic", "conversations", "list"}, file, in.Filter)...)
	if err != nil {
		return nil, nil, err
	}
	parsed := parseOutput(out)
	return buildResult(out.Text, out), parsed, nil
}

func handleTimelineSummary(ctx context.Context, _ *mcp.CallToolRequest, in timelineSummaryIn) (*mcp.CallToolResult, map[string]any, error) {
	file, err := resolvePCAPPath(in.File)
	if err != nil {
		return nil, nil, err
	}
	out, err := runGowireshark(ctx, fileFilterCLI([]string{"traffic", "timeline", "summary"}, file, in.Filter)...)
	if err != nil {
		return nil, nil, err
	}
	parsed := parseOutput(out)
	return buildResult(out.Text, out), parsed, nil
}

func handleFilesList(ctx context.Context, _ *mcp.CallToolRequest, in filesListIn) (*mcp.CallToolResult, map[string]any, error) {
	file, err := resolvePCAPPath(in.File)
	if err != nil {
		return nil, nil, err
	}
	out, err := runGowireshark(ctx, fileFilterCLI([]string{"traffic", "files", "list"}, file, in.Filter)...)
	if err != nil {
		return nil, nil, err
	}
	parsed := parseOutput(out)
	return buildResult(out.Text, out), parsed, nil
}

func handleExpertList(ctx context.Context, _ *mcp.CallToolRequest, in expertListIn) (*mcp.CallToolResult, map[string]any, error) {
	file, err := resolvePCAPPath(in.File)
	if err != nil {
		return nil, nil, err
	}
	out, err := runGowireshark(ctx, fileFilterCLI([]string{"expert", "list"}, file, in.Filter)...)
	if err != nil {
		return nil, nil, err
	}
	parsed := parseOutput(out)
	return buildResult(out.Text, out), parsed, nil
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
	out, err := runGowireshark(ctx, args...)
	if err != nil {
		return nil, nil, err
	}
	parsed := parseOutput(out)
	return buildResult(out.Text, out), parsed, nil
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
	out, err := runGowireshark(ctx, args...)
	if err != nil {
		return nil, nil, err
	}
	parsed := parseOutput(out)
	return buildResult(out.Text, out), parsed, nil
}

func handleEvidenceBundle(ctx context.Context, _ *mcp.CallToolRequest, in evidenceBundleIn) (*mcp.CallToolResult, map[string]any, error) {
	file, err := resolvePCAPPath(in.File)
	if err != nil {
		return nil, nil, err
	}
	out, err := runGowireshark(ctx, fileFilterCLI([]string{"evidence", "bundle"}, file, in.Filter)...)
	if err != nil {
		return nil, nil, err
	}
	out.suggestTool("gowireshark_slice_pcap")
	parsed := parseOutput(out)
	return buildResult(out.Text, out), parsed, nil
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
	out, err := runGowireshark(ctx, args...)
	if err != nil {
		return nil, nil, err
	}
	parsed := parseOutput(out)
	return buildResult(out.Text, out), parsed, nil
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
	out, err := runGowireshark(ctx, args...)
	if err != nil {
		return nil, nil, err
	}
	parsed := parseOutput(out)
	return buildResult(out.Text, out), parsed, nil
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
	out, err := runGowireshark(ctx, args...)
	if err != nil {
		return nil, nil, err
	}
	parsed := parseOutput(out)
	return buildResult(out.Text, out), parsed, nil
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
	out, err := runGowireshark(ctx, args...)
	if err != nil {
		return nil, nil, err
	}
	parsed := parseOutput(out)
	return buildResult(out.Text, out), parsed, nil
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
	out, err := runGowireshark(ctx, args...)
	if err != nil {
		return nil, nil, err
	}
	parsed := parseOutput(out)
	return buildResult(out.Text, out), parsed, nil
}

func handleStatsSummary(ctx context.Context, _ *mcp.CallToolRequest, in statsSummaryIn) (*mcp.CallToolResult, map[string]any, error) {
	file, err := resolvePCAPPath(in.File)
	if err != nil {
		return nil, nil, err
	}
	out, err := runGowireshark(ctx, fileFilterCLI([]string{"stats"}, file, in.Filter)...)
	if err != nil {
		return nil, nil, err
	}
	out.suggestTool("gowireshark_evidence_bundle")
	parsed := parseOutput(out)
	return buildResult(out.Text, out), parsed, nil
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
	out, err := runGowireshark(ctx, "extract", "--file", file, "--out", outPath)
	if err != nil {
		return nil, nil, err
	}
	parsed := parseOutput(out)
	return buildResult(out.Text, out), parsed, nil
}

func handleDoctor(ctx context.Context, _ *mcp.CallToolRequest, _ doctorIn) (*mcp.CallToolResult, map[string]any, error) {
	bin := gowiresharkBin()
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
		"gowiresharkPcapDir":        os.Getenv("GOWIRESHARK_PCAP_DIR"),
		"gowiresharkOutputDir":      os.Getenv("GOWIRESHARK_OUTPUT_DIR"),
		"gowiresharkTimeout":        os.Getenv("GOWIRESHARK_TIMEOUT"),
		"gowiresharkMaxOutputBytes": os.Getenv("GOWIRESHARK_MAX_OUTPUT_BYTES"),
	}

	verOut, verErr := runGowireshark(ctx, "version")
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
	return textResult(string(text)), result, nil
}

// --- Resources ---

func registerResources(srv *mcp.Server) {
	srv.AddResource(&mcp.Resource{
		URI:         "gowireshark://pcaps",
		Name:        "Available PCAPs",
		Description: "Lists PCAP files in the allowed GOWIRESHARK_PCAP_DIR directory",
		MIMEType:    "application/json",
	}, func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		dir := pcapDir()
		if dir == "" {
			return &mcp.ReadResourceResult{
				Contents: []*mcp.ResourceContents{{
					URI:      "gowireshark://pcaps",
					MIMEType: "application/json",
					Text:     `{"pcaps":[],"error":"GOWIRESHARK_PCAP_DIR not set"}`,
				}},
			}, nil
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return &mcp.ReadResourceResult{
				Contents: []*mcp.ResourceContents{{
					URI:      "gowireshark://pcaps",
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
				URI:      "gowireshark://pcaps",
				MIMEType: "application/json",
				Text:     string(data),
			}},
		}, nil
	})

	srv.AddResource(&mcp.Resource{
		URI:         "gowireshark://outputs",
		Name:        "Output files",
		Description: "Lists files in the allowed GOWIRESHARK_OUTPUT_DIR directory",
		MIMEType:    "application/json",
	}, func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		dir := outputDir()
		entries, err := os.ReadDir(dir)
		if err != nil {
			return &mcp.ReadResourceResult{
				Contents: []*mcp.ResourceContents{{
					URI:      "gowireshark://outputs",
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
				URI:      "gowireshark://outputs",
				MIMEType: "application/json",
				Text:     string(data),
			}},
		}, nil
	})

	srv.AddResource(&mcp.Resource{
		URI:         "gowireshark://docs/cli-reference",
		Name:        "CLI Reference",
		Description: "Built-in gowireshark CLI command reference for agent workflows",
		MIMEType:    "text/markdown",
	}, func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		ref := cliReferenceMarkdown()
		return &mcp.ReadResourceResult{
			Contents: []*mcp.ResourceContents{{
				URI:      "gowireshark://docs/cli-reference",
				MIMEType: "text/markdown",
				Text:     ref,
			}},
		}, nil
	})

	srv.AddResourceTemplate(&mcp.ResourceTemplate{
		URITemplate: "gowireshark://pcap/{name}/summary",
		Name:        "PCAP Summary",
		Description: "Lightweight summary (frame count, streams, expert infos) for a named PCAP file in GOWIRESHARK_PCAP_DIR",
		MIMEType:    "application/json",
	}, func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		return pcapSummaryResource(ctx, req.Params.URI)
	})
}

func pcapSummaryResource(ctx context.Context, uri string) (*mcp.ReadResourceResult, error) {
	const prefix = "gowireshark://pcap/"
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
	if countOut, err := runGowireshark(ctx, "frames", "count", "--file", file); err != nil {
		summary["frameCountError"] = err.Error()
	} else if parsed := parseOutput(countOut); parsed != nil {
		summary["frameCount"] = parsed["count"]
	}
	if streamsOut, err := runGowireshark(ctx, "streams", "list", "--file", file); err != nil {
		summary["streamsError"] = err.Error()
	} else if parsed := parseOutput(streamsOut); parsed != nil {
		summary["streamsCount"] = listLen(parsed["list"])
	}
	if expertOut, err := runGowireshark(ctx, "expert", "list", "--file", file); err != nil {
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
		filepath.Join(".codex", "skills", "gowireshark", "references", "cli-reference.md"),
		filepath.Join("agents", "pcap-analysis-rules.md"),
	}
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(exeDir, "..", ".codex", "skills", "gowireshark", "references", "cli-reference.md"),
			filepath.Join(exeDir, "..", "agents", "pcap-analysis-rules.md"),
		)
	}
	for _, candidate := range candidates {
		data, err := os.ReadFile(candidate)
		if err == nil {
			return string(data)
		}
	}
	return `# gowireshark CLI Reference

## System & Discovery

` + "`" + "`" + "`" + `bash
gowireshark version
gowireshark filter validate --expr 'tcp.port == 80'
gowireshark filter validate-detailed --expr 'tcp.stream'
gowireshark filter suggest --prefix 'tcp.'
gowireshark metadata protocols
gowireshark metadata fields
gowireshark metadata field --name tcp.stream
` + "`" + "`" + "`" + `

## Frame Inspection

` + "`" + "`" + "`" + `bash
gowireshark frames count --file capture.pcap --filter 'tcp'
gowireshark frames page --file capture.pcap --page 1 --size 20 --filter 'http'
gowireshark frames get --file capture.pcap --index 5
gowireshark frames batch --file capture.pcap --indices 1,5,10
gowireshark frames hex --file capture.pcap --index 5
gowireshark frames write --file capture.pcap --fields frame.number,ip.src,ip.dst,frame.protocols --out frames.jsonl
gowireshark frames fields --file capture.pcap --fields ip.src,ip.dst,tcp.port
` + "`" + "`" + "`" + `

## Traffic Analysis

` + "`" + "`" + "`" + `bash
gowireshark streams list --file capture.pcap --filter 'tcp'
gowireshark traffic conversations list --file capture.pcap --filter 'dns'
gowireshark traffic timeline summary --file capture.pcap
gowireshark traffic files list --file capture.pcap
` + "`" + "`" + "`" + `

## Stream Reassembly

` + "`" + "`" + "`" + `bash
gowireshark follow --file capture.pcap --protocol tcp --filter 'tcp.stream eq 3'
gowireshark follow --file capture.pcap --protocol udp --filter 'udp.stream eq 1'
` + "`" + "`" + "`" + `

## Expert & Evidence

` + "`" + "`" + "`" + `bash
gowireshark expert list --file capture.pcap --filter 'tcp'
gowireshark slice pcap --file capture.pcap --filter 'tcp.port == 443' --out tls.pcap
gowireshark slice pcap --file capture.pcap --indices 1,5,9 --out selected.pcap
gowireshark evidence bundle --file capture.pcap --filter 'tcp.port == 80'
` + "`" + "`" + "`" + `

## Tap & SRT

` + "`" + "`" + "`" + `bash
gowireshark tap conversations --file capture.pcap --type tcp --filter 'tcp'
gowireshark tap endpoints --file capture.pcap --type ip
gowireshark srt list --file capture.pcap --protocol smb
gowireshark srt list --file capture.pcap --protocol dns
` + "`" + "`" + "`" + `

## Export Objects

` + "`" + "`" + "`" + `bash
gowireshark export-object list --file capture.pcap --protocol http
gowireshark export-object write --file capture.pcap --protocol http --packet-num 42 --out extracted.dat
` + "`" + "`" + "`" + `

## Stats & Extract

` + "`" + "`" + "`" + `bash
gowireshark stats --file capture.pcap --filter 'tcp'
gowireshark extract --file capture.pcap --out extracted-files/
` + "`" + "`" + "`" + `

## Guidance

- Use ` + "`" + `frames page` + "`" + ` as the default inspection command for large pcaps.
- ` + "`" + `streams list` + "`" + ` reveals followable streams (look for ` + "`" + `streamId >= 0` + "`" + `).
- ` + "`" + `follow` + "`" + ` expects a Wireshark display filter (e.g. ` + "`" + `tcp.stream eq 0` + "`" + `).
- ` + "`" + `slice pcap` + "`" + ` creates a new pcap from selected frames.
- ` + "`" + `evidence bundle` + "`" + ` produces comprehensive forensic metadata.
- ` + "`" + `export-object write` + "`" + ` extracts HTTP objects to disk.
- Always validate new display filters with ` + "`" + `gowireshark filter validate-detailed` + "`" + ` before using them.
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
   - Use gowireshark_frames_count to count frames

2. Map the traffic structure:
   - Use gowireshark_streams_list to see TCP/UDP streams

3. Check for anomalies:
   - Use gowireshark_expert_list to find protocol violations, warnings

4. Get protocol distribution:
   - Use gowireshark_stats_summary for a statistical overview

5. Summarize your findings: protocol distribution, stream count, notable anomalies.

IMPORTANT: Do NOT dump all frames. Use paginated frame inspection (gowireshark_frames_page) only when you need to inspect specific packets.`,
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
   - Use gowireshark_streams_list to list all streams
   - Note: only follow streams where streamId >= 0

2. Follow the stream to get reassembled payload:
   - Use gowireshark_follow_stream with protocol=tcp|udp and filter='tcp.stream eq N'

3. Inspect key frames in the stream:
   - Use gowireshark_frames_page with filter='tcp.stream eq N'
   - Look at frame content using gowireshark_frames_get

4. Check for any objects embedded in the stream:
   - Use gowireshark_export_object_list with protocol=http (if HTTP)

5. If HTTP objects found, extract relevant ones:
   - Use gowireshark_export_object_write

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
   - Use gowireshark_frames_count, gowireshark_streams_list, gowireshark_expert_list
   - Use gowireshark_stats_summary for statistical overview

2. Narrow scope with validated filters:
   - Construct a display filter for the traffic of interest
   - ALWAYS validate: use gowireshark_filter_validate_detailed with your filter expression
   - DO NOT guess Wireshark display filter syntax

3. Slice the PCAP to isolate evidence:
   - Use gowireshark_slice_pcap with your validated filter
   - Verify the slice with gowireshark_frames_count on the output

4. Build the evidence bundle:
   - Use gowireshark_evidence_bundle with your validated filter
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
   - Use gowireshark_export_object_list with protocol=http

2. Review the object list for interesting items:
   - Look at content types, sizes, filenames
   - Identify objects relevant to the investigation

3. Extract specific objects:
   - Use gowireshark_export_object_write for each interesting object
   - Provide the packetNum (packet number) for each object to extract
   - Output must go to GOWIRESHARK_OUTPUT_DIR

4. For bulk extraction of all detected files:
   - Use gowireshark_extract_files with the out directory

5. Report what was extracted: object types, filenames, sizes, and where they were saved.`,
				},
			}},
		}, nil
	})
}
