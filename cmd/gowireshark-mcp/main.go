package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	log.SetOutput(os.Stderr)
	log.SetFlags(0)

	srv := mcp.NewServer(&mcp.Implementation{Name: "gowireshark", Version: "1.0.0"}, nil)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_version",
		Description: "Get gowireshark version",
	}, handleVersion)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_filter_validate",
		Description: "Validate a Wireshark display filter expression",
	}, handleFilterValidate)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_filter_validate_detailed",
		Description: "Validate a display filter with detailed field feedback",
	}, handleFilterValidateDetailed)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_filter_suggest",
		Description: "Suggest filter field names by prefix",
	}, handleFilterSuggest)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_metadata_field",
		Description: "Get metadata information for a display filter field",
	}, handleMetadataField)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_frames_count",
		Description: "Count frames in a PCAP file, optionally filtered",
	}, handleFramesCount)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_frames_page",
		Description: "Get paginated frames from a PCAP file",
	}, handleFramesPage)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_frames_get",
		Description: "Get a single frame by its index number",
	}, handleFramesGet)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_frames_batch",
		Description: "Get multiple frames by their index numbers",
	}, handleFramesBatch)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_frames_hex",
		Description: "Get hex dump for a specific frame",
	}, handleFramesHex)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_frames_fields",
		Description: "Export selected fields from frames as JSONL",
	}, handleFramesFields)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_streams_list",
		Description: "List TCP/UDP streams in a PCAP file",
	}, handleStreamsList)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_conversations_list",
		Description: "List network conversations from a PCAP file",
	}, handleConversationsList)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_timeline_summary",
		Description: "Get traffic timeline summary from a PCAP file",
	}, handleTimelineSummary)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_files_list",
		Description: "List file objects detected in network traffic",
	}, handleFilesList)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_expert_list",
		Description: "Get expert info entries from a PCAP file",
	}, handleExpertList)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_follow_stream",
		Description: "Follow and reconstruct a TCP or UDP stream",
	}, handleFollowStream)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_slice_pcap",
		Description: "Slice a PCAP file by display filter or frame indices",
	}, handleSlicePcap)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_evidence_bundle",
		Description: "Build an evidence bundle for selected frames",
	}, handleEvidenceBundle)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_tap_conversations",
		Description: "Get conversation statistics via tap",
	}, handleTapConversations)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_tap_endpoints",
		Description: "Get endpoint statistics via tap",
	}, handleTapEndpoints)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_srt_list",
		Description: "Get service response time statistics for a protocol",
	}, handleSRTList)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_export_object_list",
		Description: "List export objects for a protocol",
	}, handleExportObjectList)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gowireshark_export_object_write",
		Description: "Write an export object to a file",
	}, handleExportObjectWrite)

	if err := srv.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}

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
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return 8 * 1024 * 1024
}

func validatePCAPPath(path string) error {
	if path == "" {
		return fmt.Errorf("file path is required")
	}
	dir := pcapDir()
	if dir == "" {
		return nil
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("cannot resolve path: %w", err)
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("cannot resolve pcap dir: %w", err)
	}
	rel, err := filepath.Rel(absDir, absPath)
	if err != nil || strings.HasPrefix(rel, "..") {
		return fmt.Errorf("pcap path %q is outside allowed directory %q", path, dir)
	}
	return nil
}

func validateOutputPath(path string) error {
	if path == "" {
		return nil
	}
	dir := outputDir()
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("cannot resolve path: %w", err)
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("cannot resolve output dir: %w", err)
	}
	rel, err := filepath.Rel(absDir, absPath)
	if err != nil || strings.HasPrefix(rel, "..") {
		return fmt.Errorf("output path %q is outside allowed directory %q", path, dir)
	}
	return nil
}

func runGowireshark(ctx context.Context, args ...string) (string, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, timeout())
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, gowiresharkBin(), args...)
	cmd.Stderr = os.Stderr

	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("command failed: %s", string(exitErr.Stderr))
		}
		return "", fmt.Errorf("command failed: %w", err)
	}

	if int64(len(output)) > maxOutputBytes() {
		output = output[:maxOutputBytes()]
	}

	var rawJSON any
	if err := json.Unmarshal(output, &rawJSON); err != nil {
		return string(output), nil
	}
	pretty, _ := json.MarshalIndent(rawJSON, "", "  ")
	return string(pretty), nil
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

type filterValidateIn struct {
	Expr string `json:"expr"`
}

func handleVersion(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
	text, err := runGowireshark(ctx, "version")
	if err != nil {
		return nil, nil, err
	}
	return textResult(text), nil, nil
}

func handleFilterValidate(ctx context.Context, _ *mcp.CallToolRequest, in filterValidateIn) (*mcp.CallToolResult, any, error) {
	text, err := runGowireshark(ctx, "filter", "validate", "--expr", in.Expr)
	if err != nil {
		return nil, nil, err
	}
	return textResult(text), nil, nil
}

type filterValidateDetailedIn struct {
	Expr string `json:"expr"`
}

func handleFilterValidateDetailed(ctx context.Context, _ *mcp.CallToolRequest, in filterValidateDetailedIn) (*mcp.CallToolResult, any, error) {
	text, err := runGowireshark(ctx, "filter", "validate-detailed", "--expr", in.Expr)
	if err != nil {
		return nil, nil, err
	}
	return textResult(text), nil, nil
}

type filterSuggestIn struct {
	Prefix string `json:"prefix"`
	Limit  int    `json:"limit,omitempty"`
}

func handleFilterSuggest(ctx context.Context, _ *mcp.CallToolRequest, in filterSuggestIn) (*mcp.CallToolResult, any, error) {
	limit := 50
	if in.Limit > 0 {
		limit = in.Limit
	}
	text, err := runGowireshark(ctx, "filter", "suggest", "--prefix", in.Prefix, "--limit", strconv.Itoa(limit))
	if err != nil {
		return nil, nil, err
	}
	return textResult(text), nil, nil
}

type metadataFieldIn struct {
	Name string `json:"name"`
}

func handleMetadataField(ctx context.Context, _ *mcp.CallToolRequest, in metadataFieldIn) (*mcp.CallToolResult, any, error) {
	text, err := runGowireshark(ctx, "metadata", "field", "--name", in.Name)
	if err != nil {
		return nil, nil, err
	}
	return textResult(text), nil, nil
}

type framesCountIn struct {
	File   string  `json:"file"`
	Filter *string `json:"filter,omitempty"`
}

func handleFramesCount(ctx context.Context, _ *mcp.CallToolRequest, in framesCountIn) (*mcp.CallToolResult, any, error) {
	if err := validatePCAPPath(in.File); err != nil {
		return nil, nil, err
	}
	text, err := runGowireshark(ctx, fileFilterCLI([]string{"frames", "count"}, in.File, in.Filter)...)
	if err != nil {
		return nil, nil, err
	}
	return textResult(text), nil, nil
}

type framesPageIn struct {
	File   string  `json:"file"`
	Filter *string `json:"filter,omitempty"`
	Page   int     `json:"page,omitempty"`
	Size   int     `json:"size,omitempty"`
}

func handleFramesPage(ctx context.Context, _ *mcp.CallToolRequest, in framesPageIn) (*mcp.CallToolResult, any, error) {
	if err := validatePCAPPath(in.File); err != nil {
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
	args := []string{"frames", "page", "--file", in.File, "--page", strconv.Itoa(page), "--size", strconv.Itoa(size)}
	if in.Filter != nil && *in.Filter != "" {
		args = append(args, "--filter", *in.Filter)
	}
	text, err := runGowireshark(ctx, args...)
	if err != nil {
		return nil, nil, err
	}
	return textResult(text), nil, nil
}

type framesGetIn struct {
	File  string `json:"file"`
	Index int    `json:"index"`
}

func handleFramesGet(ctx context.Context, _ *mcp.CallToolRequest, in framesGetIn) (*mcp.CallToolResult, any, error) {
	if err := validatePCAPPath(in.File); err != nil {
		return nil, nil, err
	}
	text, err := runGowireshark(ctx, "frames", "get", "--file", in.File, "--index", strconv.Itoa(in.Index))
	if err != nil {
		return nil, nil, err
	}
	return textResult(text), nil, nil
}

type framesBatchIn struct {
	File    string  `json:"file"`
	Indices string  `json:"indices"`
	Filter  *string `json:"filter,omitempty"`
}

func handleFramesBatch(ctx context.Context, _ *mcp.CallToolRequest, in framesBatchIn) (*mcp.CallToolResult, any, error) {
	if err := validatePCAPPath(in.File); err != nil {
		return nil, nil, err
	}
	args := []string{"frames", "batch", "--file", in.File, "--indices", in.Indices}
	if in.Filter != nil && *in.Filter != "" {
		args = append(args, "--filter", *in.Filter)
	}
	text, err := runGowireshark(ctx, args...)
	if err != nil {
		return nil, nil, err
	}
	return textResult(text), nil, nil
}

type framesHexIn struct {
	File  string `json:"file"`
	Index int    `json:"index"`
}

func handleFramesHex(ctx context.Context, _ *mcp.CallToolRequest, in framesHexIn) (*mcp.CallToolResult, any, error) {
	if err := validatePCAPPath(in.File); err != nil {
		return nil, nil, err
	}
	text, err := runGowireshark(ctx, "frames", "hex", "--file", in.File, "--index", strconv.Itoa(in.Index))
	if err != nil {
		return nil, nil, err
	}
	return textResult(text), nil, nil
}

type framesFieldsIn struct {
	File   string  `json:"file"`
	Fields string  `json:"fields"`
	Filter *string `json:"filter,omitempty"`
}

func handleFramesFields(ctx context.Context, _ *mcp.CallToolRequest, in framesFieldsIn) (*mcp.CallToolResult, any, error) {
	if err := validatePCAPPath(in.File); err != nil {
		return nil, nil, err
	}
	args := []string{"frames", "fields", "--file", in.File, "--fields", in.Fields}
	if in.Filter != nil && *in.Filter != "" {
		args = append(args, "--filter", *in.Filter)
	}
	text, err := runGowireshark(ctx, args...)
	if err != nil {
		return nil, nil, err
	}
	return textResult(text), nil, nil
}

type streamsListIn struct {
	File   string  `json:"file"`
	Filter *string `json:"filter,omitempty"`
}

func handleStreamsList(ctx context.Context, _ *mcp.CallToolRequest, in streamsListIn) (*mcp.CallToolResult, any, error) {
	if err := validatePCAPPath(in.File); err != nil {
		return nil, nil, err
	}
	text, err := runGowireshark(ctx, fileFilterCLI([]string{"streams", "list"}, in.File, in.Filter)...)
	if err != nil {
		return nil, nil, err
	}
	return textResult(text), nil, nil
}

type conversationsListIn struct {
	File   string  `json:"file"`
	Filter *string `json:"filter,omitempty"`
}

func handleConversationsList(ctx context.Context, _ *mcp.CallToolRequest, in conversationsListIn) (*mcp.CallToolResult, any, error) {
	if err := validatePCAPPath(in.File); err != nil {
		return nil, nil, err
	}
	text, err := runGowireshark(ctx, fileFilterCLI([]string{"traffic", "conversations", "list"}, in.File, in.Filter)...)
	if err != nil {
		return nil, nil, err
	}
	return textResult(text), nil, nil
}

type timelineSummaryIn struct {
	File   string  `json:"file"`
	Filter *string `json:"filter,omitempty"`
}

func handleTimelineSummary(ctx context.Context, _ *mcp.CallToolRequest, in timelineSummaryIn) (*mcp.CallToolResult, any, error) {
	if err := validatePCAPPath(in.File); err != nil {
		return nil, nil, err
	}
	text, err := runGowireshark(ctx, fileFilterCLI([]string{"traffic", "timeline", "summary"}, in.File, in.Filter)...)
	if err != nil {
		return nil, nil, err
	}
	return textResult(text), nil, nil
}

type filesListIn struct {
	File   string  `json:"file"`
	Filter *string `json:"filter,omitempty"`
}

func handleFilesList(ctx context.Context, _ *mcp.CallToolRequest, in filesListIn) (*mcp.CallToolResult, any, error) {
	if err := validatePCAPPath(in.File); err != nil {
		return nil, nil, err
	}
	text, err := runGowireshark(ctx, fileFilterCLI([]string{"traffic", "files", "list"}, in.File, in.Filter)...)
	if err != nil {
		return nil, nil, err
	}
	return textResult(text), nil, nil
}

type expertListIn struct {
	File   string  `json:"file"`
	Filter *string `json:"filter,omitempty"`
}

func handleExpertList(ctx context.Context, _ *mcp.CallToolRequest, in expertListIn) (*mcp.CallToolResult, any, error) {
	if err := validatePCAPPath(in.File); err != nil {
		return nil, nil, err
	}
	text, err := runGowireshark(ctx, fileFilterCLI([]string{"expert", "list"}, in.File, in.Filter)...)
	if err != nil {
		return nil, nil, err
	}
	return textResult(text), nil, nil
}

type followStreamIn struct {
	File     string  `json:"file"`
	Protocol *string `json:"protocol,omitempty"`
	Filter   *string `json:"filter,omitempty"`
}

func handleFollowStream(ctx context.Context, _ *mcp.CallToolRequest, in followStreamIn) (*mcp.CallToolResult, any, error) {
	if err := validatePCAPPath(in.File); err != nil {
		return nil, nil, err
	}
	proto := "tcp"
	if in.Protocol != nil && *in.Protocol != "" {
		proto = *in.Protocol
	}
	args := []string{"follow", "--file", in.File, "--protocol", proto}
	if in.Filter != nil && *in.Filter != "" {
		args = append(args, "--filter", *in.Filter)
	}
	text, err := runGowireshark(ctx, args...)
	if err != nil {
		return nil, nil, err
	}
	return textResult(text), nil, nil
}

type slicePcapIn struct {
	File    string  `json:"file"`
	Out     string  `json:"out"`
	Filter  *string `json:"filter,omitempty"`
	Indices *string `json:"indices,omitempty"`
}

func handleSlicePcap(ctx context.Context, _ *mcp.CallToolRequest, in slicePcapIn) (*mcp.CallToolResult, any, error) {
	if err := validatePCAPPath(in.File); err != nil {
		return nil, nil, err
	}
	if err := validateOutputPath(in.Out); err != nil {
		return nil, nil, err
	}
	args := []string{"slice", "pcap", "--file", in.File, "--out", in.Out}
	if in.Filter != nil && *in.Filter != "" {
		args = append(args, "--filter", *in.Filter)
	}
	if in.Indices != nil && *in.Indices != "" {
		args = append(args, "--indices", *in.Indices)
	}
	text, err := runGowireshark(ctx, args...)
	if err != nil {
		return nil, nil, err
	}
	return textResult(text), nil, nil
}

type evidenceBundleIn struct {
	File   string  `json:"file"`
	Filter *string `json:"filter,omitempty"`
}

func handleEvidenceBundle(ctx context.Context, _ *mcp.CallToolRequest, in evidenceBundleIn) (*mcp.CallToolResult, any, error) {
	if err := validatePCAPPath(in.File); err != nil {
		return nil, nil, err
	}
	text, err := runGowireshark(ctx, fileFilterCLI([]string{"evidence", "bundle"}, in.File, in.Filter)...)
	if err != nil {
		return nil, nil, err
	}
	return textResult(text), nil, nil
}

type tapConversationsIn struct {
	File   string  `json:"file"`
	Type   *string `json:"type,omitempty"`
	Filter *string `json:"filter,omitempty"`
}

func handleTapConversations(ctx context.Context, _ *mcp.CallToolRequest, in tapConversationsIn) (*mcp.CallToolResult, any, error) {
	if err := validatePCAPPath(in.File); err != nil {
		return nil, nil, err
	}
	convType := "tcp"
	if in.Type != nil && *in.Type != "" {
		convType = *in.Type
	}
	args := []string{"tap", "conversations", "--file", in.File, "--type", convType}
	if in.Filter != nil && *in.Filter != "" {
		args = append(args, "--filter", *in.Filter)
	}
	text, err := runGowireshark(ctx, args...)
	if err != nil {
		return nil, nil, err
	}
	return textResult(text), nil, nil
}

type tapEndpointsIn struct {
	File   string  `json:"file"`
	Type   *string `json:"type,omitempty"`
	Filter *string `json:"filter,omitempty"`
}

func handleTapEndpoints(ctx context.Context, _ *mcp.CallToolRequest, in tapEndpointsIn) (*mcp.CallToolResult, any, error) {
	if err := validatePCAPPath(in.File); err != nil {
		return nil, nil, err
	}
	epType := "ip"
	if in.Type != nil && *in.Type != "" {
		epType = *in.Type
	}
	args := []string{"tap", "endpoints", "--file", in.File, "--type", epType}
	if in.Filter != nil && *in.Filter != "" {
		args = append(args, "--filter", *in.Filter)
	}
	text, err := runGowireshark(ctx, args...)
	if err != nil {
		return nil, nil, err
	}
	return textResult(text), nil, nil
}

type srtListIn struct {
	File     string  `json:"file"`
	Protocol string  `json:"protocol"`
	Filter   *string `json:"filter,omitempty"`
}

func handleSRTList(ctx context.Context, _ *mcp.CallToolRequest, in srtListIn) (*mcp.CallToolResult, any, error) {
	if err := validatePCAPPath(in.File); err != nil {
		return nil, nil, err
	}
	args := []string{"srt", "list", "--file", in.File, "--protocol", in.Protocol}
	if in.Filter != nil && *in.Filter != "" {
		args = append(args, "--filter", *in.Filter)
	}
	text, err := runGowireshark(ctx, args...)
	if err != nil {
		return nil, nil, err
	}
	return textResult(text), nil, nil
}

type exportObjectListIn struct {
	File     string  `json:"file"`
	Protocol string  `json:"protocol"`
	Filter   *string `json:"filter,omitempty"`
}

func handleExportObjectList(ctx context.Context, _ *mcp.CallToolRequest, in exportObjectListIn) (*mcp.CallToolResult, any, error) {
	if err := validatePCAPPath(in.File); err != nil {
		return nil, nil, err
	}
	args := []string{"export-object", "list", "--file", in.File, "--protocol", in.Protocol}
	if in.Filter != nil && *in.Filter != "" {
		args = append(args, "--filter", *in.Filter)
	}
	text, err := runGowireshark(ctx, args...)
	if err != nil {
		return nil, nil, err
	}
	return textResult(text), nil, nil
}

type exportObjectWriteIn struct {
	File      string `json:"file"`
	Protocol  string `json:"protocol"`
	PacketNum int    `json:"packetNum"`
	Out       string `json:"out"`
}

func handleExportObjectWrite(ctx context.Context, _ *mcp.CallToolRequest, in exportObjectWriteIn) (*mcp.CallToolResult, any, error) {
	if err := validatePCAPPath(in.File); err != nil {
		return nil, nil, err
	}
	if err := validateOutputPath(in.Out); err != nil {
		return nil, nil, err
	}
	text, err := runGowireshark(ctx, "export-object", "write", "--file", in.File, "--protocol", in.Protocol, "--packet-num", strconv.Itoa(in.PacketNum), "--out", in.Out)
	if err != nil {
		return nil, nil, err
	}
	return textResult(text), nil, nil
}