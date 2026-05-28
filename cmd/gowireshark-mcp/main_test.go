package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestValidateProtocol(t *testing.T) {
	tests := []struct {
		protocol string
		allowed  []string
		wantErr  bool
	}{
		{"tcp", []string{"tcp", "udp"}, false},
		{"udp", []string{"tcp", "udp"}, false},
		{"http", []string{"tcp", "udp"}, true},
		{"", []string{"tcp", "udp"}, true},
	}
	for _, tt := range tests {
		err := validateProtocol(tt.protocol, tt.allowed...)
		if (err != nil) != tt.wantErr {
			t.Errorf("validateProtocol(%q, %v) error = %v, wantErr = %v", tt.protocol, tt.allowed, err, tt.wantErr)
		}
	}
}

func TestValidateTapType(t *testing.T) {
	tests := []struct {
		tapType string
		allowed []string
		wantErr bool
	}{
		{"eth", []string{"eth", "ip", "tcp", "udp"}, false},
		{"ip", []string{"eth", "ip", "tcp", "udp"}, false},
		{"tcp", []string{"eth", "ip", "tcp", "udp"}, false},
		{"udp", []string{"eth", "ip", "tcp", "udp"}, false},
		{"http", []string{"eth", "ip", "tcp", "udp"}, true},
		{"", []string{"eth", "ip", "tcp", "udp"}, true},
	}
	for _, tt := range tests {
		err := validateTapType(tt.tapType, tt.allowed...)
		if (err != nil) != tt.wantErr {
			t.Errorf("validateTapType(%q, %v) error = %v, wantErr = %v", tt.tapType, tt.allowed, err, tt.wantErr)
		}
	}
}

func TestValidatePCAPPath(t *testing.T) {
	originalDir := os.Getenv("GOWIRESHARK_PCAP_DIR")
	defer os.Setenv("GOWIRESHARK_PCAP_DIR", originalDir)

	tmpDir := t.TempDir()
	os.Setenv("GOWIRESHARK_PCAP_DIR", tmpDir)

	if err := os.WriteFile(filepath.Join(tmpDir, "test.pcap"), []byte("dummy"), 0644); err != nil {
		t.Fatalf("create test pcap: %v", err)
	}

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"empty path", "", true},
		{"valid path", filepath.Join(tmpDir, "test.pcap"), false},
		{"outside path", "/etc/passwd", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePCAPPath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("validatePCAPPath(%q) error = %v, wantErr = %v", tt.path, err, tt.wantErr)
			}
		})
	}

	os.Unsetenv("GOWIRESHARK_PCAP_DIR")
	if err := validatePCAPPath(filepath.Join(tmpDir, "test.pcap")); err != nil {
		t.Errorf("validatePCAPPath with no GOWIRESHARK_PCAP_DIR should allow any path: %v", err)
	}
}

func TestResolvePCAPPathRelativeAndTraversal(t *testing.T) {
	originalDir := os.Getenv("GOWIRESHARK_PCAP_DIR")
	defer os.Setenv("GOWIRESHARK_PCAP_DIR", originalDir)

	tmpDir := t.TempDir()
	os.Setenv("GOWIRESHARK_PCAP_DIR", tmpDir)

	got, err := resolvePCAPPath("test.pcap")
	if err != nil {
		t.Fatalf("resolve relative pcap: %v", err)
	}
	want := filepath.Join(tmpDir, "test.pcap")
	if got != want {
		t.Fatalf("resolved pcap = %q, want %q", got, want)
	}
	if _, err := resolvePCAPPath("../outside.pcap"); err == nil {
		t.Fatal("resolvePCAPPath should reject parent traversal")
	}

	hiddenDir := filepath.Join(tmpDir, "..hidden")
	if err := os.Mkdir(hiddenDir, 0755); err != nil {
		t.Fatalf("mkdir ..hidden: %v", err)
	}
	if _, err := resolvePCAPPath(filepath.Join("..hidden", "inside.pcap")); err != nil {
		t.Fatalf("..hidden under allowed dir should be accepted: %v", err)
	}
}

func TestValidateOutputPath(t *testing.T) {
	originalDir := os.Getenv("GOWIRESHARK_OUTPUT_DIR")
	defer os.Setenv("GOWIRESHARK_OUTPUT_DIR", originalDir)

	tmpDir := t.TempDir()
	os.Setenv("GOWIRESHARK_OUTPUT_DIR", tmpDir)

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"empty path", "", false},
		{"valid path", filepath.Join(tmpDir, "out.pcap"), false},
		{"outside path", "/tmp/out.pcap", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateOutputPath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateOutputPath(%q) error = %v, wantErr = %v", tt.path, err, tt.wantErr)
			}
		})
	}
}

func TestResolveOutputPathRelativeAndSymlinkEscape(t *testing.T) {
	originalDir := os.Getenv("GOWIRESHARK_OUTPUT_DIR")
	defer os.Setenv("GOWIRESHARK_OUTPUT_DIR", originalDir)

	tmpDir := t.TempDir()
	os.Setenv("GOWIRESHARK_OUTPUT_DIR", tmpDir)

	got, err := resolveOutputPath("evidence.pcap")
	if err != nil {
		t.Fatalf("resolve relative output: %v", err)
	}
	want := filepath.Join(tmpDir, "evidence.pcap")
	if got != want {
		t.Fatalf("resolved output = %q, want %q", got, want)
	}
	if _, err := resolveOutputPath("../outside.pcap"); err == nil {
		t.Fatal("resolveOutputPath should reject parent traversal")
	}

	if runtime.GOOS == "windows" {
		t.Skip("symlink permissions vary on Windows")
	}
	outside := t.TempDir()
	link := filepath.Join(tmpDir, "link")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := resolveOutputPath(filepath.Join("link", "escaped.pcap")); err == nil {
		t.Fatal("resolveOutputPath should reject symlink escape")
	}
}

func TestToolRegistration(t *testing.T) {
	toolNames := []string{
		"gowireshark_get_version",
		"gowireshark_validate_filter",
		"gowireshark_suggest_filter",
		"gowireshark_list_protocols",
		"gowireshark_list_fields",
		"gowireshark_get_field_info",
		"gowireshark_count_frames",
		"gowireshark_list_frames",
		"gowireshark_get_frame",
		"gowireshark_get_frames_batch",
		"gowireshark_get_frame_hex",
		"gowireshark_get_frame_fields",
		"gowireshark_list_streams",
		"gowireshark_list_conversations",
		"gowireshark_get_timeline_summary",
		"gowireshark_list_files",
		"gowireshark_list_expert_findings",
		"gowireshark_follow_stream",
		"gowireshark_create_pcap_slice",
		"gowireshark_create_evidence_bundle",
		"gowireshark_verify_zeek_alert",
		"gowireshark_list_tap_conversations",
		"gowireshark_list_tap_endpoints",
		"gowireshark_list_service_response_times",
		"gowireshark_list_exportable_objects",
		"gowireshark_write_exported_object",
		"gowireshark_get_stats_summary",
		"gowireshark_extract_files",
		"gowireshark_health_check",
	}

	seen := make(map[string]bool)
	for _, name := range toolNames {
		if seen[name] {
			t.Errorf("duplicate tool name: %s", name)
		}
		seen[name] = true
		if !strings.HasPrefix(name, "gowireshark_") {
			t.Errorf("tool %s should have gowireshark_ prefix", name)
		}
	}

	expectedNewTools := []string{
		"gowireshark_list_protocols",
		"gowireshark_list_fields",
		"gowireshark_get_stats_summary",
		"gowireshark_extract_files",
		"gowireshark_health_check",
		"gowireshark_verify_zeek_alert",
	}
	for _, name := range expectedNewTools {
		if !seen[name] {
			t.Errorf("expected new tool %s not found", name)
		}
	}
}

func TestExportObjectWriteHasFilter(t *testing.T) {
	in := exportObjectWriteIn{
		File:      "test.pcap",
		Protocol:  "http",
		PacketNum: 42,
		Out:       "/tmp/out.dat",
		Filter:    strPtr("tcp.port == 80"),
	}
	if in.Filter == nil || *in.Filter != "tcp.port == 80" {
		t.Error("exportObjectWriteIn should have filter field")
	}
}

func strPtr(s string) *string {
	return &s
}

func TestTruncationMetadata(t *testing.T) {
	text := "test output"
	text = text + "\n\n[output truncated: 1024/2048 bytes, max=1024]"

	out := &gowiresharkOutput{
		Text:              text,
		Truncated:         true,
		MaxOutputBytes:    1024,
		OriginalBytes:     2048,
		SuggestedNextTool: "gowireshark_create_pcap_slice",
	}

	result := buildResult(out.Text, out)
	if result.StructuredContent != nil {
		t.Error("truncated output metadata should not use StructuredContent")
	}

	if result.Meta == nil {
		t.Fatal("truncated output should have result Meta")
	}
	if result.Meta["truncated"] != true {
		t.Error("Meta.truncated should be true")
	}
	if result.Meta["maxOutputBytes"] != int64(1024) {
		t.Errorf("Meta.maxOutputBytes = %v, want 1024", result.Meta["maxOutputBytes"])
	}
	if result.Meta["originalBytes"] != int64(2048) {
		t.Errorf("Meta.originalBytes = %v, want 2048", result.Meta["originalBytes"])
	}
	if result.Meta["suggestedNextTool"] != "gowireshark_create_pcap_slice" {
		t.Errorf("Meta.suggestedNextTool = %v, want gowireshark_create_pcap_slice", result.Meta["suggestedNextTool"])
	}

	if !strings.Contains(out.Text, "truncated") {
		t.Error("truncated output Text should contain truncation info")
	}
}

func TestNonTruncatedOutputNoMeta(t *testing.T) {
	out := &gowiresharkOutput{
		Text:           "test output",
		Truncated:      false,
		MaxOutputBytes: 1024,
		OriginalBytes:  512,
	}

	result := buildResult(out.Text, out)
	if result.StructuredContent != nil {
		t.Error("non-truncated output should not have StructuredContent")
	}
}

func TestParseOutputNonTruncated(t *testing.T) {
	out := &gowiresharkOutput{
		Raw:       []byte(`{"count":3}`),
		Truncated: false,
	}
	parsed := parseOutput(out)
	if parsed["count"].(float64) != 3 {
		t.Fatalf("count = %v, want 3", parsed["count"])
	}
}

func TestInputValidation(t *testing.T) {
	tmpDir := t.TempDir()
	originalDir := os.Getenv("GOWIRESHARK_OUTPUT_DIR")
	os.Setenv("GOWIRESHARK_OUTPUT_DIR", tmpDir)
	defer os.Setenv("GOWIRESHARK_OUTPUT_DIR", originalDir)

	originalPcapDir := os.Getenv("GOWIRESHARK_PCAP_DIR")
	os.Setenv("GOWIRESHARK_PCAP_DIR", tmpDir)
	defer os.Setenv("GOWIRESHARK_PCAP_DIR", originalPcapDir)

	tests := []struct {
		name    string
		err     error
		wantErr bool
	}{
		{"nil error", nil, false},
		{"empty file", validatePCAPPath(""), true},
		{"empty protocol", validateProtocol("", "tcp", "udp"), true},
		{"valid protocol", validateProtocol("tcp", "tcp", "udp"), false},
		{"empty output path in slice", validateOutputPath(""), false},
		{"outside output path", validateOutputPath("/etc/shadow"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if (tt.err != nil) != tt.wantErr {
				t.Errorf("%s: error = %v, wantErr = %v", tt.name, tt.err, tt.wantErr)
			}
		})
	}
}

func TestExportObjectWriteFilterPassthrough(t *testing.T) {
	in := exportObjectWriteIn{
		File:      "test.pcap",
		Protocol:  "http",
		PacketNum: 42,
		Out:       "/tmp/out.dat",
	}
	if in.Filter != nil {
		t.Error("Filter should default to nil (optional)")
	}

	in2 := exportObjectWriteIn{
		File:      "test.pcap",
		Protocol:  "http",
		PacketNum: 42,
		Out:       "/tmp/out.dat",
		Filter:    strPtr("tcp"),
	}
	if in2.Filter == nil || *in2.Filter != "tcp" {
		t.Error("Filter should be passed through when set")
	}
}

func TestPageSizeValidation(t *testing.T) {
	in := framesPageIn{Page: 0, Size: 0}
	if in.Page < 1 {
		in.Page = 1
	}
	if in.Size < 1 {
		in.Size = 20
	}
	if in.Page != 1 {
		t.Errorf("Page should default to 1, got %d", in.Page)
	}
	if in.Size != 20 {
		t.Errorf("Size should default to 20, got %d", in.Size)
	}
}

func TestPromptNames(t *testing.T) {
	prompts := []string{
		"pcap_triage",
		"stream_deep_dive",
		"evidence_bundle_workflow",
		"extract_http_objects",
	}
	for _, name := range prompts {
		if name == "" {
			t.Error("prompt name should not be empty")
		}
	}
}

func TestResourceURIs(t *testing.T) {
	resources := []string{
		"gowireshark://pcaps",
		"gowireshark://outputs",
		"gowireshark://docs/cli-reference",
	}
	for _, uri := range resources {
		if uri == "" {
			t.Error("resource URI should not be empty")
		}
		if !strings.HasPrefix(uri, "gowireshark://") {
			t.Errorf("resource URI %s should have gowireshark:// prefix", uri)
		}
	}
}

func TestResourceTemplateURI(t *testing.T) {
	template := "gowireshark://pcap/{name}/summary"
	if !strings.Contains(template, "{name}") {
		t.Error("resource template should contain {name} variable")
	}
	if !strings.HasPrefix(template, "gowireshark://") {
		t.Error("resource template should have gowireshark:// prefix")
	}
}

func TestResourcePCAPsReturnToolReadyPaths(t *testing.T) {
	originalDir := os.Getenv("GOWIRESHARK_PCAP_DIR")
	defer os.Setenv("GOWIRESHARK_PCAP_DIR", originalDir)

	tmpDir := t.TempDir()
	os.Setenv("GOWIRESHARK_PCAP_DIR", tmpDir)
	if err := os.WriteFile(filepath.Join(tmpDir, "sample.pcap"), []byte("pcap"), 0644); err != nil {
		t.Fatalf("write sample pcap: %v", err)
	}

	cs, closeFn := startMCPTestSession(t)
	defer closeFn()

	res, err := cs.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: "gowireshark://pcaps"})
	if err != nil {
		t.Fatalf("ReadResource(pcaps): %v", err)
	}
	var body map[string]any
	decodeResourceText(t, res, &body)
	pcaps := body["pcaps"].([]any)
	if len(pcaps) != 1 {
		t.Fatalf("pcaps length = %d, want 1", len(pcaps))
	}
	pcap := pcaps[0].(map[string]any)
	if pcap["path"] != filepath.Join(tmpDir, "sample.pcap") {
		t.Fatalf("pcap path = %v, want %s", pcap["path"], filepath.Join(tmpDir, "sample.pcap"))
	}
}

func TestResourceOutputsReturnToolReadyPaths(t *testing.T) {
	originalDir := os.Getenv("GOWIRESHARK_OUTPUT_DIR")
	defer os.Setenv("GOWIRESHARK_OUTPUT_DIR", originalDir)

	tmpDir := t.TempDir()
	os.Setenv("GOWIRESHARK_OUTPUT_DIR", tmpDir)
	if err := os.WriteFile(filepath.Join(tmpDir, "evidence.pcap"), []byte("pcap"), 0644); err != nil {
		t.Fatalf("write output file: %v", err)
	}

	cs, closeFn := startMCPTestSession(t)
	defer closeFn()

	res, err := cs.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: "gowireshark://outputs"})
	if err != nil {
		t.Fatalf("ReadResource(outputs): %v", err)
	}
	var body map[string]any
	decodeResourceText(t, res, &body)
	outputs := body["outputs"].([]any)
	if len(outputs) != 1 {
		t.Fatalf("outputs length = %d, want 1", len(outputs))
	}
	output := outputs[0].(map[string]any)
	if output["path"] != filepath.Join(tmpDir, "evidence.pcap") {
		t.Fatalf("output path = %v, want %s", output["path"], filepath.Join(tmpDir, "evidence.pcap"))
	}
}

func TestPCAPSummaryResourceUsesRuntime(t *testing.T) {
	originalPcapDir := os.Getenv("GOWIRESHARK_PCAP_DIR")
	originalBin := os.Getenv("GOWIRESHARK_BIN")
	defer os.Setenv("GOWIRESHARK_PCAP_DIR", originalPcapDir)
	defer os.Setenv("GOWIRESHARK_BIN", originalBin)

	tmpDir := t.TempDir()
	os.Setenv("GOWIRESHARK_PCAP_DIR", tmpDir)
	if err := os.WriteFile(filepath.Join(tmpDir, "sample.pcap"), []byte("pcap"), 0644); err != nil {
		t.Fatalf("write sample pcap: %v", err)
	}
	fakeBin := filepath.Join(tmpDir, "fake-gowireshark")
	script := `#!/bin/sh
case "$1 $2" in
  "frames count") echo '{"count":7}' ;;
  "streams list") echo '{"list":[{},{}]}' ;;
  "expert list") echo '{"list":[{}]}' ;;
  *) echo '{"ok":true}' ;;
esac
`
	if err := os.WriteFile(fakeBin, []byte(script), 0755); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}
	os.Setenv("GOWIRESHARK_BIN", fakeBin)

	res, err := pcapSummaryResource(context.Background(), "gowireshark://pcap/sample.pcap/summary")
	if err != nil {
		t.Fatalf("pcapSummaryResource: %v", err)
	}
	var body map[string]any
	decodeResourceText(t, res, &body)
	if body["frameCount"].(float64) != 7 {
		t.Fatalf("frameCount = %v, want 7", body["frameCount"])
	}
	if body["streamsCount"].(float64) != 2 {
		t.Fatalf("streamsCount = %v, want 2", body["streamsCount"])
	}
	if body["expertCount"].(float64) != 1 {
		t.Fatalf("expertCount = %v, want 1", body["expertCount"])
	}
}

func TestToolSchemasAdvertiseConstraints(t *testing.T) {
	cs, closeFn := startMCPTestSession(t)
	defer closeFn()

	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	tools := map[string]*mcp.Tool{}
	for _, tool := range res.Tools {
		tools[tool.Name] = tool
	}
	for _, name := range []string{
		"gowireshark_count_frames",
		"gowireshark_list_frames",
		"gowireshark_get_frame",
		"gowireshark_health_check",
		"gowireshark_verify_zeek_alert",
	} {
		if tools[name] == nil {
			t.Fatalf("expected renamed tool %s to be listed", name)
		}
	}
	for _, old := range []string{
		"gowireshark_frames_count",
		"gowireshark_frames_page",
		"gowireshark_frames_get",
		"gowireshark_doctor",
		"gowireshark_expert_list",
	} {
		if tools[old] != nil {
			t.Fatalf("old tool %s should not be listed", old)
		}
	}

	framesPage := schemaMap(t, tools["gowireshark_list_frames"].InputSchema)
	requireContains(t, framesPage["required"], "file")
	page := propertySchema(t, framesPage, "page")
	if page["minimum"].(float64) != 1 {
		t.Fatalf("frames_page page minimum = %v, want 1", page["minimum"])
	}

	follow := schemaMap(t, tools["gowireshark_follow_stream"].InputSchema)
	protocol := propertySchema(t, follow, "protocol")
	requireContains(t, protocol["enum"], "tcp")
	requireContains(t, protocol["enum"], "udp")

	tap := schemaMap(t, tools["gowireshark_list_tap_endpoints"].InputSchema)
	tapType := propertySchema(t, tap, "type")
	requireContains(t, tapType["enum"], "eth")
	requireContains(t, tapType["enum"], "udp")

	exportWrite := schemaMap(t, tools["gowireshark_write_exported_object"].InputSchema)
	requireContains(t, exportWrite["required"], "packetNum")
	packetNum := propertySchema(t, exportWrite, "packetNum")
	if packetNum["minimum"].(float64) != 1 {
		t.Fatalf("packetNum minimum = %v, want 1", packetNum["minimum"])
	}

	verify := schemaMap(t, tools["gowireshark_verify_zeek_alert"].InputSchema)
	requireContains(t, verify["required"], "file")
}

func TestTracedToolErrorEnvelopeAndLog(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "calls.jsonl")
	originalLog := os.Getenv("MCP_CALL_LOG_PATH")
	os.Setenv("MCP_CALL_LOG_PATH", logPath)
	defer os.Setenv("MCP_CALL_LOG_PATH", originalLog)

	handler := tracedTool("gowireshark_count_frames", func(ctx context.Context, req *mcp.CallToolRequest, in emptyIn) (*mcp.CallToolResult, map[string]any, error) {
		return nil, nil, os.ErrNotExist
	})
	result, _, err := handler(context.Background(), &mcp.CallToolRequest{}, emptyIn{})
	if err != nil {
		t.Fatalf("handler returned protocol error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected tool error result")
	}
	if result.StructuredContent == nil {
		t.Fatal("expected structured error envelope")
	}
	if result.StructuredContent.(map[string]any)["ok"] != false {
		t.Fatalf("structured error envelope ok = %v, want false", result.StructuredContent.(map[string]any)["ok"])
	}
	if result.Meta["trace_id"] == "" {
		t.Fatal("expected trace_id metadata")
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read call log: %v", err)
	}
	if !strings.Contains(string(data), `"tool_name":"gowireshark_count_frames"`) {
		t.Fatalf("call log missing tool name: %s", data)
	}
}

func TestCountFramesDoesNotAdvertiseOutputSchema(t *testing.T) {
	cs, closeFn := startMCPTestSession(t)
	defer closeFn()

	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	for _, tool := range res.Tools {
		if tool.Name == "gowireshark_count_frames" && tool.OutputSchema != nil {
			t.Fatalf("gowireshark_count_frames output schema = %#v, want nil so clients accept CLI JSON structuredContent", tool.OutputSchema)
		}
	}
}

func TestDoctorOutputFields(t *testing.T) {
	result := map[string]any{
		"binary":                    "gowireshark",
		"resolvedBinaryPath":        "",
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

	expectedFields := []string{
		"binary", "resolvedBinaryPath", "pcapDir", "outputDir", "timeout",
		"maxOutputBytes", "wiresharkLibDir", "wiresharkDataDir",
		"wiresharkConfDir", "gowiresharkPcapDir", "gowiresharkOutputDir",
		"gowiresharkTimeout", "gowiresharkMaxOutputBytes",
	}
	for _, field := range expectedFields {
		if _, ok := result[field]; !ok {
			t.Errorf("doctor output missing field: %s", field)
		}
	}
}

func TestCliReferenceContent(t *testing.T) {
	ref := cliReferenceMarkdown()
	if !strings.Contains(ref, "gowireshark version") {
		t.Error("CLI reference should contain version command")
	}
	if !strings.Contains(ref, "gowireshark stats") {
		t.Error("CLI reference should contain stats command")
	}
	if !strings.Contains(ref, "gowireshark extract") {
		t.Error("CLI reference should contain extract command")
	}
}

func TestTimeoutDefault(t *testing.T) {
	original := os.Getenv("GOWIRESHARK_TIMEOUT")
	defer os.Setenv("GOWIRESHARK_TIMEOUT", original)

	os.Unsetenv("GOWIRESHARK_TIMEOUT")
	d := timeout()
	if d != 120*1e9 {
		t.Errorf("default timeout = %v, want 120s", d)
	}
}

func TestMaxOutputBytesDefault(t *testing.T) {
	original := os.Getenv("GOWIRESHARK_MAX_OUTPUT_BYTES")
	defer os.Setenv("GOWIRESHARK_MAX_OUTPUT_BYTES", original)

	os.Unsetenv("GOWIRESHARK_MAX_OUTPUT_BYTES")
	n := maxOutputBytes()
	if n != 8*1024*1024 {
		t.Errorf("default maxOutputBytes = %d, want %d", n, 8*1024*1024)
	}

	for _, value := range []string{"0", "-1"} {
		os.Setenv("GOWIRESHARK_MAX_OUTPUT_BYTES", value)
		if got := maxOutputBytes(); got != defaultMaxOutputBytes {
			t.Errorf("maxOutputBytes(%q) = %d, want %d", value, got, defaultMaxOutputBytes)
		}
	}
}

func startMCPTestSession(t *testing.T) (*mcp.ClientSession, func()) {
	t.Helper()
	ctx := context.Background()
	server := newMCPServer()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "v0.0.1"}, nil)
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		serverSession.Close()
		t.Fatalf("client connect: %v", err)
	}
	return clientSession, func() {
		clientSession.Close()
		serverSession.Close()
	}
}

func decodeResourceText(t *testing.T, res *mcp.ReadResourceResult, out any) {
	t.Helper()
	if res == nil || len(res.Contents) == 0 {
		t.Fatal("resource returned no content")
	}
	if err := json.Unmarshal([]byte(res.Contents[0].Text), out); err != nil {
		t.Fatalf("decode resource JSON: %v\n%s", err, res.Contents[0].Text)
	}
}

func schemaMap(t *testing.T, schema any) map[string]any {
	t.Helper()
	data, err := json.Marshal(schema)
	if err != nil {
		t.Fatalf("marshal schema: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal schema: %v", err)
	}
	return out
}

func propertySchema(t *testing.T, schema map[string]any, name string) map[string]any {
	t.Helper()
	props, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("schema properties missing or invalid: %#v", schema["properties"])
	}
	prop, ok := props[name].(map[string]any)
	if !ok {
		t.Fatalf("schema property %q missing or invalid", name)
	}
	return prop
}

func requireContains(t *testing.T, value any, want string) {
	t.Helper()
	list, ok := value.([]any)
	if !ok {
		t.Fatalf("value is not a list: %#v", value)
	}
	for _, item := range list {
		if item == want {
			return
		}
	}
	t.Fatalf("%#v does not contain %q", value, want)
}
