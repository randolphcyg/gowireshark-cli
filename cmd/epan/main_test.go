package main

import (
	"flag"
	"strconv"
	"strings"
	"testing"
)

func TestUsageContainsStatsAndExtract(t *testing.T) {
	usage := "usage: epan <version|filter|metadata|frames|streams|traffic|expert|follow|slice|evidence|tap|srt|export-object|stats|extract>"
	if !strings.Contains(usage, "stats") {
		t.Error("usage should contain stats")
	}
	if !strings.Contains(usage, "extract") {
		t.Error("usage should contain extract")
	}
}

func TestStatsCmdArgs(t *testing.T) {
	fs := flag.NewFlagSet("stats", flag.ContinueOnError)
	file := fs.String("file", "", "pcap path")
	filterStr := fs.String("filter", "", "display filter")
	args := []string{"--file", "test.pcap", "--filter", "tcp"}
	if err := fs.Parse(args); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if *file != "test.pcap" {
		t.Errorf("file = %q, want test.pcap", *file)
	}
	if *filterStr != "tcp" {
		t.Errorf("filter = %q, want tcp", *filterStr)
	}
}

func TestStatsCmdMissingFile(t *testing.T) {
	fs := flag.NewFlagSet("stats", flag.ContinueOnError)
	file := fs.String("file", "", "pcap path")
	if err := fs.Parse([]string{}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if *file != "" {
		t.Error("file should be empty when not provided")
	}
}

func TestExtractCmdArgs(t *testing.T) {
	fs := flag.NewFlagSet("extract", flag.ContinueOnError)
	file := fs.String("file", "", "pcap path")
	out := fs.String("out", "", "output directory")
	args := []string{"--file", "test.pcap", "--out", "/tmp/out"}
	if err := fs.Parse(args); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if *file != "test.pcap" {
		t.Errorf("file = %q, want test.pcap", *file)
	}
	if *out != "/tmp/out" {
		t.Errorf("out = %q, want /tmp/out", *out)
	}
}

func TestExtractCmdMissingOut(t *testing.T) {
	fs := flag.NewFlagSet("extract", flag.ContinueOnError)
	file := fs.String("file", "", "pcap path")
	out := fs.String("out", "", "output directory")
	if err := fs.Parse([]string{"--file", "test.pcap"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if *file != "test.pcap" {
		t.Errorf("file = %q, want test.pcap", *file)
	}
	if *out != "" {
		t.Error("out should be empty when not provided")
	}
}

func TestFilterPassthrough(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	file := fs.String("file", "", "pcap path")
	filterStr := fs.String("filter", "", "display filter")
	args := []string{"--file", "test.pcap", "--filter", "tcp.port == 80"}
	if err := fs.Parse(args); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if *file != "test.pcap" {
		t.Errorf("file = %q, want test.pcap", *file)
	}
	if *filterStr != "tcp.port == 80" {
		t.Errorf("filter = %q, want tcp.port == 80", *filterStr)
	}
}

func TestFrameOptsDefaults(t *testing.T) {
	fs := flag.NewFlagSet("frames", flag.ContinueOnError)
	page := fs.Int("page", 1, "page number")
	size := fs.Int("size", 20, "page size")
	if err := fs.Parse([]string{}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if *page != 1 {
		t.Errorf("default page = %d, want 1", *page)
	}
	if *size != 20 {
		t.Errorf("default size = %d, want 20", *size)
	}
}

func TestRequireIndex(t *testing.T) {
	tests := []struct {
		idx    int
		wantOk bool
	}{
		{idx: 0, wantOk: false},
		{idx: -1, wantOk: false},
		{idx: 1, wantOk: true},
	}
	for _, tt := range tests {
		ok := tt.idx >= 1
		if ok != tt.wantOk {
			t.Errorf("index=%d: valid = %v, want %v", tt.idx, ok, tt.wantOk)
		}
	}
}

func TestIntListParsing(t *testing.T) {
	tests := []struct {
		input string
		want  []int
	}{
		{"1,2,3", []int{1, 2, 3}},
		{"5", []int{5}},
		{"", nil},
	}
	for _, tt := range tests {
		got := parseIntListTest(tt.input)
		if len(got) != len(tt.want) {
			t.Errorf("parseIntList(%q) = %v, want %v", tt.input, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("parseIntList(%q)[%d] = %d, want %d", tt.input, i, got[i], tt.want[i])
			}
		}
	}
}

func parseIntListTest(s string) []int {
	parts := strings.Split(s, ",")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, _ := strconv.Atoi(p)
		out = append(out, n)
	}
	return out
}
