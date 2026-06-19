package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/randolphcyg/gowireshark"
	"github.com/randolphcyg/gowireshark/analysis"
	extractpkg "github.com/randolphcyg/gowireshark/extract"
)

// ──────────────────────────────────────────────────────────────────────────────
// MCP-composite CLI commands — 1:1 with MCP tool names.
// Each command accepts the same args as its MCP tool's inputSchema.
// ──────────────────────────────────────────────────────────────────────────────

// triage_pcap: frame count + streams + expert findings + stats + conversations
func triagePcapCmd(args []string) {
	fs := flag.NewFlagSet("triage_pcap", flag.ExitOnError)
	file := fs.String("file", "", "pcap path")
	filterStr := fs.String("filter", "", "display filter")
	_ = fs.Parse(args)
	requireFile(*file)

	result := map[string]any{"file": *file}
	opts := []gowireshark.Option{gowireshark.WithDisplayFilter(*filterStr)}

	if count, err := gowireshark.FrameCount(*file, opts...); err != nil {
		result["frame_count_error"] = err.Error()
	} else {
		result["frame_count"] = count
	}
	if streams, err := gowireshark.Streams(*file, opts...); err != nil {
		result["streams_error"] = err.Error()
	} else {
		result["streams"] = streams
	}
	if infos, err := gowireshark.ExpertInfos(*file, opts...); err != nil {
		result["expert_error"] = err.Error()
	} else {
		result["expert_findings"] = infos
	}
	if stats, err := analysis.WalkAnalyze(*file, opts...); err != nil {
		result["stats_error"] = err.Error()
	} else {
		result["stats"] = stats
	}
	if convs, err := gowireshark.Conversations(*file, opts...); err != nil {
		result["conversations_error"] = err.Error()
	} else {
		result["conversations"] = convs
	}
	writeJSON(result)
}

// search_frames: page / batch / fields dispatch
func searchFramesCmd(args []string) {
	fs := flag.NewFlagSet("search_frames", flag.ExitOnError)
	file := fs.String("file", "", "pcap path")
	filterStr := fs.String("filter", "", "display filter")
	page := fs.Int("page", 1, "page number")
	size := fs.Int("size", 20, "page size")
	fields := fs.String("fields", "", "comma-separated field names")
	indices := fs.String("indices", "", "comma-separated frame numbers")
	_ = fs.Parse(args)
	requireFile(*file)

	opts := []gowireshark.Option{gowireshark.WithDisplayFilter(*filterStr), gowireshark.WithIgnoreErrors(true)}

	switch {
	case *indices != "":
		idxs := parseIntList(*indices)
		frames, err := gowireshark.FramesByNumbers(*file, idxs, opts...)
		must(err)
		writeJSON(map[string]any{"list": frames})
	case *fields != "":
		arr := strings.Split(*fields, ",")
		withFields := append(opts, gowireshark.WithOutputFields(arr))
		frames, err := gowireshark.Frames(*file, withFields...)
		must(err)
		writeJSON(map[string]any{"list": frames, "fields": arr})
	default:
		if *page < 1 {
			*page = 1
		}
		if *size < 1 {
			*size = 20
		}
		frames, hasMore, err := gowireshark.FramesPage(*file, *page, *size, opts...)
		must(err)
		writeJSON(map[string]any{"list": frames, "hasMore": hasMore, "page": *page, "size": *size})
	}
}

// get_frame: single frame with optional hex dump and field extraction
func getFrameCmd(args []string) {
	fs := flag.NewFlagSet("get_frame", flag.ExitOnError)
	file := fs.String("file", "", "pcap path")
	index := fs.Int("index", 0, "frame number (>= 1)")
	includeHex := fs.Bool("include-hex", false, "include hex dump")
	fields := fs.String("fields", "", "comma-separated field names")
	_ = fs.Parse(args)
	requireFile(*file)
	requireIndex(*index)

	result := map[string]any{"file": *file, "index": *index}
	opts := []gowireshark.Option{gowireshark.WithIgnoreErrors(true)}

	f, err := gowireshark.FrameByNumberContext(context.Background(), *file, *index, opts...)
	must(err)
	result["frame"] = f

	if *includeHex {
		h, err := gowireshark.HexDataByFrameNumber(*file, *index, opts...)
		if err != nil {
			result["hex_error"] = err.Error()
		} else {
			result["hex"] = h
		}
	}
	if *fields != "" {
		arr := strings.Split(*fields, ",")
		withFields := append(opts, gowireshark.WithOutputFields(arr), gowireshark.WithDisplayFilter(fmt.Sprintf("frame.number == %d", *index)))
		fieldFrames, err := gowireshark.Frames(*file, withFields...)
		if err != nil {
			result["fields_error"] = err.Error()
		} else {
			result["fields"] = fieldFrames
		}
	}
	writeJSON(result)
}

// inspect_stream: follow and reconstruct TCP/UDP stream
func inspectStreamCmd(args []string) {
	fs := flag.NewFlagSet("inspect_stream", flag.ExitOnError)
	file := fs.String("file", "", "pcap path")
	protocol := fs.String("protocol", "tcp", "tcp or udp")
	filterStr := fs.String("filter", "", "display filter (e.g. tcp.stream eq 0)")
	_ = fs.Parse(args)
	requireFile(*file)
	if *protocol != "tcp" && *protocol != "udp" {
		fatal("--protocol must be tcp or udp, got %q", *protocol)
	}
	data, err := gowireshark.FollowStream(*file, *filterStr, *protocol, gowireshark.WithIgnoreErrors(true))
	must(err)
	writeJSON(data)
}

// validate_filter: validate display filter, optionally with detailed field feedback
func validateFilterCmd(args []string) {
	fs := flag.NewFlagSet("validate_filter", flag.ExitOnError)
	expr := fs.String("expr", "", "display filter expression")
	detailed := fs.Bool("detailed", false, "return field-level validation")
	_ = fs.Parse(args)
	if *expr == "" {
		fatal("--expr is required")
	}
	if *detailed {
		result, err := gowireshark.ValidateDisplayFilterDetailed(*expr)
		must(err)
		writeJSON(result)
		return
	}
	if err := gowireshark.ValidateFilter(*expr); err != nil {
		writeJSON(map[string]any{"valid": false, "error": err.Error()})
		return
	}
	writeJSON(map[string]any{"valid": true})
}

// suggest_filter: suggest field names by prefix
func suggestFilterCmd(args []string) {
	fs := flag.NewFlagSet("suggest_filter", flag.ExitOnError)
	prefix := fs.String("prefix", "", "field name prefix")
	limit := fs.Int("limit", 50, "max results")
	_ = fs.Parse(args)
	if *prefix == "" {
		fatal("--prefix is required")
	}
	fields, err := gowireshark.RuntimeSuggestFields(context.Background(), *prefix, *limit)
	must(err)
	writeJSON(map[string]any{"fields": fields})
}

// get_field_info: get metadata for a display filter field
func getFieldInfoCmd(args []string) {
	fs := flag.NewFlagSet("get_field_info", flag.ExitOnError)
	name := fs.String("name", "", "field name (e.g. tcp.stream)")
	_ = fs.Parse(args)
	if *name == "" {
		fatal("--name is required")
	}
	info, err := gowireshark.FieldInfo(*name)
	must(err)
	writeJSON(info)
}

// slice_pcap: slice PCAP by filter or frame indices
func slicePcapCmd(args []string) {
	fs := flag.NewFlagSet("slice_pcap", flag.ExitOnError)
	file := fs.String("file", "", "pcap path")
	out := fs.String("out", "", "output pcap path")
	filterStr := fs.String("filter", "", "display filter")
	indices := fs.String("indices", "", "comma-separated frame numbers")
	_ = fs.Parse(args)
	requireFile(*file)
	if *out == "" {
		fatal("--out is required")
	}
	outW, err := os.Create(*out)
	must(err)
	defer outW.Close()

	selector := gowireshark.FrameSelector{Filter: *filterStr}
	if *indices != "" {
		selector.Indices = parseIntList(*indices)
	}
	count, err := gowireshark.WritePcapSlice(*file, outW, selector, gowireshark.WithIgnoreErrors(true))
	must(err)
	writeJSON(map[string]any{"written": count, "output": *out})
}

// build_evidence: evidence bundle + endpoint tap
func buildEvidenceCmd(args []string) {
	fs := flag.NewFlagSet("build_evidence", flag.ExitOnError)
	file := fs.String("file", "", "pcap path")
	filterStr := fs.String("filter", "", "display filter")
	_ = fs.Parse(args)
	requireFile(*file)

	result := map[string]any{"file": *file}
	filter := *filterStr
	if filter == "" {
		filter = "frame"
	}
	opts := []gowireshark.Option{gowireshark.WithDisplayFilter(filter), gowireshark.WithIgnoreErrors(true)}

	bundle, err := gowireshark.BuildEvidenceBundle(*file, gowireshark.FrameSelector{Filter: filter}, opts...)
	if err != nil {
		result["evidence_error"] = err.Error()
	} else {
		result["evidence"] = bundle
	}
	eps, err := gowireshark.TapEndpoints(*file, "ip", opts...)
	if err != nil {
		result["endpoints_error"] = err.Error()
	} else {
		result["endpoints"] = eps
	}
	writeJSON(result)
}

// export_objects: list or extract exportable objects
func exportObjectsCmd(args []string) {
	fs := flag.NewFlagSet("export_objects", flag.ExitOnError)
	file := fs.String("file", "", "pcap path")
	protocol := fs.String("protocol", "", "protocol (e.g. http, smb)")
	action := fs.String("action", "list", "list or extract")
	packetNum := fs.Int("packet-num", 0, "packet number for single object extract")
	out := fs.String("out", "", "output file path (extract) or directory (bulk extract)")
	filterStr := fs.String("filter", "", "display filter")
	_ = fs.Parse(args)
	requireFile(*file)

	switch *action {
	case "extract":
		if *out == "" {
			fatal("--out is required for action=extract")
		}
		if *protocol != "" {
			// Single object export by protocol + packet_num
			if *packetNum <= 0 {
				fatal("--packet-num is required for action=extract with --protocol")
			}
			outW, err := os.Create(*out)
			must(err)
			defer outW.Close()
			err = gowireshark.WriteExportObject(*file, *protocol, *packetNum, outW, gowireshark.WithDisplayFilter(*filterStr))
			must(err)
			writeJSON(map[string]any{"written": *out, "packet_num": *packetNum, "protocol": *protocol})
			return
		}
		// Bulk file carving (no protocol specified)
		extractor, err := extractpkg.New(*out)
		must(err)
		frames, err := gowireshark.Frames(*file, gowireshark.WithIgnoreErrors(true), gowireshark.WithDisplayFilter(*filterStr))
		must(err)
		files, err := extractor.Files(frames)
		must(err)
		writeJSON(files)
	default:
		// list
		if *protocol == "" {
			fatal("--protocol is required for action=list")
		}
		objs, err := gowireshark.ExportObjects(*file, *protocol, gowireshark.WithDisplayFilter(*filterStr))
		must(err)
		writeJSON(map[string]any{"list": objs, "protocol": *protocol})
	}
}

// verify_zeek_alert: multi-step verification of a Zeek alert against packet evidence
func verifyZeekAlertCmd(args []string) {
	fs := flag.NewFlagSet("verify_zeek_alert", flag.ExitOnError)
	file := fs.String("file", "", "pcap path")
	filterStr := fs.String("filter", "", "display filter")
	alert := fs.String("alert", "", "alert type (e.g. scan, exploit, malware)")
	srcIP := fs.String("src-ip", "", "source IP")
	dstIP := fs.String("dst-ip", "", "destination IP")
	srcPort := fs.Int("src-port", 0, "source port")
	dstPort := fs.Int("dst-port", 0, "destination port")
	proto := fs.String("protocol", "", "transport protocol (tcp/udp)")
	_ = fs.Parse(args)
	requireFile(*file)

	// Build filter from fields if not provided
	filter := *filterStr
	if filter == "" {
		parts := []string{}
		if *srcIP != "" && net.ParseIP(*srcIP) != nil {
			parts = append(parts, fmt.Sprintf("ip.src == %s", *srcIP))
		}
		if *dstIP != "" && net.ParseIP(*dstIP) != nil {
			parts = append(parts, fmt.Sprintf("ip.dst == %s", *dstIP))
		}
		if *srcPort > 0 {
			parts = append(parts, fmt.Sprintf("tcp.srcport == %d", *srcPort))
		}
		if *dstPort > 0 {
			parts = append(parts, fmt.Sprintf("tcp.dstport == %d", *dstPort))
		}
		if *proto != "" {
			parts = append(parts, *proto)
		}
		if len(parts) == 0 {
			fatal("--filter or alert fields (--src-ip, --dst-ip, etc.) are required")
		}
		filter = strings.Join(parts, " && ")
	}

	result := map[string]any{
		"file":   *file,
		"filter": filter,
		"alert":  *alert,
	}
	opts := []gowireshark.Option{gowireshark.WithDisplayFilter(filter), gowireshark.WithIgnoreErrors(true)}

	// 1. Validate the filter
	if err := gowireshark.ValidateFilter(filter); err != nil {
		result["filter_valid"] = false
		result["filter_error"] = err.Error()
	} else {
		result["filter_valid"] = true
	}

	// 2. Frame count
	if count, err := gowireshark.FrameCount(*file, opts...); err != nil {
		result["frame_count_error"] = err.Error()
	} else {
		result["frame_count"] = count
	}

	// 3. Expert findings
	if infos, err := gowireshark.ExpertInfos(*file, opts...); err != nil {
		result["expert_error"] = err.Error()
	} else {
		result["expert_findings"] = infos
	}

	// 4. Stream reconstruction (first stream)
	if streams, err := gowireshark.Streams(*file, opts...); err != nil {
		result["streams_error"] = err.Error()
	} else if len(streams) > 0 {
		result["stream_count"] = len(streams)
		firstStream := streams[0]
		streamID := firstStream.StreamID
		if streamID >= 0 {
			streamFilter := fmt.Sprintf("%s && tcp.stream eq %d", filter, streamID)
			proto := "tcp"
			if firstStream.Protocol == "udp" {
				proto = "udp"
				streamFilter = fmt.Sprintf("%s && udp.stream eq %d", filter, streamID)
			}
			streamOpts := []gowireshark.Option{gowireshark.WithDisplayFilter(streamFilter), gowireshark.WithIgnoreErrors(true)}
			if data, err := gowireshark.FollowStream(*file, streamFilter, proto, streamOpts...); err != nil {
				result["stream_payload_error"] = err.Error()
			} else {
				result["stream_sample"] = data
			}
		}
	} else {
		result["stream_count"] = 0
	}

	writeJSON(result)
}