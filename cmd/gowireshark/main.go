package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/randolphcyg/gowireshark"
	"github.com/randolphcyg/gowireshark/analysis"
	extractpkg "github.com/randolphcyg/gowireshark/extract"
)

func main() {
	if len(os.Args) < 2 {
		fatal("usage: gowireshark <version|filter|metadata|frames|streams|traffic|expert|follow|slice|evidence|tap|srt|export-object>")
	}
	switch os.Args[1] {
	case "version":
		ver, err := gowireshark.RuntimeVersion(context.Background())
		must(err)
		writeJSON(map[string]any{"version": ver.Version})
	case "filter":
		filterCmd(os.Args[2:])
	case "metadata":
		metadataCmd(os.Args[2:])
	case "frames":
		framesCmd(os.Args[2:])
	case "streams":
		streamsCmd(os.Args[2:])
	case "traffic":
		trafficCmd(os.Args[2:])
	case "expert":
		expertCmd(os.Args[2:])
	case "follow":
		followCmd(os.Args[2:])
	case "slice":
		sliceCmd(os.Args[2:])
	case "evidence":
		evidenceCmd(os.Args[2:])
	case "tap":
		tapCmd(os.Args[2:])
	case "srt":
		srtCmd(os.Args[2:])
	case "export-object":
		exportObjCmd(os.Args[2:])
	case "stats":
		statsCmd(os.Args[2:])
	case "extract":
		extractCmd(os.Args[2:])
	default:
		fatal("unknown command: %s", os.Args[1])
	}
}

func filterCmd(args []string) {
	if len(args) < 1 {
		fatal("usage: gowireshark filter <validate|validate-detailed|suggest>")
	}
	switch args[0] {
	case "validate":
		fs := flag.NewFlagSet("filter validate", flag.ExitOnError)
		expr := fs.String("expr", "", "display filter")
		_ = fs.Parse(args[1:])
		if *expr == "" {
			fatal("--expr is required")
		}
		if err := gowireshark.ValidateFilter(*expr); err != nil {
			writeJSON(map[string]any{"valid": false, "error": err.Error()})
			return
		}
		writeJSON(map[string]any{"valid": true})
	case "validate-detailed":
		fs := flag.NewFlagSet("filter validate-detailed", flag.ExitOnError)
		expr := fs.String("expr", "", "display filter")
		_ = fs.Parse(args[1:])
		if *expr == "" {
			fatal("--expr is required")
		}
		result, err := gowireshark.ValidateDisplayFilterDetailed(*expr)
		must(err)
		writeJSON(result)
	case "suggest":
		fs := flag.NewFlagSet("filter suggest", flag.ExitOnError)
		prefix := fs.String("prefix", "", "field prefix")
		limit := fs.Int("limit", 50, "max results")
		_ = fs.Parse(args[1:])
		if *prefix == "" {
			fatal("--prefix is required")
		}
		fields, err := gowireshark.RuntimeSuggestFields(context.Background(), *prefix, *limit)
		must(err)
		writeJSON(map[string]any{"fields": fields})
	default:
		fatal("unknown filter subcommand: %s", args[0])
	}
}

func metadataCmd(args []string) {
	if len(args) < 1 {
		fatal("usage: gowireshark metadata <protocols|fields|field>")
	}
	switch args[0] {
	case "protocols":
		protos, err := gowireshark.RuntimeProtocols(context.Background())
		must(err)
		writeJSON(map[string]any{"protocols": protos})
	case "fields":
		fields, err := gowireshark.RuntimeFields(context.Background())
		must(err)
		writeJSON(map[string]any{"fields": fields})
	case "field":
		fs := flag.NewFlagSet("metadata field", flag.ExitOnError)
		name := fs.String("name", "", "field name")
		_ = fs.Parse(args[1:])
		if *name == "" {
			fatal("--name is required")
		}
		f, err := gowireshark.FieldInfo(*name)
		must(err)
		writeJSON(f)
	default:
		fatal("unknown metadata subcommand: %s", args[0])
	}
}

func framesCmd(args []string) {
	if len(args) == 0 {
		fatal("usage: gowireshark frames <count|page|get|batch|hex|write|fields>")
	}
	opts := newFrameOpts(args[1:])
	switch args[0] {
	case "count":
		requireFile(opts.file)
		count, err := gowireshark.FrameCount(opts.file, frameOptsToSDK(opts)...)
		must(err)
		writeJSON(map[string]any{"count": count})
	case "page":
		requireFile(opts.file)
		frames, hasMore, err := gowireshark.FramesPage(opts.file, opts.page, opts.size, frameOptsToSDK(opts)...)
		must(err)
		writeJSON(map[string]any{"list": frames, "hasMore": hasMore, "page": opts.page, "size": opts.size})
	case "get":
		requireFile(opts.file)
		requireIndex(opts.index)
		f, err := gowireshark.FrameByNumberContext(context.Background(), opts.file, opts.index, frameOptsToSDK(opts)...)
		must(err)
		writeJSON(f)
	case "batch":
		requireFile(opts.file)
		if opts.indices == "" {
			fatal("--indices is required")
		}
		idxs := parseIntList(opts.indices)
		frames, err := gowireshark.FramesByNumbers(opts.file, idxs, frameOptsToSDK(opts)...)
		must(err)
		writeJSON(map[string]any{"list": frames})
	case "hex":
		requireFile(opts.file)
		requireIndex(opts.index)
		h, err := gowireshark.HexDataByFrameNumber(opts.file, opts.index, frameOptsToSDK(opts)...)
		must(err)
		writeJSON(h)
	case "write":
		requireFile(opts.file)
		if opts.out == "" {
			fatal("--out is required")
		}
		if opts.fields != "" {
			arr := strings.Split(opts.fields, ",")
			count, err := gowireshark.WriteFrames(opts.file, os.Stdout, append(frameOptsToSDK(opts), gowireshark.WithOutputFields(arr))...)
			must(err)
			fmt.Fprintln(os.Stderr, "written=", count)
			return
		}
		count, err := gowireshark.WriteFrames(opts.file, os.Stdout, frameOptsToSDK(opts)...)
		must(err)
		fmt.Fprintln(os.Stderr, "written=", count)
	case "fields":
		requireFile(opts.file)
		if opts.fields == "" {
			fatal("--fields is required")
		}
		arr := strings.Split(opts.fields, ",")
		count, err := gowireshark.WriteFrames(opts.file, os.Stdout, append(frameOptsToSDK(opts), gowireshark.WithOutputFields(arr))...)
		must(err)
		fmt.Fprintln(os.Stderr, "written=", count)
	default:
		fatal("unknown frames subcommand: %s", args[0])
	}
}

func streamsCmd(args []string) {
	if len(args) < 1 || args[0] != "list" {
		fatal("usage: gowireshark streams list --file <pcap>")
	}
	fs := flag.NewFlagSet("streams list", flag.ExitOnError)
	file := fs.String("file", "", "pcap path")
	filterStr := fs.String("filter", "", "display filter")
	_ = fs.Parse(args[1:])
	requireFile(*file)
	opts := []gowireshark.Option{gowireshark.WithDisplayFilter(*filterStr)}
	streams, err := gowireshark.Streams(*file, opts...)
	must(err)
	writeJSON(map[string]any{"list": streams})
}

func trafficCmd(args []string) {
	if len(args) < 1 {
		fatal("usage: gowireshark traffic <conversations|timeline|files>")
	}
	switch args[0] {
	case "conversations":
		if len(args) < 2 || args[1] != "list" {
			fatal("usage: gowireshark traffic conversations list --file <pcap>")
		}
		fs := flag.NewFlagSet("traffic conversations list", flag.ExitOnError)
		file := fs.String("file", "", "pcap path")
		filterStr := fs.String("filter", "", "display filter")
		_ = fs.Parse(args[2:])
		requireFile(*file)
		convs, err := gowireshark.Conversations(*file, gowireshark.WithDisplayFilter(*filterStr))
		must(err)
		writeJSON(map[string]any{"list": convs})
	case "timeline":
		if len(args) < 2 || args[1] != "summary" {
			fatal("usage: gowireshark traffic timeline summary --file <pcap>")
		}
		fs := flag.NewFlagSet("traffic timeline summary", flag.ExitOnError)
		file := fs.String("file", "", "pcap path")
		filterStr := fs.String("filter", "", "display filter")
		_ = fs.Parse(args[2:])
		requireFile(*file)
		timeline, err := gowireshark.Timeline(*file, gowireshark.WithDisplayFilter(*filterStr))
		must(err)
		writeJSON(map[string]any{"list": timeline})
	case "files":
		if len(args) < 2 || args[1] != "list" {
			fatal("usage: gowireshark traffic files list --file <pcap>")
		}
		fs := flag.NewFlagSet("traffic files list", flag.ExitOnError)
		file := fs.String("file", "", "pcap path")
		filterStr := fs.String("filter", "", "display filter")
		_ = fs.Parse(args[2:])
		requireFile(*file)
		files, err := gowireshark.Files(*file, gowireshark.WithDisplayFilter(*filterStr))
		must(err)
		writeJSON(map[string]any{"list": files})
	default:
		fatal("unknown traffic subcommand: %s", args[0])
	}
}

func expertCmd(args []string) {
	if len(args) < 1 || args[0] != "list" {
		fatal("usage: gowireshark expert list --file <pcap>")
	}
	fs := flag.NewFlagSet("expert list", flag.ExitOnError)
	file := fs.String("file", "", "pcap path")
	filterStr := fs.String("filter", "", "display filter")
	_ = fs.Parse(args[1:])
	requireFile(*file)
	infos, err := gowireshark.ExpertInfos(*file, gowireshark.WithDisplayFilter(*filterStr))
	must(err)
	writeJSON(map[string]any{"list": infos})
}

func followCmd(args []string) {
	fs := flag.NewFlagSet("follow", flag.ExitOnError)
	file := fs.String("file", "", "pcap path")
	protocol := fs.String("protocol", "tcp", "tcp or udp")
	filterStr := fs.String("filter", "", "display filter")
	_ = fs.Parse(args)
	requireFile(*file)
	data, err := gowireshark.FollowStream(*file, *filterStr, *protocol, gowireshark.WithIgnoreErrors(true))
	must(err)
	writeJSON(data)
}

func sliceCmd(args []string) {
	if len(args) < 1 || args[0] != "pcap" {
		fatal("usage: gowireshark slice pcap --file <pcap> --out <output.pcap>")
	}
	fs := flag.NewFlagSet("slice pcap", flag.ExitOnError)
	file := fs.String("file", "", "pcap path")
	filterStr := fs.String("filter", "", "display filter")
	indices := fs.String("indices", "", "comma-separated frame numbers")
	out := fs.String("out", "", "output pcap path")
	_ = fs.Parse(args[1:])
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

func evidenceCmd(args []string) {
	if len(args) < 1 || args[0] != "bundle" {
		fatal("usage: gowireshark evidence bundle --file <pcap>")
	}
	fs := flag.NewFlagSet("evidence bundle", flag.ExitOnError)
	file := fs.String("file", "", "pcap path")
	filterStr := fs.String("filter", "", "display filter")
	_ = fs.Parse(args[1:])
	requireFile(*file)
	bundle, err := gowireshark.BuildEvidenceBundle(*file, gowireshark.FrameSelector{Filter: *filterStr}, gowireshark.WithIgnoreErrors(true))
	must(err)
	writeJSON(bundle)
}

func tapCmd(args []string) {
	if len(args) < 1 {
		fatal("usage: gowireshark tap <conversations|endpoints>")
	}
	switch args[0] {
	case "conversations":
		fs := flag.NewFlagSet("tap conversations", flag.ExitOnError)
		file := fs.String("file", "", "pcap path")
		convType := fs.String("type", "tcp", "eth/ip/tcp/udp")
		filterStr := fs.String("filter", "", "display filter")
		_ = fs.Parse(args[1:])
		requireFile(*file)
		convs, err := gowireshark.TapConversations(*file, *convType, gowireshark.WithDisplayFilter(*filterStr))
		must(err)
		writeJSON(map[string]any{"list": convs})
	case "endpoints":
		fs := flag.NewFlagSet("tap endpoints", flag.ExitOnError)
		file := fs.String("file", "", "pcap path")
		epType := fs.String("type", "ip", "eth/ip/tcp/udp")
		filterStr := fs.String("filter", "", "display filter")
		_ = fs.Parse(args[1:])
		requireFile(*file)
		eps, err := gowireshark.TapEndpoints(*file, *epType, gowireshark.WithDisplayFilter(*filterStr))
		must(err)
		writeJSON(map[string]any{"list": eps})
	default:
		fatal("unknown tap subcommand: %s", args[0])
	}
}

func srtCmd(args []string) {
	if len(args) < 1 || args[0] != "list" {
		fatal("usage: gowireshark srt list --file <pcap> --protocol <protocol>")
	}
	fs := flag.NewFlagSet("srt list", flag.ExitOnError)
	file := fs.String("file", "", "pcap path")
	protocol := fs.String("protocol", "", "protocol (e.g. smb, dns)")
	filterStr := fs.String("filter", "", "display filter")
	_ = fs.Parse(args[1:])
	requireFile(*file)
	if *protocol == "" {
		fatal("--protocol is required")
	}
	srt, err := gowireshark.ServiceResponseTimes(*file, *protocol, gowireshark.WithDisplayFilter(*filterStr))
	must(err)
	writeJSON(map[string]any{"list": srt})
}

func exportObjCmd(args []string) {
	if len(args) < 1 {
		fatal("usage: gowireshark export-object <list|write>")
	}
	switch args[0] {
	case "list":
		fs := flag.NewFlagSet("export-object list", flag.ExitOnError)
		file := fs.String("file", "", "pcap path")
		protocol := fs.String("protocol", "", "protocol (e.g. http)")
		filterStr := fs.String("filter", "", "display filter")
		_ = fs.Parse(args[1:])
		requireFile(*file)
		if *protocol == "" {
			fatal("--protocol is required")
		}
		objs, err := gowireshark.ExportObjects(*file, *protocol, gowireshark.WithDisplayFilter(*filterStr))
		must(err)
		writeJSON(map[string]any{"list": objs})
	case "write":
		fs := flag.NewFlagSet("export-object write", flag.ExitOnError)
		file := fs.String("file", "", "pcap path")
		protocol := fs.String("protocol", "", "protocol (e.g. http)")
		packetNum := fs.Int("packet-num", 0, "packet number")
		out := fs.String("out", "", "output file path")
		filterStr := fs.String("filter", "", "display filter")
		_ = fs.Parse(args[1:])
		requireFile(*file)
		if *protocol == "" {
			fatal("--protocol is required")
		}
		if *packetNum <= 0 {
			fatal("--packet-num is required")
		}
		if *out == "" {
			fatal("--out is required")
		}
		outW, err := os.Create(*out)
		must(err)
		defer outW.Close()
		err = gowireshark.WriteExportObject(*file, *protocol, *packetNum, outW, gowireshark.WithDisplayFilter(*filterStr))
		must(err)
		writeJSON(map[string]any{"written": *out})
	default:
		fatal("unknown export-object subcommand: %s", args[0])
	}
}

func statsCmd(args []string) {
	fs := flag.NewFlagSet("stats", flag.ExitOnError)
	file := fs.String("file", "", "pcap path")
	filterStr := fs.String("filter", "", "display filter")
	_ = fs.Parse(args)
	requireFile(*file)
	summary, err := analysis.WalkAnalyze(*file, gowireshark.WithDisplayFilter(*filterStr), gowireshark.WithIgnoreErrors(true))
	must(err)
	writeJSON(summary)
}

func extractCmd(args []string) {
	fs := flag.NewFlagSet("extract", flag.ExitOnError)
	file := fs.String("file", "", "pcap path")
	out := fs.String("out", "", "output directory")
	_ = fs.Parse(args)
	requireFile(*file)
	if *out == "" {
		fatal("--out is required")
	}
	extractor, err := extractpkg.New(*out)
	must(err)
	frames, err := gowireshark.Frames(*file, gowireshark.WithIgnoreErrors(true))
	must(err)
	files, err := extractor.Files(frames)
	must(err)
	writeJSON(files)
}

type frameOpts struct {
	file       string
	filter     string
	page       int
	size       int
	index      int
	indices    string
	fields     string
	out        string
	compact    bool
	rawJSON    bool
	ignoreErrs bool
}

func newFrameOpts(args []string) frameOpts {
	o := frameOpts{page: 1, size: 20}
	fs := flag.NewFlagSet("frames", flag.ExitOnError)
	fs.StringVar(&o.file, "file", "", "pcap path")
	fs.StringVar(&o.filter, "filter", "", "display filter")
	fs.IntVar(&o.page, "page", 1, "page number (page)")
	fs.IntVar(&o.size, "size", 20, "page size (page)")
	fs.IntVar(&o.index, "index", 0, "frame index (get/hex)")
	fs.StringVar(&o.indices, "indices", "", "comma-separated frame indices (batch)")
	fs.StringVar(&o.fields, "fields", "", "comma-separated output fields (write/fields)")
	fs.StringVar(&o.out, "out", "", "output file path (write/slice)")
	fs.BoolVar(&o.compact, "compact", false, "compact json")
	fs.BoolVar(&o.rawJSON, "raw-json", false, "include raw fields")
	fs.BoolVar(&o.ignoreErrs, "ignore-errors", false, "ignore parse errors")
	_ = fs.Parse(args)
	return o
}

func frameOptsToSDK(o frameOpts) []gowireshark.Option {
	out := []gowireshark.Option{
		gowireshark.WithDisplayFilter(o.filter),
	}
	if o.compact {
		out = append(out, gowireshark.WithCompactJSON(true))
	}
	if o.rawJSON {
		out = append(out, gowireshark.WithRawJSON(true))
	}
	if o.ignoreErrs {
		out = append(out, gowireshark.WithIgnoreErrors(true))
	}
	return out
}

func writeJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fatal("encode output: %v", err)
	}
}

func requireFile(path string) {
	if path == "" {
		fatal("--file is required")
	}
}

func requireIndex(idx int) {
	if idx < 1 {
		fatal("--index is required (>= 1)")
	}
}

func parseIntList(s string) []int {
	parts := strings.Split(s, ",")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			fatal("invalid index: %q", p)
		}
		out = append(out, n)
	}
	return out
}

func must(err error) {
	if err != nil {
		fatal("%v", err)
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
