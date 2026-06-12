# epan Claude Code Instructions

Use the packaged wrapper, not the raw binary:

```bash
/path/to/epan-<target>/bin/epan-env version
```

When analyzing captures, follow `agents/pcap-analysis-rules.md`. Start with `frames count`, then `streams list`, then `expert list`. Validate new display filters with `filter validate-detailed` before using them. Only follow mapped stream ids, and create slices/evidence bundles only after narrowing scope.

Do not dump full frame trees from unknown or large PCAPs.
