# Testing

Run everything from the repository root:

```sh
make lint
go test ./...
make e2e
make bench
```

## Examples and unit tests

`example_test.go` holds the godoc examples; the `*_test.go` files next to each source file check the library API, and `internal/` packages test the manifest, resource table, DEX and signing parsers on synthetic archives built in the tests. CI runs them with the race detector on Linux, macOS and Windows, on the go.mod floor and on the newest Go (`.github/workflows/test.yml`).

## Generated properties

[`properties_test.go`](../properties_test.go) uses [rapid](https://pkg.go.dev/pgregory.net/rapid) to generate findings, fail policies and inspection results from a small alphabet, so equal IDs, fingerprints and permission names collide often. It checks that `Check` triggers exactly the findings at or above the threshold, that `EvaluateFailConditions` with `NewOnly` passes against itself, that `DiffFindings` and `Compare` report nothing for a result compared with itself and never list one entry as both added and removed, and that report.json survives a write, load, write round trip byte for byte. The properties run in the ordinary `go test`; a failure prints the seed and a `-rapid.failfile` to replay it.

## Metamorphic relations

The same file relates two runs whose outputs must agree without knowing either output: shuffling the findings does not change the verdict, adding a finding never turns a failure into a pass, lowering the severity threshold keeps every finding that already triggered, and `Compare(old, new)` lists exactly what `Compare(new, old)` lists with added and removed swapped. The last relation found that entries sharing a name came out in map iteration order.

## Fuzzing

`FuzzParse` (`internal/dex`), `FuzzNewXMLFile` and `FuzzNewTableFile` (`internal/platform/android`) feed arbitrary bytes to the DEX, binary XML and resource table parsers and check that they return an error instead of panicking, and that the decoded string pools and XML stay within a fixed multiple of the input size. `.github/workflows/fuzz.yml` runs each target nightly.

## CLI end-to-end tests

`e2e/atago/*.atago.yaml` runs the built `mobilepkg` binary with [atago](https://github.com/nao1215/atago) on Linux, macOS and Windows: exit codes, `--fail-on`, baselines, compare, error messages, and the commands shown in the README (`make e2e`, `.github/workflows/e2e.yml`).

## Paired CI benchmarks

`bench/himorime.yaml` measures `inspect` on generated APKs with [himorime](https://github.com/nao1215/himorime). On a pull request, `.github/workflows/bench.yml` builds the base and the head and measures them in alternating rounds on the same runner, so runner noise affects both. See [bench/README.md](../bench/README.md).
