package mobilepkg

import (
	"context"
	"runtime"
	"sync"
)

// BatchOptions controls the behaviour of [InspectFiles].
type BatchOptions struct {
	InspectOptions
	// Concurrency sets the maximum number of files inspected in parallel.
	// Zero or negative means runtime.NumCPU().
	Concurrency int
}

// BatchResult pairs a file path with its inspection outcome.
type BatchResult struct {
	// Path is the file path that was inspected.
	Path string
	// Report holds the inspection result on success.
	Report Report
	// Err is non-nil when the file could not be inspected.
	Err error
}

// InspectFiles inspects multiple files concurrently and returns a
// [BatchResult] for each input path. Results are returned in the same
// order as paths. If ctx is cancelled, remaining files are skipped.
func InspectFiles(ctx context.Context, paths []string, opts BatchOptions) []BatchResult {
	results := make([]BatchResult, len(paths))

	conc := opts.Concurrency
	if conc <= 0 {
		conc = runtime.NumCPU()
	}

	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup

	for i, p := range paths {
		results[i].Path = p

		if ctx.Err() != nil {
			results[i].Err = ctx.Err()
			continue
		}

		wg.Add(1)
		go func(idx int, path string) {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			if ctx.Err() != nil {
				results[idx].Err = ctx.Err()
				return
			}

			report, err := InspectFile(ctx, path, opts.InspectOptions)
			results[idx].Report = report
			results[idx].Err = err
		}(i, p)
	}

	wg.Wait()
	return results
}
