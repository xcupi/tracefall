package memory

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// AnalysisSchema marks a document written by Collect.
const AnalysisSchema = "tracefall.memory-analysis/1"

// Plugin statuses.
const (
	StatusOK     = "ok"
	StatusFailed = "failed"
)

// PluginResult is one Volatility plugin's outcome.
type PluginResult struct {
	// Logical is Tracefall's name for what was asked (pslist, netscan...).
	Logical string `json:"logical"`
	// Plugin is the Volatility plugin that actually ran.
	Plugin  string           `json:"plugin"`
	Status  string           `json:"status"`
	Error   string           `json:"error,omitempty"`
	Seconds float64          `json:"seconds"`
	Rows    []map[string]any `json:"rows"`
}

// Analysis is everything Volatility reported for one memory image, in one
// document. Keeping it as ONE file (not one per plugin) is deliberate:
// the events it yields join across plugins (a process from pslist with its
// command line from cmdline), and a join across separately imported files
// would depend on the order they happened to be extracted in.
type Analysis struct {
	Schema      string            `json:"schema"`
	Volatility  string            `json:"volatility_version"`
	Isolation   string            `json:"isolation"`
	ImageName   string            `json:"image_name"`
	ImageSize   int64             `json:"image_size"`
	CollectedAt time.Time         `json:"collected_at"`
	Info        map[string]string `json:"info"`
	Plugins     []PluginResult    `json:"plugins"`
}

// plan is the ordered set of plugins, by logical name, with the names
// each has had across Volatility releases.
var plan = []struct {
	logical    string
	candidates []string
}{
	{"pslist", []string{"windows.pslist.PsList"}},
	{"psscan", []string{"windows.psscan.PsScan"}},
	{"cmdline", []string{"windows.cmdline.CmdLine"}},
	{"netscan", []string{"windows.netscan.NetScan"}},
	{"malfind", []string{"windows.malware.malfind.Malfind", "windows.malfind.Malfind"}},
	{"svcscan", []string{"windows.svcscan.SvcScan"}},
	// What was typed into command prompts. Volatility 3 reads these from
	// conhost.exe, so an image of a Windows that hosted consoles elsewhere
	// yields no rows from either; the parser says so rather than implying
	// that nothing was typed.
	{"cmdscan", []string{"windows.cmdscan.CmdScan"}},
	{"consoles", []string{"windows.consoles.Consoles"}},
	// File objects the kernel still has: files that were open or cached at
	// capture, including some that no longer exist on disk.
	{"filescan", []string{"windows.filescan.FileScan"}},
}

const infoPlugin = "windows.info.Info"

// Identity is what Volatility says about an image before any analysis.
type Identity struct {
	Volatility string            `json:"volatility_version"`
	Isolation  string            `json:"isolation"`
	Info       map[string]string `json:"info"`
	available  map[string]bool
}

// Identify runs windows.info, the cheapest plugin that proves Volatility
// can read the image at all. It fails with ErrSymbols when it cannot.
func Identify(ctx context.Context, r *Runner, image string) (Identity, error) {
	id := Identity{Isolation: string(r.Isolation()), Info: map[string]string{}}
	version, err := r.Version(ctx)
	if err != nil {
		return id, err
	}
	id.Volatility = version
	if id.available, err = r.Plugins(ctx); err != nil {
		return id, err
	}
	out, _, err := r.Run(ctx, image, infoPlugin)
	if err != nil {
		return id, fmt.Errorf("identifying the image: %w", err)
	}
	rows, err := ParseRows(out)
	if err != nil {
		return id, err
	}
	for _, row := range rows {
		k, _ := row["Variable"].(string)
		v, _ := row["Value"].(string)
		if k != "" {
			id.Info[k] = v
		}
	}
	return id, nil
}

// Collect runs the Windows plugin set against image.
//
// windows.info runs first and must succeed: if Volatility cannot identify
// the image, nothing else is attempted and the error says why. After that,
// a plugin that fails is recorded with its error and the rest continue,
// because plugins break independently across Windows builds and losing the
// process list to a netscan failure would be a worse outcome than a gap
// that is stated.
func Collect(ctx context.Context, r *Runner, image string, progress func(plugin string)) (Analysis, error) {
	if err := ctx.Err(); err != nil {
		return Analysis{}, err
	}
	st, err := os.Stat(image)
	if err != nil {
		return Analysis{}, err
	}
	id, err := Identify(ctx, r, image)
	a := Analysis{
		Schema: AnalysisSchema, Volatility: id.Volatility, Isolation: id.Isolation,
		ImageName: filepath.Base(image), ImageSize: st.Size(), CollectedAt: time.Now().UTC(),
		Info: id.Info, Plugins: []PluginResult{},
	}
	if err != nil {
		return a, err
	}
	version := id.Volatility
	available := id.available
	if progress != nil {
		progress(infoPlugin)
	}

	for _, p := range plan {
		if err := ctx.Err(); err != nil {
			return a, err
		}
		res := PluginResult{Logical: p.logical, Status: StatusFailed, Rows: []map[string]any{}}
		name, ok := ResolvePlugin(available, p.candidates...)
		if !ok {
			res.Plugin = p.candidates[0]
			res.Error = fmt.Sprintf("this Volatility (%s) does not offer %s", version, p.candidates[0])
			a.Plugins = append(a.Plugins, res)
			continue
		}
		res.Plugin = name
		if progress != nil {
			progress(name)
		}
		start := time.Now()
		raw, _, err := r.Run(ctx, image, name)
		res.Seconds = time.Since(start).Seconds()
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return a, err
			}
			res.Error = err.Error()
			a.Plugins = append(a.Plugins, res)
			continue
		}
		rows, err := ParseRows(raw)
		if err != nil {
			res.Error = err.Error()
			a.Plugins = append(a.Plugins, res)
			continue
		}
		res.Status, res.Rows = StatusOK, rows
		a.Plugins = append(a.Plugins, res)
	}
	return a, nil
}
