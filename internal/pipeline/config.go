package pipeline

// Config is the resolved CLI input for one pipeline run.
type Config struct {
	Image          string // remote image ref: repo:tag or repo@sha256
	GoMod          string // Go module path (directory)
	SupplierName   string // required; applied by the augment stage (not yet present)
	SkipEnrichment bool   // opt out of the parlay enrich stage
}
