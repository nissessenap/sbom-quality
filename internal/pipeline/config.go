package pipeline

// Config is the resolved CLI input for one pipeline run.
type Config struct {
	Image        string // remote image ref: repo:tag or repo@sha256
	SupplierName string // required; applied by the augment stage (not yet present)
}
