package scanner

type Scanner struct {
	File       string
	Amsi       bool
	Defender   bool
	EnginePath string
}

type ScanResult string

type DefenderScanner struct {
	Path string
}
