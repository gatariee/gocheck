package engine

type Scanner struct {
	File       string
	Amsi       bool
	Defender   bool
	EnginePath string
}

type ScanResult struct {
	Flagged              bool
	FlaggedByte          byte
	FlaggedByteIndex     int
	LastFlaggedByteIndex int
}