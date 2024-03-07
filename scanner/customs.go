package scanner

/*
there are plans to add more scanners in the future, so we need to make sure that the scanner interface is implemented properly.
	* as of [7/3/2024] im lazy to do this, so i'll just hardcode the vendors into a struct and manually parse them XD

var scanners = map[string]CustomScanner{
	"Kaspersky": {
		...
	},
	"Elastic": {
		...
	}
}

type Scanner interface {
	Scan(file string, scanPath string, args ...string) (string, error)
	IsMalicious(output string, detectionString string) bool
	GetSignature(output string) string
}

*/

type CustomScanner struct {
	ScanPath        string
	AltScanPath     string
	DetectionString string
	SignatureString string
	Arguments       []string
}

var Kaspersky = CustomScanner{
	ScanPath:        "C:\\Program Files (x86)\\Kaspersky Lab\\Kaspersky Security Cloud 21.3\\avp.com",
	AltScanPath:     "C:\\Program Files\\Kaspersky Lab\\Kaspersky Security Cloud 21.3\\avp.com",
	DetectionString: "suspicion",
	SignatureString: "HEUR:",
	Arguments:       []string{"SCAN", "/i0"},
}
