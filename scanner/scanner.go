package scanner

import (
	utils "github.com/gatariee/gocheck/utils"
)

type Scanner struct {
	File       string
	Amsi       bool
	Defender   bool
	EnginePath string
}

type ScanResult string

const (
	NoThreatFound ScanResult = "NoThreatFound"
	ThreatFound   ScanResult = "ThreatFound"
	ThreatName    ScanResult = "ThreatName"
	FileNotFound  ScanResult = "FileNotFound"
	Timeout       ScanResult = "Timeout"
	Error         ScanResult = "Error"
)

func Run(token Scanner, debug bool) {
	if token.Defender {
		err := ScanWindef(token, debug)
		if err != nil {
			utils.PrintErr(err.Error())
		}
	}

	if token.Amsi {
		err := ScanAMSI(token.File, debug)
		if err != nil {
			utils.PrintErr(err.Error())
		}
	}
}
