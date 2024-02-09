package scanner

import (
	"encoding/hex"
	"strings"
)

func HexDump(data []byte) string {
	dump := hex.Dump(data)
	return dump
}

func extractThreat(scanOutput string) string {
	lines := strings.Split(scanOutput, "\n")
	threatInfo := ""

	for _, line := range lines {
		if strings.HasPrefix(line, "Threat ") {
			threatInfo = line
			break
		}
	}

	if threatInfo != "" {

		threatInfo = strings.Split(threatInfo, ": ")[1]
		return threatInfo
	}

	return "No specific threat information found"
}
