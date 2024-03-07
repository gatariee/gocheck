package scanner

import (
	"strings"
)

/*
	Eventually, all scanning modules will be ported to this  file; including Windows Defender.
*/

func IsMalicious(output string, detectionString string) bool {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, detectionString) {
			return true
		}
	}
	return false
}

func GetSignature(output string, sigString string) string {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, sigString) {
			parts := strings.Fields(line)
			for _, part := range parts {
				if strings.Contains(part, sigString) {
					return part
				}
			}
		}
	}

	return "No signature found"
}
