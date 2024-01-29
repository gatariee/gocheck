package engine

import (
	"bytes"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

type Engine struct {
	Path string
}

func NewEngine(path string) *Engine {
	return &Engine{Path: path}
}

func (e *Engine) ScanFile(filePath string) (bool, string, error) {

	absFilePath, err := filepath.Abs(filePath)
	if err != nil {
		return false, "", err
	}

	cmd := exec.Command(e.Path, "-Scan", "-ScanType", "3", "-File", absFilePath, "-DisableRemediation", "-Trace", "-Level", "0x10")
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	/* For whatever reason, Windows Defender exits with a non-standard error code when it detects a threat. /shrug */
	cmd.Run()

	stdOut := out.String()

	if strings.Contains(stdOut, "Threat  ") {

		threat := e.extractThreat(stdOut)
		return true, threat, nil
	}

	return false, "", nil
}

func (e *Engine) HexDump(data []byte) {
	/*
		creds: https://github.com/matterpreter/DefenderCheck/blob/master/DefenderCheck/DefenderCheck/Program.cs
	*/

	const bytesPerLine = 16

	for i := 0; i < len(data); i += bytesPerLine {
		fmt.Printf("%06x: ", i)

		for j := 0; j < bytesPerLine; j++ {
			if i+j < len(data) {
				fmt.Printf("%02x ", data[i+j])
			} else {
				fmt.Print("   ")
			}
		}

		fmt.Print(" |")
		for j := 0; j < bytesPerLine; j++ {
			if i+j < len(data) {
				if data[i+j] >= 32 && data[i+j] <= 126 {
					fmt.Printf("%c", data[i+j])
				} else {
					fmt.Print(".")
				}
			}
		}
		fmt.Println("|")
	}
}

func (e *Engine) extractThreat(scanOutput string) string {
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
