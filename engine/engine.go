package engine

import (
	"bytes"
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
