package engine

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	utils "github.com/gatariee/gocheck/utils"
)

func newDefenderScanner(path string) *DefenderScanner {
	return &DefenderScanner{Path: path}
}

const (
	NoThreatFound ScanResult = "NoThreatFound"
	ThreatFound   ScanResult = "ThreatFound"
	ThreatName    ScanResult = "ThreatName"
	FileNotFound  ScanResult = "FileNotFound"
	Timeout       ScanResult = "Timeout"
	Error         ScanResult = "Error"
)

func (ds *DefenderScanner) Scan(filePath string, threat_names chan string) ScanResult {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return FileNotFound
	}

	// TODO: convert to abs before passing into the function, if this errors out- it's not actually handled properly in the caller.
	absFilePath, err := filepath.Abs(filePath)
	if err != nil {
		return Error
	}

	cmd := exec.Command(ds.Path, "-Scan", "-ScanType", "3", "-File", absFilePath, "-DisableRemediation", "-Trace", "-Level", "0x10")
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	cmd.Run()

	stdOut := out.String()

	if strings.Contains(stdOut, "Threat  ") {

		threat := extractThreat(stdOut)
		threat_names <- threat

		return ThreatFound
	}

	return NoThreatFound
}

func HexDump(data []byte) {
	dump := hex.Dump(data)
	fmt.Println(dump)
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

func HalfSplitter(originalArray []byte, lastGood int) []byte {
	newSize := (len(originalArray)-lastGood)/2 + lastGood
	return originalArray[:newSize]
}

func Overshot(originalArray []byte, splitArraySize int) []byte {
	newSize := (len(originalArray)-splitArraySize)/2 + splitArraySize
	return originalArray[:newSize]
}

func Run(token Scanner) {
	scanner := newDefenderScanner(token.EnginePath)
	original_file, err := os.ReadFile(token.File)
	if err != nil {
		fmt.Println(err)
		return
	}

	threat_names := make(chan string)
	threat_list := make([]string, 0)
	go func() {
		for threat := range threat_names {
			threat_list = append(threat_list, threat)
		}
	}()

	size := len(original_file)
	utils.PrintInfo(fmt.Sprintf("Scanning %s, analyzing %d bytes...", token.File, size))

	if scanner.Scan(token.File, threat_names) == NoThreatFound {
		utils.PrintInfo("File looks clean, no threat detected")
		return
	} else {
		utils.PrintErr("Threat detected in the original file, beginning binary search...")
	}

	tempDir := filepath.Join(os.TempDir(), "gocheck")
	os.MkdirAll(tempDir, 0o755)
	testFilePath := filepath.Join(tempDir, "testfile.exe")

	lastGood := 0
	upperBound := len(original_file)
	mid := upperBound / 2
	threatFound := false

	for upperBound-lastGood > 1 {
		// utils.PrintInfo(fmt.Sprintf("scanning from %d to %d bytes", lastGood, mid))

		err := os.WriteFile(testFilePath, original_file[0:mid], 0o644)
		if err != nil {
			utils.PrintErr(fmt.Sprintf("failed to write to test file: %s", err))
			return
		}

		if scanner.Scan(testFilePath, threat_names) == ThreatFound {
			threatFound = true
			upperBound = mid
		} else {
			lastGood = mid
		}

		mid = lastGood + (upperBound-lastGood)/2
	}

	if threatFound {
		utils.PrintNewLine()
		utils.PrintErr(fmt.Sprintf("Isolated bad bytes at offset 0x%X in the original file [approximately %d / %d bytes]", lastGood, lastGood, size))

		start := lastGood - 64
		if start < 0 {
			start = 0
		}

		end := mid + 64
		if end > len(original_file) {
			end = len(original_file)
		}

		threatData := original_file[start:end]
		HexDump(threatData)

		uniqueThreats := make(map[string]bool)
		for _, threat := range threat_list {
			uniqueThreats[threat] = true
		}

		for threat := range uniqueThreats {
			utils.PrintErr(threat)
		}

		utils.PrintNewLine()
	} else {
		utils.PrintInfo("No threat detected")
	}

	os.Remove(testFilePath)
}
