package scanner

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	utils "github.com/gatariee/gocheck/utils"
)

type DefenderScanner struct {
	Path string
}

func newDefenderScanner(path string) *DefenderScanner {
	return &DefenderScanner{Path: path}
}

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

		/* yeah, there has to be a better way to do this. */
		threat_names <- threat

		return ThreatFound
	}

	return NoThreatFound
}

func ScanWindef(token Scanner) error {
	/* Setup */
	scanner := newDefenderScanner(token.EnginePath)
	original_file, err := os.ReadFile(token.File)
	if err != nil {
		return err
	}

	/* Setup a channel to keep track of threat names */
	threat_names := make(chan string)
	threat_list := make([]string, 0)
	go func() {
		for threat := range threat_names {
			threat_list = append(threat_list, threat)
		}
	}()

	size := len(original_file)
	utils.PrintInfo(fmt.Sprintf("Scanning %s, analyzing %d bytes...", token.File, size))

	/* Scan the original file, if the original file isn't flagged as malicious, don't begin the binary search */
	if scanner.Scan(token.File, threat_names) == NoThreatFound {
		utils.PrintInfo("File looks clean, no threat detected")
		return nil
	} else {
		utils.PrintErr("Threat detected in the original file, beginning binary search...")
	}

	/* Create a temporary directory to store the scanning files */
	tempDir := filepath.Join(os.TempDir(), "gocheck")

	/* TODO: Check whether the parent directory has an exclusion, or to perform a sanity check to ensure that MpCmdRun.exe is actually working */
	os.MkdirAll(tempDir, 0o755)
	testFilePath := filepath.Join(tempDir, "testfile.exe")

	lastGood := 0                    // lower range
	upperBound := len(original_file) // upper range
	mid := upperBound / 2            // pivot point
	threatFound := false

	for upperBound-lastGood > 1 {
		// utils.PrintInfo(fmt.Sprintf("scanning from %d to %d bytes", lastGood, mid))

		err := os.WriteFile(testFilePath, original_file[0:mid], 0o644)
		if err != nil {
			utils.PrintErr(fmt.Sprintf("failed to write to test file: %s", err))
			return err
		}

		if scanner.Scan(testFilePath, threat_names) == ThreatFound {

			/*
				Since we found a threat in the slice, we'll set the upper range to whatever the pivot point is.
			*/
			threatFound = true
			upperBound = mid
		} else {
			/*
				We didn't find a threat in this slice, so we flip to the other half of the slice.
			*/
			lastGood = mid // lower range becomes the pivot (middle)
		}

		mid = lastGood + (upperBound-lastGood)/2
	}

	if threatFound {

		/*
			This only hits once the binary search has been exhausted, i.e: the range between the upperBound and lastGood is 0
			TODO: Check if an off-by-one error appears here for binaries with an odd number of bytes lol.
		*/

		utils.PrintNewLine()
		utils.PrintErr(fmt.Sprintf("Isolated bad bytes at offset 0x%X in the original file [approximately %d / %d bytes]", lastGood, lastGood, size))

		/* Add 64 bytes before the offset */
		start := lastGood - 64
		if start < 0 {
			start = 0
		}

		/* Add 64 bytes after the offset */
		end := mid + 64
		if end > len(original_file) {
			end = len(original_file)
		}

		/* Start printing the hex dump */
		threatData := original_file[start:end]
		fmt.Println(HexDump(threatData))

		uniqueThreats := make(map[string]bool)
		for _, threat := range threat_list {
			uniqueThreats[threat] = true
		}

		for threat := range uniqueThreats {
			utils.PrintErr(threat)
		}

		utils.PrintNewLine()
	} else {
		utils.PrintInfo("No threat detected, but the original file was flagged as malicious. The bad bytes are likely at the very end of the binary.")
	}

	/* End */
	os.Remove(testFilePath)
	close(threat_names)
	return nil
}
