package scanner

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	utils "github.com/gatariee/gocheck/utils"
)

type DefenderScanner struct {
	Path string
}

type ScanResult string

type Progress struct {
	Low       int
	High      int
	Malicious bool
}

const (
	NoThreatFound ScanResult = "NoThreatFound"
	ThreatFound   ScanResult = "ThreatFound"
	ThreatName    ScanResult = "ThreatName"
	FileNotFound  ScanResult = "FileNotFound"
	Timeout       ScanResult = "Timeout"
	Error         ScanResult = "Error"
)

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

func ScanWindef(token Scanner, debug bool) error {
	/* Setup */
	scanner := newDefenderScanner(token.EnginePath)
	start := time.Now()
	
	ticker := time.NewTicker(time.Duration(2 * float64(time.Second)))
	defer ticker.Stop()
	progressUpdates := make(chan Progress)
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ticker.C:
				progress, ok := <-progressUpdates
				if !ok {
					return
				}
				current := time.Since(start)
				utils.PrintErr(fmt.Sprintf("0x%X -> 0x%X - malicious: %t - %s", progress.Low, progress.High, progress.Malicious, current))
			case _, ok := <-progressUpdates:
				/* ticker.C is not ready, but the channel is closed- we don't want the scanner to wait for ticker.C to reopen */
				if !ok {
					return
				}
			}
		}
	}()

	utils.PrintDebug(fmt.Sprintf("Scanning %s with Windows Defender...", token.File), debug)

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
		utils.PrintInfo("Threat detected in the original file, beginning binary search...")
	}

	utils.PrintNewLine()

	/* Create a temporary directory to store the scanning files */
	tempDir := filepath.Join(".", "windef")

	/* TODO: Check whether the parent directory has an exclusion, or to perform a sanity check to ensure that MpCmdRun.exe is actually working */
	os.MkdirAll(tempDir, 0o755)
	testFilePath := filepath.Join(tempDir, "testfile.exe")

	lastGood := 0                    // lower range
	upperBound := len(original_file) // upper range
	mid := upperBound / 2            // pivot point

	threatFound := false
	tf_lower := 0
	tf_upper := upperBound
	tnf_upper := upperBound

	for upperBound-lastGood > 1 {
		// utils.PrintInfo(fmt.Sprintf("scanning from %d to %d bytes", lastGood, mid))

		err := os.WriteFile(testFilePath, original_file[tf_lower:mid], 0o644)
		if err != nil {
			utils.PrintErr(fmt.Sprintf("failed to write to test file: %s", err))
			return err
		}

		utils.PrintDebug(fmt.Sprintf("scanning from 0 to %d bytes", mid), debug)

		if scanner.Scan(testFilePath, threat_names) == ThreatFound {
			progressUpdates <- Progress{Low: tf_lower, High: mid, Malicious: true}

			utils.PrintDebug(fmt.Sprintf("threat detected in the range 0 to %d bytes", mid), debug)

			/*
				Since we found a threat in the slice, we'll set the upper range to whatever the pivot point is.
			*/
			threatFound = true
			upperBound = mid

			/* Save the last found threat range */
			tf_upper = mid
		} else {
			progressUpdates <- Progress{Low: tf_lower, High: mid, Malicious: false}
			utils.PrintDebug(fmt.Sprintf("no threat detected in the range 0 to %d bytes", mid), debug)
			/*
				We didn't find a threat in this slice, so we flip to the other half of the slice.
			*/
			lastGood = mid // lower range becomes the pivot (middle)
			tnf_upper = mid
		}

		mid = lastGood + (upperBound-lastGood)/2

		utils.PrintDebugNewLine(debug)
	}

	/* Binary search is over, let's start cleaning up */
	os.RemoveAll(tempDir) // incase the defer doesn't work for some reason
	end := time.Since(start)

	if threatFound {

		if debug {

			if _, err := os.Stat("debug"); os.IsNotExist(err) {
				os.Mkdir("debug", 0o755)
			} else {
				utils.PrintInfo("debug directory already exists, deleting contents and creating new files")
				os.RemoveAll("debug")
				utils.PrintOk("deleted debug directory")
				os.Mkdir("debug", 0o755)
			}

			utils.PrintDebugNewLine(debug)

			utils.PrintDebug(fmt.Sprintf("%d to %d bytes were: NOT MALICIOUS ", tf_lower, tnf_upper), debug)
			utils.PrintDebug(fmt.Sprintf("%d to %d bytes were: MALICIOUS ", tf_lower, tf_upper), debug)

			err = os.WriteFile("./debug/last_bad_bytes.exe", original_file[tf_lower:tf_upper], 0o644)
			if err != nil {
				utils.PrintErr(fmt.Sprintf("failed to write to last_bad_bytes.exe: %s", err))
				return err
			}

			utils.PrintInfo("Saving last bad bytes to: last_bad_bytes.exe")

			file, err := os.ReadFile("./debug/last_bad_bytes.exe")
			if err != nil {
				utils.PrintErr(fmt.Sprintf("failed to read last_bad_bytes.exe: %s", err))
				return err
			}
			fs := len(file)
			utils.PrintInfo(fmt.Sprintf("Scanning last_bad_bytes.exe, analyzing %d bytes...", fs))

			if scanner.Scan("./debug/last_bad_bytes.exe", threat_names) == ThreatFound {
				utils.PrintOk(fmt.Sprintf("Sanity check passed, windows defender detected a threat in 'last_bad_bytes.exe' [0x0 to 0x%X]", fs))
			} else {
				utils.PrintErr("Sanity check failed, windows defender did not detect a threat in the last bad bytes")
			}

			utils.PrintDebugNewLine(debug)
			utils.PrintInfo("Saving last good bytes to: last_good_bytes.exe")

			err = os.WriteFile("./debug/last_good_bytes.exe", original_file[tf_lower:tnf_upper], 0o644)
			if err != nil {
				utils.PrintErr(fmt.Sprintf("failed to write to last_good_bytes.exe: %s", err))
				return err
			}
			file, err = os.ReadFile("./debug/last_good_bytes.exe")
			if err != nil {
				utils.PrintErr(fmt.Sprintf("failed to read last_good_bytes.exe: %s", err))
				return err
			}

			fs = len(file)
			utils.PrintInfo(fmt.Sprintf("Scanning last_good_bytes.exe, analyzing %d bytes...", fs))

			if scanner.Scan("last_good_bytes.bin", threat_names) == ThreatFound {
				utils.PrintErr(fmt.Sprintf("Sanity check failed, windows defender detected a threat in 'last_good_bytes.exe' [0x0 to 0x%X]", fs))
			} else {
				utils.PrintOk(fmt.Sprintf("Sanity check passed, windows defender did not detect a threat in 'last_good_bytes.exe' [0x0 to 0x%X]", fs))
			}

			utils.PrintDebugNewLine(debug)
		}

		/*
			This only hits once the binary search has been exhausted, i.e: the range between the upperBound and lastGood is 0
			TODO: Check if an off-by-one error appears here for binaries with an odd number of bytes lol.
		*/

		utils.PrintNewLine()

		utils.PrintOk(fmt.Sprintf("Windows Defender - %s", end))
		utils.PrintErr(fmt.Sprintf("Isolated bad bytes at offset 0x%X in the original file [approximately %d / %d bytes]", lastGood, lastGood, size))

		/* Add 32 bytes before the offset */
		start := lastGood - 32
		if start < 0 {
			start = 0
		}

		/* Add 32 bytes after the offset */
		end := mid + 32
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
			utils.PrintInfo(threat)
		}

		utils.PrintNewLine()
	} else {
		utils.PrintInfo("No threat detected, but the original file was flagged as malicious. The bad bytes are likely at the very end of the binary.")
	}

	/* End */
	ticker.Stop()
	os.Remove(testFilePath)
	close(progressUpdates)
	close(threat_names)

	return nil
}
