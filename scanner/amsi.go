package scanner

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/garethjensen/amsi"

	utils "github.com/gatariee/gocheck/utils"
)

type AMSIScanner struct{}

func newAMSIScanner() *AMSIScanner {
	return &AMSIScanner{}
}

func (as *AMSIScanner) Scan(filePath string) (amsi.ScanResult, error) {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return 0, err
	}

	fileData, err := os.ReadFile(filePath)
	if err != nil {
		return 0, err
	}

	err = amsi.Initialize()
	if err != nil {
		return 0, err
	}
	defer amsi.Uninitialize()

	session := amsi.OpenSession()
	defer amsi.CloseSession(session)

	// sample := []byte("AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386")
	/* Thanks, Rasta :P */
	/* https://github.com/rasta-mouse/ThreatCheck/blob/master/ThreatCheck/ThreatCheck/Amsi/AmsiInstance.cs */
	// test := session.ScanBuffer(sample)
	// fmt.Println(test)

	result := session.ScanBuffer(fileData)
	return result, nil
}

func (as *AMSIScanner) Go(amsi_instance *AMSIScanner, file_path string) (int, error) {
	start, err := os.ReadFile(file_path)
	if err != nil {
		return 0, err
	}
	size := len(start)
	utils.PrintInfo(fmt.Sprintf("Scanning %s, analyzing %d bytes...", file_path, size))

	tempDir := filepath.Join(".", "temp")
	err = os.MkdirAll(tempDir, 0o755)
	if err != nil {
		return 0, err
	}

	testFilePath := filepath.Join(tempDir, "test")
	defer os.RemoveAll(tempDir)

	lastGood := 0
	upperBound := len(start)
	mid := upperBound / 2
	ok := false

	for upperBound-lastGood > 1 {
		err := os.WriteFile(testFilePath, start[0:mid], 0o644)
		if err != nil {
			return 0, err
		}

		result, err := amsi_instance.Scan(testFilePath)
		if err != nil {
			return 0, err
		}

		if result == amsi.ResultDetected {
			upperBound = mid
			ok = true

		} else {
			lastGood = mid
		}

		mid = (upperBound + lastGood) / 2
	}

	if !ok {
		return 0, fmt.Errorf("unable to isolate bad bytes, uh oh. :(")
	}

	return mid, nil
}

func ScanAMSI(filePath string) error {
	scanner := newAMSIScanner()
	original_file, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	result, err := scanner.Scan(filePath)
	if err != nil {
		return err
	}

	switch result {
	/*
		https://learn.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result
	*/

	case amsi.ResultClean:
		utils.PrintInfo("No threats found, got 'AMSI_RESULT_CLEAN'")
		return nil
	case amsi.ResultNotDetected:
		utils.PrintInfo("No threats found, got 'AMSI_RESULT_NOT_DETECTED'")
		return nil
	case amsi.ResultBlockedByAdminStart:
		utils.PrintErr("Scan was blocked for some reason, got 'AMSI_RESULT_BLOCKED_BY_ADMIN_START'")
	case amsi.ResultBlockedByAdminEnd:
		utils.PrintErr("Scan was blocked for some reason, got 'AMSI_RESULT_BLOCKED_BY_ADMIN_END'")
	case amsi.ResultDetected:
		/* Continue, let's do our binary search now! */
		utils.PrintInfo("Threat detected in original file, beginning AMSI binary search...")
		offset, err := scanner.Go(scanner, filePath)
		if err != nil {
			return err
		}

		utils.PrintInfo(fmt.Sprintf("Isolated bad bytes at offset 0x%X in the original file [approximately %d / %d bytes]", offset, offset, len(original_file)))

		start := offset - 64
		if start < 0 {
			start = 0
		}

		end := offset + 64
		if end > len(original_file) {
			end = len(original_file)
		}

		/* Start printing the hex dump */
		threatData := original_file[start:end]
		fmt.Println(HexDump(threatData))

	default:
		utils.PrintErr(fmt.Sprintf("Unknown result: %d", result))
	}

	return nil
}