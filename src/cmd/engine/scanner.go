package engine

import (
	"fmt"
	"os"

	"gocheck/cmd/utils"
)

func Go(token Scanner) {
	initial_threat := []string{}

	fileContents, err := os.ReadFile(token.File)
	if err != nil {
		utils.PrintErr(err.Error())
		return
	}

	fileSize := len(fileContents)
	utils.PrintInfo(fmt.Sprintf("Target file size: %d bytes", fileSize))

	e := NewEngine(token.EnginePath)

	utils.PrintNewLine()

	flagged, threat, err := e.ScanFile(token.File)
	if err != nil {
		utils.PrintErr(err.Error())
		return
	}

	if !flagged {
		utils.PrintOk("File is clean!")
		return
	}

	initial_threat = append(initial_threat, threat)

	low, high := 0, fileSize
	var flaggedPart []byte

	ntf := false
	ef := 2 // lower this for more precision
	fp := false

	for low < high {

		mid := low + (high-low)/2

		if mid > fileSize {
			mid = fileSize
		}

		// utils.PrintInfo(fmt.Sprintf("Checking range: %d to %d", low, mid))

		part := fileContents[low:mid]
		tempFile, err := os.CreateTemp("", "gocheck")
		if err != nil {
			utils.PrintErr(err.Error())
			return
		}

		_, err = tempFile.Write(part)
		if err != nil {
			utils.PrintErr(err.Error())
			return
		}
		tempFile.Close()

		flagged, _, err := e.ScanFile(tempFile.Name())
		if err != nil {
			utils.PrintErr(err.Error())
			return
		}

		err = os.Remove(tempFile.Name())
		if err != nil {
			utils.PrintErr(err.Error())
			return
		}

		if flagged {

			if !fp {
				utils.PrintInfo(fmt.Sprintf("Found malicious bytes in range: %d to %d, attempting to isolate slice...", low, mid))
				fp = true
			}

			high = mid
			flaggedPart = part
		} else {

			if !ntf {

				utils.PrintInfo(fmt.Sprintf("Found clean bytes in range: %d to %d, attempting to find malicious high range", low, mid))
				ntf = true
			}
			if ef > 0 {
				low = low + ef
				ef = ef * 3
			}

		}
	}

	if len(flaggedPart) > 0 {
		utils.PrintNewLine()
		utils.PrintOk(fmt.Sprintf("Isolated malicious bytes to range: %d to %d", high-len(flaggedPart), high))
		e.HexDump(flaggedPart)

		// the exact memory address, in the form 0x0000000000000000 (16 bytes)

		utils.PrintNewLine()
		utils.PrintErr(fmt.Sprintf("Found %d unique detections", len(initial_threat)))
		for _, threat := range initial_threat {
			utils.PrintOk(fmt.Sprintf("Detected as: %s", threat))
		}

		utils.PrintNewLine()

	} else {

		utils.PrintNewLine()

		utils.PrintErr("Unable to isolate suspicious range, possibly a bug or partial signatures haven't yet been made by Microsoft.")

		if len(initial_threat) > 0 {
			utils.PrintErr(fmt.Sprintf("We DID find %d unique detections though!", len(initial_threat)))
			for _, threat := range initial_threat {
				utils.PrintOk(fmt.Sprintf("Detected as: %s", threat))
			}
		}

	}
}
