package engine

import (
	"fmt"
	"os"

	"gocheck/cmd/utils"
)

func Go(token Scanner) {
	/*
		TODO: Add AMSI support
	*/

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

		/* Start the search from the middle of the file */
		mid := low + (high-low)/2

		/* Just to make sure that our mid is never out of bounds */
		if mid > fileSize {
			mid = fileSize
		}

		/* Temporarily write the slice to a file */
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

		/* Send to MpCmdRun.exe */
		flagged, _, err := e.ScanFile(tempFile.Name())
		if err != nil {
			utils.PrintErr(err.Error())
			return
		}

		/* Done scanning, can delete the temp files now */
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

			/* Drop the upper range to the middle if we found malicious bytes */
			high = mid

			/* Save the slice for isolation, incase we can't find a clean range */
			flaggedPart = part
		} else {

			if !ntf {
				/*
					We found the lower range, now we need to find the upper range.
				*/
				utils.PrintInfo(fmt.Sprintf("Found clean bytes in range: %d to %d, attempting to find malicious high range", low, mid))
				ntf = true
			}

			/* Budget solution to find a clean range given an exponential factor */
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

		utils.PrintNewLine()
		utils.PrintErr(fmt.Sprintf("Found %d unique detections", len(initial_threat)))
		for _, threat := range initial_threat {
			utils.PrintOk(fmt.Sprintf("Detected as: %s", threat))
		}

		utils.PrintNewLine()

	} else {

		/*

			KNOWN ISSUES
			Given the nature of malware, it's possible that the 50% middle slice may ignore/overlap malicious bytes.
			This is not accounted for in this POC because I am ~lazy~

		*/

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
