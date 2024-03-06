package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	scanner "github.com/gatariee/gocheck/scanner"
	utils "github.com/gatariee/gocheck/utils"
)

var checkCmd = &cobra.Command{
	Use:   "check [path_to_bin] /optional",
	Short: "",
	Long:  ``,
	Args:  cobra.ExactArgs(1),

	Run: func(cmd *cobra.Command, args []string) {
		/*
			@ previous usage
				file, _ := cmd.Flags().GetString("file")
		*/

		file := args[0]
		amsi, _ := cmd.Flags().GetBool("amsi")
		defender, _ := cmd.Flags().GetBool("defender")
		debug, _ := cmd.Flags().GetBool("debug")
		kaspersky, _ := cmd.Flags().GetBool("kaspersky")

		if debug {
			utils.PrintInfo("Debug mode enabled, verbose output will be displayed")
		}

		var (
			defender_path string
			err           error
		)

		if defender {
			defender_path, err = FindDefenderPath("C:\\")
			if err != nil {
				utils.PrintErr(err.Error())
				return
			}
			utils.PrintInfo(fmt.Sprintf("Found Windows Defender at %s", defender_path))
		} else {
			/* If we're not using defender, we can assume an empty string */
			defender_path = ""
		}

		var avp string
		if kaspersky {
			avp, err = scanner.FindKaspersky()
			if err != nil {
				utils.PrintErr(err.Error())
				return
			}

			if avp == "" {
				utils.PrintErr("Kaspersky not found, please ensure it's installed and the path is correct")
				utils.PrintInfo("Kaspersky is probably installed at > ")
				fmt.Println("\t", scanner.ScanPath)
				fmt.Println("\t", scanner.AltScanPath)
				return
			}

			utils.PrintInfo(fmt.Sprintf("Found Kaspersky at %s", avp))
		}

		additionals := make(map[string]string)
		if kaspersky {
			additionals["kaspersky"] = avp
		}

		token := scanner.Scanner{
			File:       file,
			Amsi:       amsi,
			Defender:   defender,
			EnginePath: defender_path,
			Additional: additionals,
		}

		start := time.Now()
		scanner.Run(token, debug)
		elapsed := time.Since(start)

		utils.PrintOk(fmt.Sprintf("Total time elasped: %s", elapsed))
	},
}

func GetFileSize(file string) (int64, error) {
	fileInfo, err := os.Stat(file)
	if err != nil {
		return 0, err
	}

	return fileInfo.Size(), nil
}

func FindDefenderPath(root string) (string, error) {
	/* We don't want to perform this expensive operation if we don't have to, so let's search common paths first! */
	paths := []string{
		"C:\\Program Files\\Windows Defender\\MpCmdRun.exe",
		"C:\\Program Files (x86)\\Windows Defender\\MpCmdRun.exe",
	}

	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	/* Now, we can panic and search for MpCmdRun.exe */
	utils.PrintErr("Could not find Windows Defender in common paths, searching C:\\ recursively for MpCmdRun.exe...")

	var defenderPath string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {

			/* If error is due to permission, don't panic just yet */
			if os.IsPermission(err) {
				return nil
				/* Keep walking! :) */
			}

			return err
		}
		if !info.IsDir() && strings.Contains(info.Name(), "MpCmdRun.exe") {
			defenderPath = path
			return filepath.SkipDir
		}
		return nil
	})
	return defenderPath, err
}

func init() {
	checkCmd.Flags().BoolP("amsi", "a", false, "Use AMSI to scan the binary")
	checkCmd.Flags().BoolP("defender", "d", false, "Use Windows Defender to scan the binary")
	checkCmd.Flags().BoolP("kaspersky", "k", false, "Use Kaspersky to scan the binary")
	checkCmd.Flags().BoolP("debug", "D", false, "Enable debug mode")
}
