package utils

import (
	"fmt"
	"os"
	"github.com/fatih/color"
)

func PrintNewLine() {
	fmt.Println("")
}

func Print(msg string) {
	fmt.Println(msg)
}

func PrintOk(msg string) {
	color.HiGreen(fmt.Sprintf("[+] %s", msg))
}

func PrintInfo(msg string) {
	color.Yellow(fmt.Sprintf("[*] %s", msg))
}

func PrintErr(msg string) {
	color.HiRed(fmt.Sprintf("[!] %s", msg))
}

func PrintDebug(msg string, debug bool) {
	if debug {
		fmt.Println("[DEBUG]", msg)
	}
}

func PrintDebugNewLine(debug bool) {
	if debug {
		fmt.Println("")
	}
}

func CheckIfExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
