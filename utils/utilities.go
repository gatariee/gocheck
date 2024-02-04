package utils

import (
	"fmt"
)

func PrintNewLine() {
	fmt.Println("")
}

func Print(msg string) {
	fmt.Println(msg)
}

func PrintOk(msg string) {
	fmt.Println("[+]", msg)
}

func PrintInfo(msg string) {
	fmt.Println("[*]", msg)
}

func PrintErr(msg string) {
	fmt.Println("[!]", msg)
}