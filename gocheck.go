package main

import (
	"os"
	"strings"

	"github.com/gatariee/gocheck/cmd"
)

var suffixes = []string{".exe", ".dll", ".sys", ".drv", ".ps1"}

func main() {
	if len(os.Args) > 1 {
		for _, suffix := range suffixes {
			if strings.HasSuffix(os.Args[1], suffix) {
				os.Args = append([]string{os.Args[0], "check"}, os.Args[1:]...)
			}
		}
	}
	/*
		What are you gonna do about it? (ง'̀-'́)ง
	*/

	cmd.Execute()
}
