package main

import (
	"os"
	"strings"

	"github.com/gatariee/gocheck/cmd"
)

func main() {
	/* If the second arg ends with a .exe, we'll just assume that the user meant to run the check command */
	if len(os.Args) > 1 && strings.HasSuffix(os.Args[1], ".exe") {
		/*
			What are you gonna do about it? (ง'̀-'́)ง
		*/
		os.Args = append([]string{os.Args[0], "check"}, os.Args[1:]...)
	}

	cmd.Execute()
}
