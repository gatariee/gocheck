package scanner

import (
	"sync"

	utils "github.com/gatariee/gocheck/utils"
)

type Scanner struct {
	File       string
	Amsi       bool
	Defender   bool
	EnginePath string
}

func Run(token Scanner, debug bool) {
	var wg sync.WaitGroup
	errors := make(chan error, 2)

	if token.Defender {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := ScanWindef(token, debug)
			if err != nil {
				errors <- err
			}
		}()
	}

	if token.Amsi {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := ScanAMSI(token.File, debug)
			if err != nil {
				errors <- err
			}
		}()
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		if err != nil {
			utils.PrintErr(err.Error())
		}
	}
}
