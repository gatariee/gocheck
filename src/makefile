BINARY_NAME = GoCheck
BIN_FOLDER = ../binaries

.PHONY: all windows win64 win32

all:
	@echo [*] No default target specified, available targets: windows, win64, win32

windows: win64 win32
	@echo [*] Done compiling for Windows x64 and x86, binary is located at: $(BIN_FOLDER)

win64:
	@echo [*] Building $(BINARY_NAME)64.exe...
	@set GOOS=windows&& set GOARCH=amd64&& go build -o $(BIN_FOLDER)\$(BINARY_NAME)64.exe

win32:
	@echo [*] Building $(BINARY_NAME)32.exe...
	@set GOOS=windows&& set GOARCH=386&& go build -o $(BIN_FOLDER)\$(BINARY_NAME)32.exe
