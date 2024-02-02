# GoCheck
> Heavily inspired by [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) and [DefenderCheck](https://github.com/matterpreter/DefenderCheck)

GoCheck a blazingly fast™ alternative to Matterpreter's [DefenderCheck](https://github.com/matterpreter/DefenderCheck) which identifies the exact bytes that Windows Defender AV by feeding byte slices to `MpCmdRun.exe`.

![GoCheck2](./assets/gocheck_windef.gif)

## Usage
```cmd
$ ./GoCheck64.exe check --help
Usage:
  gocheck check [flags]

Flags:
  -a, --amsi          Use AMSI to scan the binary
  -d, --defender      Use Windows Defender to scan the binary
  -f, --file string   Binary to check
  -h, --help          help for check
```

## Installation
Download the latest release from the [releases](https://github.com/gatariee/GoCheck/releases), or build it from source.
```bash
git clone https://github.com/gatariee/GoCheck
cd gocheck/src
make windows
```

## Benchmark

## mimikatz.exe (1,250,056 bytes / 1.19 MB)

| Tool | Time |
|------|------|
| GoCheck | 1.05s |
| DefenderCheck | 5.56s |

![comparison1](./assets/38138d0696414c4828e0caf498a8f0e1.png)

## Sliver HTTP Beacon (10,972,160 bytes / 10.4 MB)

| Tool | Time |
|------|------|
| GoCheck | 5.65s |
| DefenderCheck | 35.69s |

![comparison2](./assets/8bf97de7a1fd7b1a6d56362b3eaad39b.png)
