# GoCheck
> Heavily inspired by [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) and [DefenderCheck](https://github.com/matterpreter/DefenderCheck)

GoCheck is a tool for identifying exact bytes that are flagged by Windows Defender by splitting a file into chunks and feeding them to `MpCmdRun.exe`.

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

## Example (Cobalt Strike Beacon)
```cmd
$ ./GoCheck64.exe check --file ../tests/default_cobalt_beacon.exe --defender
[*] Found Windows Defender at C:\Program Files\Windows Defender\MpCmdRun.exe
[*] Target file size: 328704 bytes

[*] Found malicious bytes in range: 0 to 164352, attempting to isolate slice...
[*] Found clean bytes in range: 0 to 1284, attempting to find malicious high range

[+] Isolated malicious bytes to range: 0 to 2568
0007c0: 85 c9 0f 84 e6 00 00 00 8b 15 3a 1c 05 00 85 d2  |..........:.....|
0007d0: 0f 84 9a 00 00 00 48 81 c4 98 00 00 00 5b 5e 5f  |......H......[^_|
0007e0: 5d 41 5c 41 5d c3 66 2e 0f 1f 84 00 00 00 00 00  |]A\A].f.........|
0007f0: 0f b7 44 24 60 e9 0e ff ff ff 66 0f 1f 44 00 00  |..D$`.....f..D..|
000800: 48 8b 35 09 f0 04 00 bd 01 00 00 00 8b 06 83 f8  |H.5.............|
000810: 01 0f 85 f3 fd ff ff b9 1f 00 00 00 e8 6f 1a 00  |.............o..|
000820: 00 8b 06 83 f8 01 0f 85 fd fd ff ff 48 8b 15 fd  |............H...|
000830: ef 04 00 48 8b 0d e6 ef 04 00 e8 41 1a 00 00 c7  |...H.......A....|
000840: 06 02 00 00 00 85 ed 0f 85 e4 fd ff ff 31 c0 48  |.............1.H|
000850: 87 03 e9 da fd ff ff 66 0f 1f 84 00 00 00 00 00  |.......f........|
000860: 4c 89 c1 ff 15 23 2e 05 00 e9 46 fd ff ff 66 90  |L....#....F...f.|
000870: e8 13 1a 00 00 8b 05 95 1b 05 00 48 81 c4 98 00  |...........H....|
000880: 00 00 5b 5e 5f 5d 41 5c 41 5d c3 0f 1f 44 00 00  |..[^_]A\A]...D..|
000890: 48 8b 15 b9 ef 04 00 48 8b 0d a2 ef 04 00 c7 06  |H......H........|
0008a0: 01 00 00 00 e8 d7 19 00 00 e9 70 fd ff ff 89 c1  |..........p.....|
0008b0: e8 ab 19 00 00 90 66 2e 0f 1f 84 00 00 00 00 00  |......f.........|
0008c0: 48 83 ec 28 48 8b 05 f5 ef 04 00 c7 00 01 00 00  |H..(H...........|
0008d0: 00 e8 ba 04 00 00 e8 a5 fc ff ff 90 90 48 83 c4  |.............H..|
0008e0: 28 c3 66 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 00  |(.ff............|
0008f0: 48 83 ec 28 48 8b 05 c5 ef 04 00 c7 00 00 00 00  |H..(H...........|
000900: 00 e8 8a 04 00 00 e8 75 fc ff ff 90 90 48 83 c4  |.......u.....H..|
000910: 28 c3 66 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 00  |(.ff............|
000920: 48 83 ec 28 e8 4f 19 00 00 48 85 c0 0f 94 c0 0f  |H..(.O...H......|
000930: b6 c0 f7 d8 48 83 c4 28 c3 90 90 90 90 90 90 90  |....H..(........|
000940: 48 8d 0d 09 00 00 00 e9 d4 ff ff ff 0f 1f 40 00  |H.............@.|
000950: c3 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90  |................|
000960: 48 ff e1 48 63 05 c2 2a 00 00 85 c0 7e 26 83 3d  |H..Hc..*....~&.=|
000970: bb 2a 00 00 00 7e 1d 48 8b 15 fe 2c 05 00 48 89  |.*...~.H...,..H.|
000980: 14 01 48 8b 15 fb 2c 05 00 48 63 05 a0 2a 00 00  |..H...,..Hc..*..|
000990: 48 89 14 01 c3 41 54 55 57 56 53 48 83 ec 40 41  |H....ATUWVSH..@A|
0009a0: b9 04 00 00 00 4c 63 e2 48 89 cf 4c 89 c5 31 c9  |.....Lc.H..L..1.|
0009b0: 41 b8 00 30 00 00 4c 89 e2 4c 89 e6 ff 15 4a 2d  |A..0..L..L....J-|
0009c0: 05 00 48 89 c3 31 c0 39 c6 7e 15 48 89 c2 83 e2  |..H..1.9.~.H....|
0009d0: 03 8a 54 15 00 32 14 07 88 14 03 48 ff c0 eb e7  |..T..2.....H....|
0009e0: 48 89 d9 e8 7b ff ff ff 4c 8d 4c 24 3c 4c 89 e2  |H...{...L.L$<L..|
0009f0: 41 b8 20 00 00 00 ff 15 18 2d 05 00 49 89 d9 31  |A. ......-..I..1|

[!] Found 1 unique detections
[+] Detected as: Backdoor:Win64/CobaltStrike.NP!dha
```
