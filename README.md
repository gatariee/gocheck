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

## Example (mimikatz)
```cmd
PC@Zavier MINGW64 ~/Desktop/git/gocheck/bin (main)
$ ./GoCheck64.exe check --file ../tests/mimikatz.exe --defender
[*] Found Windows Defender at C:\Program Files\Windows Defender\MpCmdRun.exe
[*] Target file size: 1250056 bytes

[*] Found malicious bytes in range: 0 to 625028, attempting to isolate slice...
[*] Found clean bytes in range: 0 to 152, attempting to find malicious high range

[+] Isolated malicious bytes to range: 0 to 305
000000: 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00  |MZ..............|
000010: b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00  |........@.......|
000020: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  |................|
000030: 00 00 00 00 00 00 00 00 00 00 00 00 20 01 00 00  |............ ...|
000040: 0e 1f ba 0e 00 b4 09 cd 21 b8 01 4c cd 21 54 68  |........!..L.!Th|
000050: 69 73 20 70 72 6f 67 72 61 6d 20 63 61 6e 6e 6f  |is program canno|
000060: 74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20  |t be run in DOS |
000070: 6d 6f 64 65 2e 0d 0d 0a 24 00 00 00 00 00 00 00  |mode....$.......|
000080: 34 c8 d8 22 70 a9 b6 71 70 a9 b6 71 70 a9 b6 71  |4.."p..qp..qp..q|
000090: 79 d1 23 71 72 a9 b6 71 79 d1 35 71 4f a9 b6 71  |y.#qr..qy.5qO..q|
0000a0: 79 d1 32 71 60 a9 b6 71 79 d1 25 71 72 a9 b6 71  |y.2q`..qy.%qr..q|
0000b0: 6b 34 2a 71 72 a9 b6 71 16 47 7d 71 74 a9 b6 71  |k4*qr..q.G}qt..q|
0000c0: eb 42 7d 71 72 a9 b6 71 06 34 db 71 72 a9 b6 71  |.B}qr..q.4.qr..q|
0000d0: 6e fb 32 71 72 a9 b6 71 06 34 cd 71 5f a9 b6 71  |n.2qr..q.4.q_..q|
0000e0: 70 a9 b7 71 0a ab b6 71 57 6f c8 71 71 a9 b6 71  |p..q...qWo.qq..q|
0000f0: 79 d1 3f 71 13 a9 b6 71 79 d1 22 71 71 a9 b6 71  |y.?q...qy."qq..q|
000100: 79 d1 27 71 71 a9 b6 71 52 69 63 68 70 a9 b6 71  |y.'qq..qRichp..q|
000110: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  |................|
000120: 50 45 00 00 64 86 06 00 63 39 5a 5e 00 00 00 00  |PE..d...c9Z^....|

[!] Found 1 unique detections
[+] Detected as: HackTool:Win32/Mimikatz!pz
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
