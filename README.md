# Defender Control
Open source Windows Defender disabler. Works on Windows 10 and 11.

## Microsoft flags this tool
This repo has been public for years, so Defender ships a signature for it
(HackTool:Win32/DefenderControl) and will quarantine the exe on sight. It's a category
detection that hits any Defender disabler, not proof the code is unsafe. It's open source,
review or compile it yourself.

## How to disable
1. Open Windows Security > Virus & threat protection > Manage settings.
2. Turn Tamper Protection off.
3. Turn Real-time protection off (temporary, also stops Defender eating the exe).
4. Run disable-defender.exe as admin. It relaunches itself as TrustedInstaller.
5. Reboot (optional, but do it for full effect).

Note: "failed to write to TamperProtection" and similar "kernel-locked" / "error 5" lines
are expected. Those keys are guarded by Defender while the engine is running. The tool
gets past this by renaming the Defender drivers instead (see below), which takes effect on
the next boot.

## How it works
It runs as TrustedInstaller, sets the disabling policies and UI lockdown, then renames
Defender's drivers (WdFilter.sys, WdBoot.sys, etc.) and engine binaries to .OLD. With the
drivers gone, the engine can't start at the next boot, so there's no Safe Mode needed. A
restore list is saved to %ProgramData%\defender-control so it can all be undone.

## How to re-enable
Build and run the enable config (set DEFENDER_CONFIG in settings.hpp). It renames the .OLD
files back, clears the policy and UI lockdown keys, restores ownership, and sets WinDefend
to auto-start. Then reboot.

## Check status
After disabling, the Security UI is locked, so check state from a terminal:

```
disable-defender.exe -c
```

Shows live antivirus / real-time / tamper status, whether MsMpEng is running, and a
verdict. Add -s to skip the pause.

## If Defender won't come back
Run from an elevated terminal:

```
DISM /Online /Cleanup-Image /RestoreHealth
sfc /scannow
```

Then reboot. If that doesn't fix it, do an in-place repair upgrade (Windows ISO or
Installation Assistant, run setup.exe, keep files and apps).

## Compile
Open in Visual Studio 2022, set Release / x64, pick disable or enable in settings.hpp, build.

## Demo
![Demo](https://github.com/pgkt04/defender-control/blob/main/resources/demo.gif?raw=true)

## Release
See the releases on the right, or [here](https://github.com/pgkt04/defender-control/releases/tag/v1.2).
