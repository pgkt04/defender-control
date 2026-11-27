# Defender Control
Open source Windows Defender disabler. Works on Windows 10 and 11.

Releases ship two binaries: `disable-defender.exe` and `enable-defender.exe`.
Add `-firewall` to also turn Windows Firewall off or on. Otherwise, firewall settings are left alone.

## Microsoft flags this tool
This repo has been public for years, so Defender ships a signature for it
(`HackTool:Win32/DefenderControl`) and will quarantine the exe on sight. It is a category
detection that hits any Defender disabler, not proof the code is unsafe. It is open source,
review or compile it yourself.

## How to disable
1. Open **Windows Security > Virus & threat protection > Manage settings**.
2. Turn **Tamper Protection** off.
3. Turn **Real-time protection** off (temporary, also stops Defender eating the exe).
4. Run the tool as admin (it relaunches itself as TrustedInstaller):

   ```
   disable-defender.exe
   ```

5. Reboot (optional, but do it for full effect).

> **Note:** `failed to write to TamperProtection` and similar `kernel-locked` / `error 5`
> lines are **expected**. Those keys are guarded by Defender while the engine is running.
> The tool gets past this by renaming the Defender drivers instead (see below), which takes
> effect on the next boot.

## How it works
1. Runs as **TrustedInstaller**.
2. Sets the disabling policies and locks down the Security UI.
3. Renames Defender's drivers (`WdFilter.sys`, `WdBoot.sys`, ...) and engine binaries to
   `.OLD`.

With the drivers gone the engine cannot start at the next boot, so no Safe Mode is needed.
A restore list is saved to `%ProgramData%\defender-control` so it can all be undone.

## How to re-enable
Run the enable binary as admin, then reboot:

```
enable-defender.exe
```

It renames the `.OLD` files back, clears the policy and UI lockdown keys, restores
ownership, and sets `WinDefend` to auto-start.

## Check status
After disabling, the Security UI is locked, so check state from a terminal:

```
disable-defender.exe -c
```

Shows live antivirus / real-time / tamper status, whether `MsMpEng` is running, and a
verdict. Add `-s` to skip the pause.

## If Defender won't come back
Run from an elevated terminal:

```
DISM /Online /Cleanup-Image /RestoreHealth
sfc /scannow
```

Then reboot. If that does not fix it, do an in-place repair upgrade (Windows ISO or
Installation Assistant, run `setup.exe`, keep files and apps).

## Compile
Open the solution in Visual Studio 2026 (v145 toolset) and select **Release / x64**.
Pick the build mode in `settings.hpp`.

## Demo
![Demo](https://github.com/pgkt04/defender-control/blob/main/resources/demo.gif?raw=true)

## Release
See the releases on the right, or [here](https://github.com/pgkt04/defender-control/releases).
