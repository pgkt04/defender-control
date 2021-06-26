Here is the complete log dump cleaned:
```
obtained RegDeleteKeyW from 75A60000
obtained RegDeleteValueW from 75A60000
obtained RegEnumValueW from 75A60000
obtained RegSetValueExW from 75A60000
obtained RegCreateKeyExW from 75A60000
obtained RegConnectRegistryW from 75A60000
obtained RegEnumKeyExW from 75A60000
obtained RegQueryValueExW from 75A60000
obtained RegOpenKeyExW from 75A60000
imports resolved
preparing to hook

Check for AV:

[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
[RegQueryValueExW]
lpValueName: DisableRealtimeMonitoring
[RegQueryValueExW]
lpValueName: DisableRealtimeMonitoring
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths
[RegQueryValueExW]
lpValueName: C:\Program Files (x86)\DefenderControl\dControl.exe

Disable AV:

[RegCreateKeyExW]
lpSubKey: SOFTWARE\Policies\Microsoft\Windows Defender
[RegSetValueExW]
lpValueName: DisableAntiSpyware
[RegCreateKeyExW]
lpSubKey: SOFTWARE\Microsoft\Windows Defender
[RegCreateKeyExW]
lpSubKey: SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender
[RegQueryValueExW]
lpValueName: DisableAntiSpyware
[RegQueryValueExW]
lpValueName: DisableAntiSpyware
[RegCreateKeyExW]
lpSubKey: SYSTEM\CurrentControlSet\Services\WinDefend
[RegSetValueExW]
lpValueName: Start
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows\CurrentVersion\Run
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows\CurrentVersion\Run
[RegQueryValueExW]
lpValueName: SecurityHealth
[RegQueryValueExW]
lpValueName: SecurityHealth
[RegCreateKeyExW]
lpSubKey: SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run
[RegSetValueExW]
lpValueName: SecurityHealth
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows\CurrentVersion\Run
[RegEnumValueW]
lpValueName: SecurityHealth
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
[RegQueryValueExW]
lpValueName: DisableRealtimeMonitoring
[RegQueryValueExW]
lpValueName: DisableRealtimeMonitoring
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths
[RegQueryValueExW]
lpValueName: C:\Program Files (x86)\DefenderControl\dControl.exe

Enable AV:

[RegOpenKeyExW]
lpValueName: SOFTWARE\Policies\Microsoft\Windows Defender
[RegEnumKeyExW]
lpName: ☺
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: SOFTWARE\Policies\Microsoft\Windows Defender
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender
[RegQueryValueExW]
lpValueName: DisableAntiSpyware
[RegQueryValueExW]
lpValueName: DisableAntiSpyware
[RegOpenKeyExW]
lpValueName: SOFTWARE\Policies\Microsoft\Windows Defender
[RegOpenKeyExW]
lpValueName: SOFTWARE\Policies\Microsoft\Windows Defender
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender
[RegQueryValueExW]
lpValueName: DisableAntiSpyware
[RegQueryValueExW]
lpValueName: DisableAntiSpyware
[RegOpenKeyExW]
lpValueName: SYSTEM\CurrentControlSet\Services\SecLogon
[RegQueryValueExW]
lpValueName: Start
[RegQueryValueExW]
lpValueName: Start
[RegOpenKeyExW]
lpValueName: SOFTWARE\Policies\Microsoft\Windows Defender
[RegEnumKeyExW]
lpName: ☺
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: SOFTWARE\Policies\Microsoft\Windows Defender
[RegEnumKeyExW]
lpName: ☺
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegEnumKeyExW]
lpName: ☺
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender
[RegQueryValueExW]
lpValueName: DisableAntiSpyware
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
[RegQueryValueExW]
lpValueName: DisableRealtimeMonitoring
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows\CurrentVersion\Run
[RegEnumValueW]
lpValueName: SecurityHealth
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows\CurrentVersion\Run
[RegQueryValueExW]
lpValueName: SecurityHealth
[RegQueryValueExW]
lpValueName: SecurityHealth
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run
[RegDeleteValueW]
lpValueNameSecurityHealth
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows\CurrentVersion\Run
[RegEnumValueW]
lpValueName: SecurityHealth
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows\CurrentVersion\Run
[RegQueryValueExW]
lpValueName: WindowsDefender
[RegQueryValueExW]
lpValueName: WindowsDefender
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows\CurrentVersion\Run
[RegEnumValueW]
lpValueName: WindowsDefender
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
[RegQueryValueExW]
lpValueName: DisableRealtimeMonitoring
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths
[RegQueryValueExW]
lpValueName: C:\Program Files (x86)\DefenderControl\dControl.exe
[RegOpenKeyExW]
```