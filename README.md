# Defender Control
Open source windows defender disabler

## What is this project?  
We all know that disabling windefender is a pain going through countless registries & running endless powershell commands.
The next easiest solution is to use freeware and currently the most popular one is by sordum.
But I like open source, so I made a safe to use open source defender control.

## Demo
![Demo](https://github.com/qtkite/defender-control/blob/main/resources/demo.gif?raw=true)

## TODO
- Delete windefend as trusted installer
- Remove startup as boot


## Reversal
I reversed parts of the freeware with some hooks & x64 debugger, here are some of my findings

## x64 Debug 
### disabling defender



```asm
008CE9E8  043DCA88  L"HKLM64"
...
008CEA08  043DCBC0  L"SOFTWARE\\Policies\\Microsoft\\Windows Defender"

008CE8F0  043DCFE8  L"HKLM64"
...
008CE910  043DD120  L"SYSTEM\\CurrentControlSet\\Services\\WinDefend"

76122F7F | 397D 0C                  | cmp dword ptr ss:[ebp+C],edi            | [ebp+C]:L"Start"`

https://answers.microsoft.com/en-us/protect/forum/protect_defender-protect_start-windows_10/how-to-disable-windows-defender-in-windows-10/b834d36e-6da8-42a8-85f6-da9a520f05f2

76122FF0 | 8945 CC                  | mov dword ptr ss:[ebp-34],eax           | [ebp-34]:L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run"
76122FF3 | 66:8B01                  | mov ax,word ptr ds:[ecx]                | ecx:&L"SecurityHealth"

EDX : 043DCD78     L"SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection"
EIP : 7591E420     <advapi32.RegCreateKeyExW>

We have 2 flags set:
DisableRealtimeMonitoring as a REG_DWORD set to 0x01
DpaDisabled as REG_DWORD set to 0x0

008CEFF8  043EB4C8  L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run"
```

### enabling defender

there seems to be a reference with "Policy Manager" using RegEnumKeyExW  

It seems to call RegDeleteValueW on security health (see above)  


## reversing w hooks
We are going to write a simple dll to inject into defender control to dump out the parameters of the functions we are interested in.  

Here are the logs:  

```asm
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

Registry Routine to check if defender activated:

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

Routine to disable defender

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

Routine to enable defender

[RegOpenKeyExW]
lpValueName: SOFTWARE\Policies\Microsoft\Windows Defender
[RegOpenKeyExW]
lpValueName: Policy Manager
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
[RegOpenKeyExW]
lpValueName: Policy Manager
[RegOpenKeyExW]
lpValueName: SOFTWARE\Policies\Microsoft\Windows Defender
[RegOpenKeyExW]
lpValueName: Policy Manager
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
<also redacted a bunch of stuff from policy manager stuff>
-----
SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
DisableRealtimeMonitoring
```
  
When it disables the AV it modifies these registries:  

```asm
[RegCreateKeyExW]
lpSubKey: SOFTWARE\Policies\Microsoft\Windows Defender
[RegSetValueExW]
lpValueName: DisableAntiSpyware
[RegCreateKeyExW]
lpSubKey: SOFTWARE\Microsoft\Windows Defender
[RegCreateKeyExW]
lpSubKey: SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
[RegCreateKeyExW]
lpSubKey: SYSTEM\CurrentControlSet\Services\WinDefend
[RegSetValueExW]
lpValueName: Start
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows\CurrentVersion\Run
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
```

### Dumping VTable Calls
```asm
[Control Table] 0x495b78
[Control Table] 0x493658
[Control Table] 0x4932f8
[Control Table] 0x494e1c
[Control Table] 0x4949e4
[Control Table] 0x4965e0
[Control Table] 0x496088
[Control Table] 0x4951c4
[Control Table] 0x4960d0
[Control Table] 0x49463c
[Control Table] 0x493808
[Control Table] 0x493850
[Control Table] 0x494ed0
[Control Table] 0x49382c
[Control Table] 0x49532c
[Control Table] 0x493874
[Control Table] 0x493898
[Control Table] 0x4931fc
[Control Table] 0x4931b4
[Control Table] 0x495500
[Control Table] 0x495cbc
[Control Table] 0x495ce0
[Control Table] 0x4958cc
[Control Table] 0x494a74
[Control Table] 0x495c08
[Control Table] 0x494cfc
[Control Table] 0x493c40
[Control Table] 0x493e5c
[Control Table] 0x493ea4
[Control Table] 0x493b8c
[Control Table] 0x495b0c
[Control Table] 0x495c2c
[Control Table] 0x493f7c
[Control Table] 0x4930dc
[Control Table] 0x493fe8
[Control Table] 0x494c00
[Control Table] 0x495644
[Control Table] 0x495428
[Control Table] 0x496430
[Control Table] 0x4963e8
[Control Table] 0x4954b8
[Control Table] 0x4945d0
[Control Table] 0x496040
[Control Table] 0x4960ac
[Control Table] 0x494a50
[Control Table] 0x495be4
```


Upon starting the AV, the program calls CreateProcessW on C:\Windows\System32\SecurityHealthSystray.exe

## Windows Tamper Protection

But theres, a catch. In a newer recent windows update - you can no longer disable the defender via registries. Well, our program runs completely in usermode, so there must be another way its making these registry changes - most likely through the powershell command  Set-MpPreference if we do some research into changing the registry. So we will need to take a peek into the wmic api it accesses.  
Luckily for us, all this stuff is documented. Check out these two links:  
- https://docs.microsoft.com/en-us/powershell/module/defender/set-mppreference?view=windowsserver2019-ps
- https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-c---application-examples

I first wanted to see how powershell called the command, so i looked through the powershell github since its open sourced and found that the command was in a cmdlet that was not documented in the repository. So after reading up on some powershell commands I dumped the powershell informating using this:

```asm
Get-Command Set-MpPreference | fl
```

If we wanted to read the MSFT_MpPreference class, it is documented here:
https://docs.microsoft.com/en-us/previous-versions/windows/desktop/legacy/dn455323(v=vs.85)#requirements  
We can access via powershell like so:  

```asm
Get-WmiObject -ClassName MSFT_MpPreference -Namespace root/microsoft/windows/defender
```

If we look further we can write to this using the WMI - it is documented here:
https://docs.microsoft.com/en-us/previous-versions/windows/desktop/defender/windows-defender-wmiv2-apis-portal  

We can find the specific wmi com classes if we do the following command:
  
`MpPreference |fl *`

We get an output and we are intrested in this:

```asm
CimClass                                      : root/Microsoft/Windows/Defender:MSFT_MpPreference
CimInstanceProperties                         : {AllowDatagramProcessingOnWinServer, AllowNetworkProtectionDownLevel,
                                                AllowNetworkProtectionOnWinServer,
                                                AttackSurfaceReductionOnlyExclusions...}
CimSystemProperties                           : Microsoft.Management.Infrastructure.CimSystemProperties
```

We can find the class here: https://docs.microsoft.com/en-us/dotnet/api/microsoft.management.infrastructure.cimsystemproperties?view=powershellsdk-7.0.0

It is also located in windows binaries in the following path: C:\Program Files (x86)\Reference Assemblies\Microsoft\WMI\v1.0 
