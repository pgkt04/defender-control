## Reversal
I reversed parts of the freeware with some hooks & x64 debugger, read a bunch of security papers & here are some of my findings!

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

## Windows File Protection

But theres, a catch. In a newer recent windows update - you can no longer disable the defender via registries without elevated permissions.  
Well, our program runs completely in usermode, so there must be another way its making these registry changes - most likely through the powershell command  Set-MpPreference if we do some research into changing the registry. So we will need to take a peek into the wmic api it accesses. 

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

Here is an intersting article that got me started in understanding the WMI: https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf

## Gaining permission
Remeber when I said you need more permissions to edit certain registries and edit services?  
Well there is! 
You can read more about it here: https://0x00-0x00.github.io/research/2018/10/17/Windows-API-and-Impersonation-Part1.html  

We adapt it into C++ code which can be found in trusted. Then using an elevated process, we can now edit those registries we can't before!.

## Windows Tamper Protection
Well. We can once we disable tamper protection... But to do that without going through the security menu - we need to first kill the windefend service. Luckily now that we have TrustedInstaller privillege we can directly do that using winapi.

### Windows 11

New dump:

```asm
obtained RegDeleteKeyW from 75DD0000
obtained RegDeleteValueW from 75DD0000
obtained RegEnumValueW from 75DD0000
obtained RegSetValueExW from 75DD0000
obtained RegCreateKeyExW from 75DD0000
obtained RegConnectRegistryW from 75DD0000
obtained RegEnumKeyExW from 75DD0000
obtained RegQueryValueExW from 75DD0000
obtained RegOpenKeyExW from 75DD0000
obtained CreateProcessW from 76000000
obtained ShellExecuteExW from 76DE0000
imports resolved
preparing to hook

IDLE:


[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
ulOptions: 0
samDesired: 131353
[RegQueryValueExW]
lpValueName: DisableRealtimeMonitoring
[RegQueryValueExW]
lpValueName: DisableRealtimeMonitoring
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths
ulOptions: 0
samDesired: 131353
[RegQueryValueExW]
lpValueName: C:\Program Files (x86)\DefenderControl\dControl.exe



---


[RegQueryValueExW]
lpValueName: C:\Program Files (x86)\DefenderControl\dControl.exe
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SYSTEM\CurrentControlSet\Services\WdFilter
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE434
Ret: 0
[RegSetValueExW]
lpValueName: Start
Reserved: 0
dwType: 4
cbData: 4
Ret: 0
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SYSTEM\CurrentControlSet\Services\WdNisDrv
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE434
Ret: 0
[RegSetValueExW]
lpValueName: Start
Reserved: 0
dwType: 4
cbData: 4
Ret: 0
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SYSTEM\CurrentControlSet\Services\WdNisSvc
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE434
Ret: 0
[RegSetValueExW]
lpValueName: Start
Reserved: 0
dwType: 4
cbData: 4
Ret: 0
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SOFTWARE\Policies\Microsoft\Windows Defender
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE754
Ret: 0
[RegSetValueExW]
lpValueName: DisableAntiSpyware
Reserved: 0
dwType: 4
cbData: 4
Ret: 0
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SOFTWARE\Policies\Microsoft\Windows Defender
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE754
Ret: 0
[RegSetValueExW]
lpValueName: DisableAntiVirus
Reserved: 0
dwType: 4
cbData: 4
Ret: 0
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SOFTWARE\Microsoft\Windows Defender
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE664
Ret: 0
[RegSetValueExW]
lpValueName: DisableAntiSpyware
Reserved: 0
dwType: 4
cbData: 4
Ret: 0
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SOFTWARE\Microsoft\Windows Defender
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CEB54
Ret: 0
[RegSetValueExW]
lpValueName: DisableAntiVirus
Reserved: 0
dwType: 4
cbData: 4
Ret: 0
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE754
Ret: 0
[RegSetValueExW]
lpValueName: DisableRealtimeMonitoring
Reserved: 0
dwType: 4
cbData: 4
Ret: 0
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender
ulOptions: 0
samDesired: 131353
[RegQueryValueExW]
lpValueName: DisableAntiSpyware
[RegQueryValueExW]
lpValueName: DisableAntiSpyware
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SYSTEM\CurrentControlSet\Services\WinDefend
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CEA94
Ret: 0
[RegSetValueExW]
lpValueName: Start
Reserved: 0
dwType: 4
cbData: 4
Ret: 0
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SYSTEM\CurrentControlSet\Services\WdFilter
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE434
Ret: 0
[RegSetValueExW]
lpValueName: Start
Reserved: 0
dwType: 4
cbData: 4
Ret: 0
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SYSTEM\CurrentControlSet\Services\WdNisDrv
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE434
Ret: 0
[RegSetValueExW]
lpValueName: Start
Reserved: 0
dwType: 4
cbData: 4
Ret: 0
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SYSTEM\CurrentControlSet\Services\WdNisSvc
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE434
Ret: 0
[RegSetValueExW]
lpValueName: Start
Reserved: 0
dwType: 4
cbData: 4
Ret: 0
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SYSTEM\CurrentControlSet\Services\WinDefend
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE834
Ret: 0
[RegSetValueExW]
lpValueName: Start
Reserved: 0
dwType: 4
cbData: 4
Ret: 0
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SOFTWARE\Policies\Microsoft\Windows Defender
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE8E4
Ret: 0
[RegSetValueExW]
lpValueName: DisableAntiSpyware
Reserved: 0
dwType: 4
cbData: 4
Ret: 0
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SOFTWARE\Policies\Microsoft\Windows Defender
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE8E4
Ret: 0
[RegSetValueExW]
lpValueName: DisableAntiVirus
Reserved: 0
dwType: 4
cbData: 4
Ret: 0
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SOFTWARE\Microsoft\Windows Defender
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE7F4
Ret: 0
[RegSetValueExW]
lpValueName: DisableAntiSpyware
Reserved: 0
dwType: 4
cbData: 4
Ret: 0
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SOFTWARE\Microsoft\Windows Defender
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CECE4
Ret: 0
[RegSetValueExW]
lpValueName: DisableAntiVirus
Reserved: 0
dwType: 4
cbData: 4
Ret: 0
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE8E4
Ret: 0
[RegSetValueExW]
lpValueName: DisableRealtimeMonitoring
Reserved: 0
dwType: 4
cbData: 4
Ret: 0
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender
ulOptions: 0
samDesired: 131353
[RegQueryValueExW]
lpValueName: DisableAntiSpyware
[RegQueryValueExW]
lpValueName: DisableAntiSpyware
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows\CurrentVersion\Run
ulOptions: 0
samDesired: 131353
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows\CurrentVersion\Run
ulOptions: 0
samDesired: 131353
[RegQueryValueExW]
lpValueName: SecurityHealth
[RegQueryValueExW]
lpValueName: SecurityHealth
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CEDD4
Ret: 0
[RegSetValueExW]
lpValueName: SecurityHealth
Reserved: 0
dwType: 3
cbData: 12
Ret: 0
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows\CurrentVersion\Run
ulOptions: 0
samDesired: 131353
[RegEnumValueW]
lpValueName:→0‼rityHealth
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows\CurrentVersion\Run
ulOptions: 0
samDesired: 131353
[RegQueryValueExW]
lpValueName: Riot Vanguard
[RegQueryValueExW]
lpValueName: Riot Vanguard
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows\CurrentVersion\Run
ulOptions: 0
samDesired: 131353
[RegEnumValueW]
lpValueName:→0‼ Vanguard
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\mpcmdrun.exe
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE8CC
Ret: 0
[RegSetValueExW]
lpValueName: Debugger
Reserved: 0
dwType: 1
cbData: 64
Ret: 0
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\mpcmdrun.exe
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE7C4
Ret: 0
[RegSetValueExW]
lpValueName: Debugger
Reserved: 0
dwType: 1
cbData: 64
Ret: 0
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\mpcmdrun.exe
ulOptions: 0
samDesired: 131353
[RegQueryValueExW]
lpValueName: Debugger
[RegQueryValueExW]
lpValueName: Debugger
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SYSTEM\CurrentControlSet\Services\WinDefend
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE834
Ret: 0
[RegSetValueExW]
lpValueName: Start
Reserved: 0
dwType: 4
cbData: 4
Ret: 0


---

ENABLE:

[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SYSTEM\CurrentControlSet\Services\WdFilter
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE434
Ret: 0
[RegSetValueExW]
lpValueName: Start
Reserved: 0
dwType: 4
cbData: 4
Ret: 0
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SYSTEM\CurrentControlSet\Services\WdNisDrv
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE434
Ret: 0
[RegSetValueExW]
lpValueName: Start
Reserved: 0
dwType: 4
cbData: 4
Ret: 0
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SYSTEM\CurrentControlSet\Services\WdNisSvc
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE434
Ret: 0
[RegSetValueExW]
lpValueName: Start
Reserved: 0
dwType: 4
cbData: 4
Ret: 0
[RegOpenKeyExW]
lpValueName: SOFTWARE\Policies\Microsoft\Windows Defender
ulOptions: 0
samDesired: 131103
[RegEnumKeyExW]
lpName: ì☻♦
[RegOpenKeyExW]
lpValueName: Policy Manager
ulOptions: 0
samDesired: 131097
[RegEnumKeyExW]
lpName: ═☻♦
[RegEnumKeyExW]
lpName: Policy Manager
[RegOpenKeyExW]
lpValueName: SOFTWARE\Policies\Microsoft\Windows Defender
ulOptions: 0
samDesired: 131359
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender
ulOptions: 0
samDesired: 131359
[RegDeleteValueW]
lpValueNameDisableAntiSpyware
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender
ulOptions: 0
samDesired: 131359
[RegDeleteValueW]
lpValueNameDisableAntiVirus
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
ulOptions: 0
samDesired: 131359
[RegDeleteValueW]
lpValueNameDisableRealtimeMonitoring
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
ulOptions: 0
samDesired: 131359
[RegDeleteValueW]
lpValueNameDisableAntiSpywareRealtimeProtection
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender
ulOptions: 0
samDesired: 131353
[RegQueryValueExW]
lpValueName: DisableAntiSpyware
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
ulOptions: 0
samDesired: 131353
[RegQueryValueExW]
lpValueName: DisableRealtimeMonitoring
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SYSTEM\CurrentControlSet\Services\WinDefend
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE834
Ret: 0
[RegSetValueExW]
lpValueName: Start
Reserved: 0
dwType: 4
cbData: 4
Ret: 0
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SYSTEM\CurrentControlSet\Services\WdFilter
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE434
Ret: 0
[RegSetValueExW]
lpValueName: Start
Reserved: 0
dwType: 4
cbData: 4
Ret: 0
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SYSTEM\CurrentControlSet\Services\WdNisDrv
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE434
Ret: 0
[RegSetValueExW]
lpValueName: Start
Reserved: 0
dwType: 4
cbData: 4
Ret: 5
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SYSTEM\CurrentControlSet\Services\WdNisSvc
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE434
Ret: 0
[RegSetValueExW]
lpValueName: Start
Reserved: 0
dwType: 4
cbData: 4
Ret: 5
[RegCreateKeyExW]
hKey: 80000002
lpSubKey: SYSTEM\CurrentControlSet\Services\WinDefend
lpClass:
samDesired: 131334
Reserved: 0
lpSecurityAttributes: 00000000
dwOptions: 0
lpdwDisposition: 008CE834
Ret: 0
[RegSetValueExW]
lpValueName: Start
Reserved: 0
dwType: 4
cbData: 4
Ret: 5
[RegOpenKeyExW]
lpValueName: SOFTWARE\Policies\Microsoft\Windows Defender
ulOptions: 0
samDesired: 131103
[RegEnumKeyExW]
lpName: ]☻♦
lpValueName: DisableAntiSpyware
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
ulOptions: 0
samDesired: 131353
[RegQueryValueExW]
lpValueName: DisableRealtimeMonitoring
[CreateProcessW]
lpCommandLine: "C:\j\bin\dControl\w11 fix\dfControl.exe" /EXP |6324|
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows\CurrentVersion\Run
ulOptions: 0
samDesired: 131353
[RegEnumValueW]
lpValueName: h.°$♀
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows\CurrentVersion\Run
ulOptions: 0
samDesired: 131353
[RegQueryValueExW]
lpValueName: SecurityHealth
[RegQueryValueExW]
lpValueName: SecurityHealth
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run
ulOptions: 0
samDesired: 131359
[RegDeleteValueW]
lpValueNameSecurityHealth
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows\CurrentVersion\Run
ulOptions: 0
samDesired: 131353
[RegEnumValueW]
lpValueName: h.°$rityHealth
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows\CurrentVersion\Run
ulOptions: 0
samDesired: 131353
[RegQueryValueExW]
lpValueName: Riot Vanguard
[RegQueryValueExW]
lpValueName: Riot Vanguard
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows\CurrentVersion\Run
ulOptions: 0
samDesired: 131353
[RegEnumValueW]
lpValueName: h.°$ Vanguard
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\mpcmdrun.exe
ulOptions: 0
samDesired: 131359
[RegEnumKeyExW]
lpName: ♣☻♦
[RegOpenKeyExW]
lpValueName: SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\mpcmdrun.exe
ulOptions: 0
samDesired: 131359
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\mpcmdrun.exe
ulOptions: 0
samDesired: 131353
[CreateProcessW]
lpCommandLine: C:\Program Files\Windows Defender\mpcmdrun.exe -wdenable
[RegOpenKeyExW]
lpValueName: SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
ulOptions: 0
samDesired: 131353

```



## Conclusion
Well thats all there is to disabling defender... TLDR: We gain TrustedInstaller permission, disable the windefend service and modify the registries & make calls to the wmi to our hearts content.

## Relevant links:
- https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf
- https://0x00-0x00.github.io/research/2018/10/17/Windows-API-and-Impersonation-Part1.html  
- http://myne-us.blogspot.cz/2012/08/reverse-engineering-powershell-cmdlets.html

