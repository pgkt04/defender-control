# defender-control
currently a work in progress - feel free to come back to check on any updates
  
## what is this project?  
we all know that disabling windefender is a pain going through countless registries.  
the next easiest solution is to use freeware and currently the most popular one is by sordum. (i won't link here - you can find it on the first google result)
however, i was first wary of this program and the virus total detections; althought they are claimed to be false positive.
but i know that this program has worked well for me and friends in the past.
  
my second suspicion was this program was the fact it connected to the internet using a few of the imported functions. however after some debugging it seemed to be safe.
  
but for those who like open source, i took apart this program to put together a poc to disable windows defender without having to worry about installing malware.
  

## reversal
Our tool of choice will be IDA & x64 debugger for this task  
firstly we are going to inspect the strings and look for anything interesting.  
Strings seems to be hidden in this one, so I will do 2 different PoC of attack.  
The first one, is to hook the registry functions and output their arguments. Since I know  
for a fact after looking at the imports - this program works by writing into relevant registries.  

The second method is to breakpoint each function with x64 debugger and take a look at the strings on runtime.  
  
I did eventually come up with a third method, and it was to let procmon do its thing while you debug the program - but ill leave that as an exercise for another day.

## x64 Debug 

### disabling defender

If we breakpoint onto RegSetKeyValue it writes into "DisableAntiSpyware" which we can research on the internet  
There is a lot of occurance with the following registry directory: "Software\\Policies\\Microsoft\\Windows Defender"  
It is found under the parent directory of HKLM64. 

```asm
008CE9E8  043DCA88  L"HKLM64"
...
008CEA08  043DCBC0  L"SOFTWARE\\Policies\\Microsoft\\Windows Defender"
```

The second breakpoint leads us here:

```asm
008CE8F0  043DCFE8  L"HKLM64"
...
008CE910  043DD120  L"SYSTEM\\CurrentControlSet\\Services\\WinDefend"
```

So taking a look into the registry: SYSTEM\\CurrentControlSet\\Services\\WinDefend  
and cross referencing back to x64 dbg: we notice this:  

`76122F7F | 397D 0C                  | cmp dword ptr ss:[ebp+C],edi            | [ebp+C]:L"Start"`

It appears that 0x03 disables windefender, while 0x02 means to enable.
A quick google search brings us here: https://answers.microsoft.com/en-us/protect/forum/protect_defender-protect_start-windows_10/how-to-disable-windows-defender-in-windows-10/b834d36e-6da8-42a8-85f6-da9a520f05f2

The next one is also in HKLM:  

```asm
76122FF0 | 8945 CC                  | mov dword ptr ss:[ebp-34],eax           | [ebp-34]:L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run"
76122FF3 | 66:8B01                  | mov ax,word ptr ds:[ecx]                | ecx:&L"SecurityHealth"
```

Seems to be set to 3 or off

Now we will look at RegCreateKey  
There seems to be a regisatry opened at 

```asm
EDX : 043DCD78     L"SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection"
EIP : 7591E420     <advapi32.RegCreateKeyExW>
```

However, there doesnt seem to be anymore functions breakpointed. So lets inspect the directory

We have 2 flags set:
DisableRealtimeMonitoring as a REG_DWORD set to 0x01
DpaDisabled as REG_DWORD set to 0x0

Another one opened here:  

```asm
008CEFF8  043EB4C8  L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run"
```

### enabling defender

there seems to be a reference with "Policy Manager" using RegEnumKeyExW  

It seems to call RegDeleteValueW on security health (see above)  


## reversing w hooks
We are going to write a simple dll to inject into defender control to dump out the parameters of the functions we are interested in.  

Here are the logs:
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
```
  
So by analyzing these logs, it seems that we check if defender is enabled by reading these two registries:
```
SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
DisableRealtimeMonitoring
```
  
When it disables the AV it modifies these registries:
```
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

To enable the AV, we just do the opposite of what we needed to disable the AV.

## Windows Tamper Protection

But theres, a catch. In a newer recent windows update - you can no longer disable the defender via registries. Well, our program runs completely in usermode, so there must be another way its making these registry changes - most likely through the powershell command  Set-MpPreference if we do some research into changing the registry. So we will need to take a peek into the wmic api it accesses.  
Luckily for us, all this stuff is documented. Check out these two links:  
- https://docs.microsoft.com/en-us/powershell/module/defender/set-mppreference?view=windowsserver2019-ps
- https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-c---application-examples




  
