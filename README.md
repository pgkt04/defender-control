# defender-control

## reversal
Our tool of choice will be IDA & x64 debugger for this task  
firstly we are going to inspect the strings and look for anything interesting.  
Strings seems to be hidden in this one, so I will do 2 different PoC of attack.  
The first one, is to hook the registry functions and output their arguments. Since I know  
for a fact after looking at the imports - this program works by writing into relevant registries.  

The second method is to breakpoint each function with x64 debugger and take a look at the strings on runtime.  


## disabling defender

### x64 Debug 

If we breakpoint onto RegSetKeyValue it writes into "DisableAntiSpyware" which we can research on the internet  
There is a lot of occurance with the following registry directory: "Software\\Policies\\Microsoft\\Windows Defender"  
It is found under the parent directory of HKLM64. 

```asm
008CE9E8  043DCA88  L"HKLM64"
008CE9EC  00000006  
008CE9F0  00000008  
008CE9F4  043DCAB0  
008CE9F8  043DCA60  
008CE9FC  00000000  
008CEA00  00000008  
008CEA04  043DC950  
008CEA08  043DCBC0  L"SOFTWARE\\Policies\\Microsoft\\Windows Defender"
```

The second breakpoint leads us here:

```asm
008CE8F0  043DCFE8  L"HKLM64"
008CE8F4  00000006  
008CE8F8  00000008  
008CE8FC  043DD010  
008CE900  043DCFC0  
008CE904  00000000  
008CE908  00000008  
008CE90C  043DCEB0  
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

## enabling defender

there seems to be a reference with "Policy Manager" using RegEnumKeyExW  

It seems to call RegDeleteValueW on security health (see above)  

