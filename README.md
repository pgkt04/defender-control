# Defender Control
Open source windows defender disabler.   
Now you can disable windows defender permanently!   
Tested from Windows 10 20H2.  

## What is this project?  
We all know that disabling windefender is very difficult since microsoft is constantly enforcing changes.  
The first solution is to install an anti-virus - but thats not the point if we are trying to disable it!  
The next easiest solution is to use freeware thats already available on the internet - but none of them are native & open source...  
I like open source, so I made a safe to use open source defender control.  

## On windows updates / Windows 11
Sometimes windows decides to update and turn itself back on.  
A common issue is that defender control sometimes doesn't want to disable tamper protection again.  
Please try turning off tamper protection manually then running disable-defender.exe again before posting an issue.  

![Tamper](https://github.com/qtkite/defender-control/blob/main/resources/tamper.png?raw=true)

## What does it do?
1. It gains TrustedInstaller permissions
2. It will disable windefender services + smartscreen
3. It will disable anti-tamper protection
4. It will disable all relevant registries + wmi settings

## Is it safe?
Yes it is safe, feel free to review the code in the repository yourself.  
Anti-virus & other programs might flag this as malicious since it disables defender - but feel free to compile it using visual studio.

## Compiling
Open the project using visual studio 2022 preview.  
Set the build to Release and x64.  
Change the build type you want in settings.hpp.  
Compile.  

## Demo
![Demo](https://github.com/qtkite/defender-control/blob/main/resources/demo.gif?raw=true)

## Release
You can find the first release over at the releases on the right.  
Or alternatively click [here](https://github.com/qtkite/defender-control/releases/tag/v1.2).

## Windows 11
Works for earlier versions of Windows 11. Correct registries have not been added yet for the latest version.
Update, Trusted Installer no longer has effect on the current live versions of Windows 11. Use with caution.
