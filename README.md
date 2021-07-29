# Defender Control
Open source windows defender disabler.   
Now you can disable windows defender permanently!   
Tested & working on Windows 10 Version 20H2.  

## What is this project?  
We all know that disabling windefender is very difficult since microsoft is constantly enforcing changes.  
The first solution is to install an anti-virus - but thats not the point if we are trying to disable it!  
The next easiest solution is to use freeware thats already available on the internet - but none of them are native & open source...  
I like open source, so I made a safe to use open source defender control.  

## What does it do?
1. It gains TrustedInstaller permissions
2. It will disable windefender services + smartscreen
3. It will disable anti-tamper protection
4. It will disable all relevant registries + wmi settings

## Is it safe?
Yes it is safe, feel free to review the code in the repository yourself.

## Demo
![Demo](https://github.com/qtkite/defender-control/blob/main/resources/demo.gif?raw=true)

## Release
You can find the first release over at the releases on the right.  
Or alternatively click [here](https://github.com/qtkite/defender-control/releases/tag/v1.0).
  
Please note the release only disables defender at the moment.  
I will release a version that enables it in the near future.

## Writeup
If you are interested in how I developed this program check out the writeup [here](https://github.com/qtkite/defender-control/blob/main/Writeup.md).

## TO-DO
- Build an interface
- Create native bindings for .NET
