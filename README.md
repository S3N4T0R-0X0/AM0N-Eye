# AM0N-Eye
AM0N-Eye is the decompiled from Cobaltsetrike and has been modified and developed through several aggressor scripts & BOF
is project based on a combination of different ideas and projects used by the threat actor where we observe a set of techniques to evasion EDR and AV while allowing the operator to continue using the tools.

The most focused point for the development is the collection of projects for the Cobaltsetrike (aggressor scripts) and making it an essential feature without the need for to add it every time,Obfuscate the scripts called by the aggressor scripts to activate them at the target,and changed the default c2 profile to change the signature of Cobalt, while maintaining the integration feature with other c2 profiles, and writing new c2 samples for Windows,Linux,MacOS.

This project is not authorized to be published ⚠️

Due to the copyrights of fortra, the developers are not responsible for any attempt to publish AM0N-Eye

![Screenshot from 2023-07-16 15-29-53](https://github.com/S3N4T0R-0X0/AM0N-Eye/assets/121706460/9ce4615d-a0d4-4e02-9a9a-45245c8b595e)

The names of the projects (aggressor scripts and c2 profiles) that have been added.
/ScareCrow/ /CrossC2/ /CSSG-xor/ /InvokeCredentialPhisher/ /Registry-Recon/  /random_c2_profile/ /C2concealer/
/zerologon with CVE-2020-1472/ /process-hollowing by sektor7/ /AntiForensics by @Und3rf10w/
/StaticSyscallsAPCSpawn ,StaticSyscallsDump ,StaticSyscallsInject by @Jackson_T/
/cThreadHijack/ /ReflectiveDLLInjection/ /amsi-inject by @0xBoku/ /@r3dqu1nn scripts/

and here I will know some TTPs of AM0N-Eye, but not all.

1. Linux, MacOS and windows c2 server
2. Fake Alert techniques
3. AV/EDR evasion techniques
4. shellcode Generator & obfuscatior
5. Persistence techniques
6. Anti-Forensics
7. AV/EDR Recon
8. PayloadGenerator Undetected by antivirus programs
9. custom malwares
10. New c2 profiles
__________________________________________________________________________________________________________________________________________________________
# PayloadGenerator

Generates every type of Stageless/Staged Payload based off a HTTP/HTTPS Listener Undetected by antivirus programs
    
Creates /opt/amon-eye/Staged_Payloads, /opt/amon-eye/Stageless_Payloads
    
# Linux & MacOS C2 Server

A security framework for enterprises and Red Team personnel, supports AM0N-Eye penetration testing of other platforms (Linux / MacOS / ...), supports custom modules, and includes some commonly used penetration modules.

Lateral movement

    Generate beacon of Linux-bind / MacOS-bind type
    The target in the intranet runs ./MacOS-bind.beacon <port> to start the service
    Run connect <targetIP>:<port> in the session

Don't forget to Check C2 profiles in /AM0N-Eye/C2-Profiles/ to bypass network filters
To use a custom profile  you must start a AM0N-Eye team server and specify your profile at that tim 
Example ./teamserver [external IP] [password] [/path/to/my.profile] .


# Bypass ESET EDR
__________________________________________________________________________________________________________________________________________________________


https://github.com/S3N4T0R-0X0/AM0N-Eye/assets/121706460/d54517fb-9f36-4e84-a447-0833910bad9b


# Bypass Sophos EDR
__________________________________________________________________________________________________________________________________________________________




https://github.com/S3N4T0R-0X0/AM0N-Eye/assets/121706460/55e607f7-b3c4-4e1b-b1cd-86e4e00b2a60




# Bypass FireEye EDR
__________________________________________________________________________________________________________________________________________________________


https://github.com/S3N4T0R-0X0/AM0N-Eye/assets/121706460/5a898591-9c23-4b2d-9085-54b4c528696f


# Bypass Kaspersky AV & Hunters Against EDR
__________________________________________________________________________________________________________________________________________________________


https://github.com/S3N4T0R-0X0/AM0N-Eye/assets/121706460/c8b364a0-b52a-4edd-840d-a63420d9cb7f

__________________________________________________________________________________________________________________________________________________________


 # Bypass ClamAV
__________________________________________________________________________________________________________________________________________________________



https://github.com/S3N4T0R-0X0/AM0N-Eye/assets/121706460/9cafcc1e-d750-4432-9a68-82cbceebf35b




# C2-simples

windows https://github.com/S3N4T0R-0X0/Jicop-H00k.git

Linux   https://github.com/S3N4T0R-0X0/Marionette.git

Mac-os  https://github.com/S3N4T0R-0X0/Diablo.git
__________________________________________________________________________________________________________________________________________________________


![Screenshot from 2023-07-22 21-07-34](https://github.com/S3N4T0R-0X0/AM0N-Eye/assets/121706460/e978415c-02d0-4111-bba4-51f668459029)

	
# Fake Alert update

to send toast notifications on behalf on an (installed) application or the computer itself. The user will be asked to supply credentials once they click on the notification toast. The second one is a AM0N-Eye module to launch the phishing attack on connected beacons and you can learn the types of victim's defense mechanisms and exploit this to issue an update alert or to take action

![Screenshot from 2023-02-21 02-42-37](https://user-images.githubusercontent.com/121706460/226552401-6666bc29-2b9b-4248-9056-faafe28af324.png)


# AV-EDR Evasion
	
	
![Screenshot from 2023-03-21 04-48-45](https://user-images.githubusercontent.com/121706460/226556701-11379ed8-66de-4303-9daf-aca85f78af85.png)



 
# shellcode obfuscatior
 
	
![Screenshot from 2023-03-21 04-46-30](https://user-images.githubusercontent.com/121706460/226556899-c1253b00-8e08-469c-9a46-f1012b1f2795.png)


# Persistence
		
![Screenshot from 2023-07-22 21-08-58](https://github.com/S3N4T0R-0X0/AM0N-Eye/assets/121706460/95c68a5e-d926-4a3c-ae4a-e3003c7c0493)



* (Active-Evilentry) 
job to execute as your current user context. This job will be executed every time the user logs in. Currently only works on Windows 7, 8, Server 2008, Server 2012.



* (UserSchtasksPersist)

Schtasks Persistence that runs as current user for the selected beacon

Meant for quick user level persistence upon initial access


* (ServiceEXEPersist)

Admin Level Custom Service EXE Persistence
    
Runs as elevated user/SYSTEM for the selected beacon



* (WMICEventPersist)
    
Generates a Custom WMI Event using WMIC for SYSTEM Level persistence on selected beacon

Very syntax heavy, Test first before using on live targets


* (StartupGPOPersist)
   
Generates a Local GPO Entry in psscripts.ini to call a .ps1 script file for persistence on selected beacon
   
Calls back as SYSTEM
   
Check permissions with GPO Enumeration (Successful GroupPolicy Directory Listing) first before executing
   
Beacon execution will cause winlogon.exe to hang and the end user can't login. Once the new beacon checks in inject into another process and kill the original. Update to come out soon.


* (RegistryPersist)

Creates a Custom Registry Key, Value, Type, and Payload Location based on user input for selected beacon



* (HKCURunKeyPSRegistryPersist)

Creates two Custom Registry Run Key entries in HKCU
   
The Payload is a base64 encoded powershell payload based off your HTTP/HTTPS listener
 


##checkmate request 
version of the checkmate request Web Delivery attack


    Stageless Web Delivery using checkmate.exe 
    
    Powerpick is used to spawn checkmate.exe to download the stageless payload on target and execute with rundll32.exe


# Curl-TLS  

simple web requests without establishing SOCKS PROXY. Example use case could be confirming outbound access to specific service before deploying a relay from [F-Secure's C3]


# Defensive Recon
AV/EDR  & EDR exact query
 
As a red-team practitioner, we are often using tools that attempt to fingerprint details about a compromised system, preferably in the most stealthy way possible. Some of our usual tooling for this started getting flagged by EDR products, due to the use of Windows CLI commands.
This aims to solve that problem by only probing the system using native registry queries, no CLI commands.






#BOF & (New command)

    AV_Query                  Queries the Registry for AV Installed
    FindModule                Find loaded modules.
    FindProcHandle            Find specific process handles.
    amsi-inject               Bypass AMSI in a remote process with code injection.
    blockdlls                 Block non-Microsoft DLLs in child processes
    bypassuac-eventvwr        Bypass UAC using Eventvwr Fileless UAC bypass via. Powershell SMB Beacon
    cThreadHijack             cThreadHijack: Remote process injection via thread hijacking
    dllinject                 Inject a Reflective DLL into a process
    dllload                   Load DLL into a process with LoadLibrary()
    edr_query                 Queries the remote or local system for all major EDR products installed
    etw                       Start or stop ETW logging.
    execute-assembly          Execute a local .NET program in-memory on target
    info_RTFM                 A large repository of commands and red team tips
    process-hollowing         EarlyBird process hollowing technique - Spawns a process in a suspended state, injects shellcode, hijack main
    thread with APC, and execute shellcode.
    regenum                   System, AV, and EDR profiling via registry queries
    shinject                  Inject shellcode into a process
    show_beacon_downloads     Show all Downloads associated with your current Beacon.
    show_sync_location        Shows sync location for downloads.
    static_syscalls_apc_shspawnSpawn process and use syscalls to execute custom shellcode launch with Nt functions (NtMapViewOfSection -> NtQueueUserApc).
    static_syscalls_apc_spawn Spawn process and use syscalls to execute beacon shellcode launch with Nt functions (NtMapViewOfSection -> NtQueueUserApc).
    static_syscalls_dump      Use static syscalls to dump a given PID and save to disk
    static_syscalls_inject    Use static syscalls to execute CRT beacon shellcode launch with Nt functions.
    static_syscalls_shinject  Use static syscalls to execute custom shellcode launch with Nt functions.
    sync_all_beacon_downloads Sync all Downloads.
    sync_beacon_downloads     Sync all Downloads from current Beacon.
    syscalls_inject           Use syscalls from on-disk dll to execute CRT beacon shellcode launch with Nt functions.
    syscalls_shinject         Use syscalls from on-disk dll to execute custom shellcode launch with Nt functions.
    unhook                    remove hooks from DLLs in this process
    zerologon                 Reset DC machine account password with CVE-2020-1472
    info_Advanced             A common collection of OS commands, and Red Team Tips for when you have no Google or RTFM on hand
    
    __________________________________________________________________________________________________________________________________
    
    
