# Driver Collider - Background
Current sixty-four-bit Windows operating systems require device drivers to be digitally-signed and to chain to a certificate authority registered on the system. While malware writers can in theory purchase their own code-signing certificate for a small fee and sign their own drivers, the use of their own certificate can be made a signature for use by anti-virus products to detect them. An existing infrastructure is already in place for blocking signed malware in the form of Certificate Revocation. Thus, malware writers have a significant incentive to rely on legitimately signed binaries where possible. Furthermore, using legitimate, digitally-signed drivers complicates detection, since the very same drivers are also used by legitimate products. This Bring Your Own Kernel Driver (BYOKD) technique was used in the Uroburos malware toolkit, which carried along a copy of the Virtual Box driver VBoxDrv.sys, digitally-signed by Oracle, and exploited this to gain kernel mode code execution [1]. Another example was the use of the EldoS RawDisk driver to securely wipe data in other malware attacks [2].

These cases highlight the need to be able to quickly block the loading of unwanted kernel drivers. While Windows does not support preventing a user with administrative privileges from installing and running a digitally-signed driver, it is relatively easy to create a driver that can block the load of a specific driver, and also detect attempts to access it. NSA IA has implemented a proof-of-concept solution to block known legitimate drivers used in conjunction with malware in a project called Driver Collider. This solution also logs attempts to access the blacklisted drivers in the System event log.


# Driver Collider - Technical Details 
Drivers that support communication with user mode clients generally always create at least one named `DEVICE_OBJECT` in their `DriverEntry` entry point routine using the function `IoCreateDevice`. This object is used by the operating system to manage communication with a driver. If a driver tries to create a `DEVICE_OBJECT` having a name already in use, the call to `IoCreateDevice` fails and returns an error code. In this case, legitimate drivers nearly always return an error status. When the `DriverEntry` fails, Windows unloads the driver. This happens before any communication with a user mode client is allowed. Therefore, one easy method to block a legitimate driver from running on the system is to write a very simple driver that creates a `DEVICE_OBJECT` of the same name used by the target driver. `DEVICE_OBJECT` names are typically of the form `\Device\<name>` and can generally be found by enumerating strings in the target driver. Having implemented such a driver, it is important to verify that the target driver really does respond as expected and unload when its call to `IoCreateDevice` fails. Poorly written drivers could fail to check the return code on the call and try to operate on a NULL `DEVICE_OBJECT` pointer, resulting in a system crash. This is easy to test by loading the blocking driver, and then attempting to load the target driver to verify the load fails.

Before attempting to load a driver, it is a frequent practice for user mode clients to attempt to contact the driver first in case it is already running. This provides an easy method for the blocking driver to identify attempts to communicate with the target driver. The blocking driver initializes an `IRP_MJ_CREATE` major function to watch for attempts to open the name-conflicting `DEVICE_OBJECT`. Since the operating system call to the driver's IRP_MJ_CREATE handler occurs in the context of the process attempting to open the object, the blocking driver can identify the offending process via `PsGetCurrentProcessId`, and find the system path and image name of the process binary with `ZwQueryInformationProcess`. The Driver Collider solution uses this implementation to log attempts to open the conflicting object in the System event log.

The project includes a whitelist of device names taken from the strings of Microsoft signed drivers from full installation desktop versions of Windows 7 - 10 and server versions of Windows 2008 R2 - 2016. The inclusion and use of the whitelist is intended to provide protection from inadvertently blocking any legitimate Microsoft drivers that are needed for system operation. Both the whitelist and blacklist of driver object names are configured through a Group Policy Extension that is created upon installation.

The whitelist was created by taking the output of the PowerShell script `device_strings.ps1`, run on each version of Windows OS mentioned above. The script makes use of the `sigcheck.exe` and `strings.exe` programs included in the Windows Sysinternals software suite. The text file `collision_list.txt` contains the whitelist and can be found in the folder **Program Files -> Collision -> Install Files** after installation.


## Installation / Uninstallation
Building of the Driver Collider project is accomplished with Visual Studio 2015, along with Windows SDK, Windows DDK, and Wix Installer plug-in for Visual Studio. A valid certificate will need to be referenced in the Visual Studio project to digitally-sign the driver upon compilation.

Once built, the execution of the `collisionSetup.msi` file will create a kernel driver service for the Collision driver, as well as save the driver, Group Policy Extension files, and Windows Event Log manifest file to disk. After installation, the system administrator must use the Group Policy Extension at **Computer Configuration -> Policies -> Administrative Templates -> System -> IA Configuration -> Collision Tool Configuration** to configure the whitelist and blacklist, then restart the system for the Collision tool to begin operation. 

All installation files and the whitelist can be found in the folder **Program Files -> Collision -> Install Files** after installation. 

To uninstall, the system administrator can navigate to the Collision item in the **Add and Remove Programs** Control Panel option and select Uninstall.


## References
[1] https://www.mcafee.com/uk/security-awareness/articles/rise-of-rootkits.aspx
[2] https://community.rsa.com/community/products/netwitness/blog/2017/02/08/recent-resurgence-in-shamoon


## License
See [LICENSE] {LICENSE.md}


## Disclaimer
See [DISCLAIMER] {DISCLAIMER.md}