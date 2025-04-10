# DefenderKiller: A Tamper Protection Bypass PoC

### This PoC is currently working on all versions of Windows, please note that the canary build of windows 11 has moved the driver files from the "wd" subfolder to the main "drivers" folder. This does not affect the bypass, and a check has been added to locate the drivers.

## Overview

DefenderKiller is a proof-of-concept (PoC) repository that demonstrates a workaround for disabling Windows Defender’s tamper protection and real-time protection components. Inspired by [Disabling Tamper Protection and Other Defender MDE Components](https://www.alteredsecurity.com/post/disabling-tamper-protection-and-other-defender-mde-components) by Altered Security, this PoC adapts the technique of swapping driver files while also automating several critical steps. In this case, the core bypass is implemented by renaming Windows Defender driver files—preventing `wdfilter` from loading—thus effectively disabling tamper protection. Additional enhancements include automated downloads, elevation handling via AdvancedRun, UAC disablement, and registry modifications.

## Technical Details

The script is structured in multiple stages to ensure a reliable and reversible process. Below is a breakdown of the key technical components:

### 1. AdvancedRun Download and Integration

- **Download and Extract AdvancedRun:**  
  The script first checks for the presence of the **AdvancedRun.exe** executable under `C:\ProgramData\AdvancedRun`. If missing, it downloads the AdvancedRun package from NirSoft, extracts it, and places it in the designated directory.
  - *Key Commands:*
    - `Invoke-WebRequest` downloads the ZIP archive.
    - `Expand-Archive` extracts the executable for later use.

- **Elevated Command Execution:**  
  A helper function, `Invoke-ElevatedCommand`, leverages AdvancedRun to run commands with elevated privileges. This ensures that subsequent operations such as renaming system drivers or modifying the registry can be executed without UAC prompts.
  - *Key Implementation:*
    ~~~powershell
    function Invoke-ElevatedCommand {
        param(
            [Parameter(Mandatory=$true)]
            [string]$Command
        )
        $arguments = '/RunAs 8 /RunMode 4 /CommandLine "' + $Command + '" /Run'
        Start-Process -FilePath $global:advRunPath -ArgumentList $arguments -Wait
    }
    ~~~

### 2. Disabling UAC

The function `Disable-UAC` changes the registry setting for UAC (`EnableLUA`) to 0, preventing further interruptions by User Account Control during the remainder of the process. This is particularly useful for ensuring that all elevated operations run seamlessly.
- *Key Command:*
  ~~~powershell
  Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -Value 0 -Force
  ~~~

### 3. Driver File Detection and Swapping

- **Driver Check:**  
  The `Get-WdDriversPath` function looks for the presence of the Defender drivers (`WdFilter.sys` and `WdNisDrv.sys`). If both files are found, it returns the path to the directory.
  - *Logic:*
    - It iterates through potential directories (`C:\Windows\System32\drivers` and `C:\Windows\System32\drivers\wd`).
    - Confirms that both critical driver files exist before proceeding.

- **Driver Swapping:**  
  The `Swap-WdDrivers` function performs the core bypass. By renaming the driver files, the script prevents the wdfilter from loading:
  - **Step 1:** `WdFilter.sys` is renamed to `WdFilter_tmp.sys`.
  - **Step 2:** `WdNisDrv.sys` is then renamed to `WdFilter.sys`.
  - **Step 3:** Finally, the temporary file `WdFilter_tmp.sys` is renamed to `WdNisDrv.sys`.
  
  This sequence effectively swaps the driver names so that the expected files are not present where Windows Defender expects to find them.
  - *Key Command Block:*
    ~~~powershell
    $cmd = "Rename-Item -Path '$fileWdFilter' -NewName 'WdFilter_tmp.sys' -Force; " +
           "Rename-Item -Path '$fileWdNisDrv' -NewName 'WdFilter.sys' -Force; " +
           "Rename-Item -Path '$driversDir\WdFilter_tmp.sys' -NewName 'WdNisDrv.sys' -Force; exit"
    Invoke-ElevatedCommand -Command $cmd
    ~~~

### 4. Registry Modifications

After the driver swap and system reboot, the script continues with additional registry modifications to ensure that Windows Defender’s tamper protection and real-time monitoring are disabled:

- **Disabling Tamper Protection:**  
  The function `Disable-TamperProtection` updates registry keys under `HKLM:\SOFTWARE\Microsoft\Windows Defender\Features` to disable tamper protection by setting both `TamperProtection` and `TamperProtectionSource` to `4`.
  - *Key Command:*
    ~~~powershell
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features' -Name 'TamperProtection' -Value 4 -Force;
    ~~~

- **Disabling AV/MDE:**  
  The `Disable-AV_MDE` function creates a new registry entry under the policies branch for Windows Defender real-time protection and sets `DisableRealtimeMonitoring` to `1`, effectively turning off active antivirus scanning.
  - *Key Command:*
    ~~~powershell
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -Name 'DisableRealtimeMonitoring' -Value 1 -Force;
    ~~~

### 5. RunOnce Registry Key and Controlled Reboot

To manage the multi-stage process:

- **Flag File Creation:**  
  A flag file (`DriverSwapCompleted.txt`) is created in the TEMP directory to determine whether the system reboot already occurred.

- **RunOnce Setup:**  
  The function `Set-RunOnceKey` ensures that after reboot, the script continues with the next steps by placing a command into the `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce` registry key. This mechanism helps resume the operation seamlessly after the system restarts.

- **Execution Logic:**  
  The script initially performs the driver swap and disables UAC, then sets up the reboot environment. On reboot, it detects the flag file, applies the registry modifications to disable tamper protection and AV/MDE, removes the flag file, and confirms that UAC is disabled system-wide.

## Methodology and Acknowledgments

This repository builds on the core bypass method introduced in the [Altered Security blog post](https://www.alteredsecurity.com/post/disabling-tamper-protection-and-other-defender-mde-components). Special thanks to the author of the original post for providing the insights that inspired this work. While the fundamental concept of disrupting the driver loading sequence remains unchanged, this PoC enhances it by automating additional system modifications, handling privileges more robustly with AdvancedRun, and ensuring a controlled environment through registry and reboot operations.

## Disclaimer

**WARNING:** This PoC is provided for educational and research purposes only. Modifying system security settings, such as disabling Windows Defender tamper protection, may violate organizational policies or local laws. Use responsibly and only in environments where you have explicit permission to test and modify these settings. The contributors and maintainers of this project are not liable for any misuse or damages resulting from the application of this script.

## MSRC Response

> "Upon investigation, we have determined that this submission does not meet the bar for security servicing. This report does not appear to identify a weakness in a Microsoft product or service that would enable an attacker to compromise the integrity, availability, or confidentiality of a Microsoft offering. As submitted, this attack requires administrative privileges. Reports that are predicated on having administrative/root privileges are not valid reports because a malicious administrator can do much worse things.
> 
> As such, this thread is being closed and no longer monitored."

*— Microsoft Security Response Center (MSRC)*
