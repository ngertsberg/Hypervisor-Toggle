# Hypervisor Toggle

A Windows PowerShell GUI for viewing and toggling virtualization-based security features from one place.

## Managed features

- Windows hypervisor launch state
- Virtualization-based Security (VBS)
- Memory Integrity / Hypervisor-protected Code Integrity (HVCI)
- Credential Guard
- System Guard Secure Launch
- Driver Signature Enforcement (DSE)

Windows Hello and biometric settings are intentionally not modified.

## Requirements

- Windows 10 or Windows 11
- Windows PowerShell 5.1
- An administrator account

## Usage

Keep `Manager.bat` and `hypervisor.ps1` in the same folder, then double-click `Manager.bat`. Accept the administrator prompt to open the GUI.

### Disable all

Click **Disable all + restart**. The manager disables the active virtualization protections and schedules the one-time Windows advanced boot-options menu.

At the boot-options screen, press **7** or **F7** to select **Disable Driver Signature Enforcement**. DSE is disabled only for that Windows session and is automatically enforced again after a normal restart.

### Enable all

Click **Enable all + restart**. The manager explicitly enables the hypervisor, VBS, Memory Integrity, Credential Guard, System Guard, and DSE, then performs a normal restart.

The buttons are disabled visually and interactively when their operation is not applicable to the current system state.

## Important notes

- Disabling these protections reduces Windows security.
- Hyper-V, WSL2, Windows Sandbox, virtual machines, and some anti-cheat software may stop working while the hypervisor or DSE protections are disabled.
- The manager refuses the disable operation when it detects a UEFI-locked VBS feature. It does not modify BIOS or UEFI settings.
- Some protections require compatible hardware and a supported Windows edition. A configured feature may not run when the platform does not support it.
- Save open work before using either restart action.

## Files

- `Manager.bat` requests administrator privileges and launches the GUI.
- `hypervisor.ps1` contains status detection, configuration logic, and the Windows Forms interface.
