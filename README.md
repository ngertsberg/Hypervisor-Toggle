# Hypervisor Toggle

A Windows PowerShell GUI for viewing and toggling virtualization-based security features from one place.

## Managed features

- Windows hypervisor launch state
- Virtualization-based Security (VBS)
- Memory Integrity / Hypervisor-protected Code Integrity (HVCI)
- Credential Guard
- System Guard Secure Launch configuration
- Driver Signature Enforcement (DSE)

Windows Hello and biometric settings are intentionally not modified.

## Requirements

- Windows 10 or Windows 11
- Windows PowerShell 5.1
- An administrator account

## Usage

Keep `Manager.bat` and `hypervisor.ps1` in the same folder, then double-click `Manager.bat`. Accept the administrator prompt to open the GUI.

### Disable all

Click **Disable all + restart**. The manager explicitly writes the disabled value for every managed registry and boot setting, then schedules the one-time Windows advanced boot-options menu.

The disable action also turns off the hypervisor, Virtual Secure Mode, and isolated-context boot settings so the secure kernel does not remain active after restart.

If Riot Vanguard is installed, the manager stops its `vgc` service and returns it to Demand Start for the disabled session.

At the boot-options screen, press **7** or **F7** to select **Disable Driver Signature Enforcement**. DSE is disabled only for that Windows session and is automatically enforced again after a normal restart.

### Enable all

Click **Enable all + restart**. The manager explicitly writes the enabled value for every managed registry and boot setting, including the hypervisor, VBS, Memory Integrity, Credential Guard, System Guard, and DSE, then performs a normal restart.

If Riot Vanguard is installed, the manager configures its `vgc` service for Automatic startup before rebooting so it can initialize with the restored Windows security stack.

The manager stages the hypervisor, Virtual Secure Mode, and isolated-context boot settings before restarting so supported systems do not need a second configuration restart.

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
