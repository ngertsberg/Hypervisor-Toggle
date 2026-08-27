Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$dgPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
$scPath = "$dgPath\Scenarios"
$hvciPath = "$scPath\HypervisorEnforcedCodeIntegrity"
$sgPath = "$scPath\SystemGuard"
$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'

# Disable values differ for some policies. Original values are saved before changes.
$managed = @(
    @{Id='VBS';Path=$dgPath;Name='EnableVirtualizationBasedSecurity';Off=0},
    @{Id='PlatformSecurity';Path=$dgPath;Name='RequirePlatformSecurityFeatures';Off=0},
    @{Id='Mandatory';Path=$dgPath;Name='Mandatory';Off=0},
    @{Id='HVCI';Path=$hvciPath;Name='Enabled';Off=0},
    @{Id='CG';Path=$lsaPath;Name='LsaCfgFlags';Off=0},
    @{Id='CGPolicy';Path=$policyPath;Name='LsaCfgFlags';Off=0},
    @{Id='VBSPolicy';Path=$policyPath;Name='EnableVirtualizationBasedSecurity';Off=0},
    @{Id='HVCIPolicy';Path=$policyPath;Name='HypervisorEnforcedCodeIntegrity';Off=0},
    @{Id='SGPolicy';Path=$policyPath;Name='ConfigureSystemGuardLaunch';Off=2},
    @{Id='SystemGuard';Path=$sgPath;Name='Enabled';Off=0}
)

function Get-RegValue([string]$Path,[string]$Name) {
    try { (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name }
    catch { $null }
}
function Set-Dword([string]$Path,[string]$Name,[int]$Value) {
    New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
    New-ItemProperty -LiteralPath $Path -Name $Name -PropertyType DWord -Value $Value -Force -ErrorAction Stop | Out-Null
}
function Get-DeviceGuard {
    try { Get-CimInstance Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard' -ErrorAction Stop }
    catch { $null }
}
function Get-HypervisorPresent {
    try { [bool](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).HypervisorPresent }
    catch { $false }
}
function Set-HypervisorLaunch([ValidateSet('Auto','Off')][string]$Value) {
    $out = & "$env:SystemRoot\System32\bcdedit.exe" /set hypervisorlaunchtype $Value 2>&1
    if ($LASTEXITCODE) { throw "BCDEdit failed: $(($out|Out-String).Trim())" }
}
function Get-Locks {
    $r = [Collections.Generic.List[string]]::new()
    if ((Get-RegValue $dgPath 'Locked') -eq 1) { $r.Add('VBS UEFI lock') }
    if ((Get-RegValue $hvciPath 'Locked') -eq 1) { $r.Add('Memory Integrity UEFI lock') }
    if ((Get-RegValue $lsaPath 'LsaCfgFlags') -eq 1 -or (Get-RegValue $policyPath 'LsaCfgFlags') -eq 1) { $r.Add('Credential Guard UEFI lock') }
    $r
}
function Disable-ActiveProtections {
    $locks = @(Get-Locks)
    if ($locks.Count) {
        throw "No changes were made. These settings need Microsoft's physical-presence UEFI opt-out process:`n`n- $($locks -join "`n- ")"
    }
    $count = 0
    foreach ($s in $managed) {
        $v = Get-RegValue $s.Path $s.Name
        if ($null -ne $v -and [int]$v -ne [int]$s.Off) {
            Set-Dword $s.Path $s.Name ([int]$s.Off)
            $count++
        }
    }
    if (Get-HypervisorPresent) {
        Set-HypervisorLaunch Off
        $count++
    }
    $count
}
function Enable-AllProtections {
    # Enable VBS and Memory Integrity without creating a UEFI lock.
    Set-Dword $dgPath 'EnableVirtualizationBasedSecurity' 1
    Set-Dword $dgPath 'RequirePlatformSecurityFeatures' 1
    Set-Dword $dgPath 'Locked' 0
    Set-Dword $hvciPath 'Enabled' 1
    Set-Dword $hvciPath 'Locked' 0
    Set-Dword $hvciPath 'WasEnabledBy' 2

    # Value 2 enables Credential Guard without a UEFI lock.
    Set-Dword $lsaPath 'LsaCfgFlags' 2
    Set-Dword $sgPath 'Enabled' 1

    # If these policy values already exist, return them to enabled states without
    # creating new policy keys that make Windows display "managed by your organization."
    if ($null -ne (Get-RegValue $policyPath 'EnableVirtualizationBasedSecurity')) { Set-Dword $policyPath 'EnableVirtualizationBasedSecurity' 1 }
    if ($null -ne (Get-RegValue $policyPath 'HypervisorEnforcedCodeIntegrity')) { Set-Dword $policyPath 'HypervisorEnforcedCodeIntegrity' 2 }
    if ($null -ne (Get-RegValue $policyPath 'LsaCfgFlags')) { Set-Dword $policyPath 'LsaCfgFlags' 2 }
    if ($null -ne (Get-RegValue $policyPath 'ConfigureSystemGuardLaunch')) { Set-Dword $policyPath 'ConfigureSystemGuardLaunch' 1 }

    Set-HypervisorLaunch Auto
    foreach ($option in @(@('testsigning','off'),@('nointegritychecks','off'))) {
        $out = & "$env:SystemRoot\System32\bcdedit.exe" /set $option[0] $option[1] 2>&1
        if ($LASTEXITCODE) { throw "BCDEdit could not enforce DSE: $(($out | Out-String).Trim())" }
    }

}

# Read the kernel's live Code Integrity flag so DSE status is not guessed from BCD.
if (-not ('NativeCI' -as [type])) {
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class NativeCI {
  [StructLayout(LayoutKind.Sequential)] public struct Info { public UInt32 Length; public UInt32 Options; }
  [DllImport("ntdll.dll")] public static extern int NtQuerySystemInformation(int c, ref Info i, int l, IntPtr r);
}
'@
}
function Get-DseStatus {
    try {
        $i = [NativeCI+Info]::new(); $i.Length = [Runtime.InteropServices.Marshal]::SizeOf($i)
        if ([NativeCI]::NtQuerySystemInformation(103,[ref]$i,$i.Length,[IntPtr]::Zero)) { return 'Unknown' }
        if ($i.Options -band 1) { 'Enforced' } else { 'Disabled this boot' }
    } catch { 'Unknown' }
}
function Start-AdvancedRestart {
    $bcdedit = "$env:SystemRoot\System32\bcdedit.exe"
    $out = & $bcdedit /set '{current}' onetimeadvancedoptions on 2>&1
    if ($LASTEXITCODE) {
        throw "Windows could not schedule the one-time Startup Settings menu. $(($out | Out-String).Trim())"
    }
    Restart-Computer
}

# ----- Styled GUI -----
$bg=[Drawing.Color]::FromArgb(15,18,27); $card=[Drawing.Color]::FromArgb(25,30,43)
$soft=[Drawing.Color]::FromArgb(34,40,55); $text=[Drawing.Color]::FromArgb(240,243,249)
$muted=[Drawing.Color]::FromArgb(151,160,181); $accent=[Drawing.Color]::FromArgb(94,114,228)
$green=[Drawing.Color]::FromArgb(44,194,139); $red=[Drawing.Color]::FromArgb(239,91,112); $orange=[Drawing.Color]::FromArgb(244,169,66)

$form=[Windows.Forms.Form]@{Text='Virtualization Security Manager';ClientSize=[Drawing.Size]::new(650,609);StartPosition='CenterScreen';FormBorderStyle='FixedSingle';MaximizeBox=$false;BackColor=$bg;ForeColor=$text;Font=[Drawing.Font]::new('Segoe UI',9)}
$bar=[Windows.Forms.Panel]@{BackColor=$accent;Location=[Drawing.Point]::new(0,0);Size=[Drawing.Size]::new(6,104)}; $form.Controls.Add($bar)
$eyebrow=[Windows.Forms.Label]@{Text='SYSTEM SECURITY';ForeColor=$accent;Font=[Drawing.Font]::new('Segoe UI Semibold',8);AutoSize=$true;Location=[Drawing.Point]::new(34,20)}; $form.Controls.Add($eyebrow)
$title=[Windows.Forms.Label]@{Text='NICKEYS AWESOME Virtualization protection';ForeColor=$text;Font=[Drawing.Font]::new('Segoe UI Semibold',21);AutoSize=$true;Location=[Drawing.Point]::new(30,38)}; $form.Controls.Add($title)
$sub=[Windows.Forms.Label]@{Text='Live status and reversible configuration for Windows security services.';ForeColor=$muted;AutoSize=$true;Location=[Drawing.Point]::new(34,80)}; $form.Controls.Add($sub)
$panel=[Windows.Forms.Panel]@{BackColor=$card;Location=[Drawing.Point]::new(30,116);Size=[Drawing.Size]::new(590,309)}; $form.Controls.Add($panel)
$caption=[Windows.Forms.Label]@{Text='CURRENT STATUS';ForeColor=$muted;Font=[Drawing.Font]::new('Segoe UI Semibold',8);AutoSize=$true;Location=[Drawing.Point]::new(22,16)}; $panel.Controls.Add($caption)
$refresh=[Windows.Forms.Button]@{Text='Refresh';ForeColor=$text;BackColor=$soft;FlatStyle='Flat';Location=[Drawing.Point]::new(482,10);Size=[Drawing.Size]::new(84,30);Cursor='Hand';UseVisualStyleBackColor=$false}; $refresh.FlatAppearance.BorderSize=0; $panel.Controls.Add($refresh)

$features=@(
 @{K='Hypervisor';N='Windows hypervisor';D='Hyper-V launch state'},@{K='VBS';N='Virtualization-based Security';D='Secure kernel isolation'},
 @{K='Memory';N='Memory Integrity';D='Hypervisor-protected code integrity'},@{K='Credential';N='Credential Guard';D='Credential isolation'},
 @{K='SystemGuard';N='System Guard Secure Launch';D='Firmware and boot protection'},@{K='DSE';N='Driver Signature Enforcement';D='Kernel driver signature checks'}
)
$values=@{}; $y=56
foreach($f in $features) {
    $n=[Windows.Forms.Label]@{Text=$f.N;ForeColor=$text;Font=[Drawing.Font]::new('Segoe UI Semibold',9.5);AutoSize=$true;Location=[Drawing.Point]::new(22,$y)}; $panel.Controls.Add($n)
    $d=[Windows.Forms.Label]@{Text=$f.D;ForeColor=$muted;Font=[Drawing.Font]::new('Segoe UI',8);AutoSize=$true;Location=[Drawing.Point]::new(22,$y+20)}; $panel.Controls.Add($d)
    $v=[Windows.Forms.Label]@{ForeColor=$muted;Font=[Drawing.Font]::new('Segoe UI Semibold',9);TextAlign='MiddleRight';Location=[Drawing.Point]::new(370,$y+4);Size=[Drawing.Size]::new(195,24)}; $panel.Controls.Add($v); $values[$f.K]=$v
    $y+=41
}
function New-ActionButton($label,$x,$color) {
    $b=[Windows.Forms.Button]@{Text=$label;ForeColor=[Drawing.Color]::White;BackColor=$color;Font=[Drawing.Font]::new('Segoe UI Semibold',10);FlatStyle='Flat';Cursor='Hand';Location=[Drawing.Point]::new($x,447);Size=[Drawing.Size]::new(280,48);UseVisualStyleBackColor=$false}; $b.FlatAppearance.BorderSize=0; $form.Controls.Add($b); $b
}
$disable=New-ActionButton 'Disable all + restart' 30 $red
$enable=New-ActionButton 'Enable all + restart' 340 $accent
$dse=[Windows.Forms.Button]@{Text='Restart to disable DSE for one boot';ForeColor=$text;BackColor=$soft;Font=[Drawing.Font]::new('Segoe UI Semibold',9);FlatStyle='Flat';Cursor='Hand';Location=[Drawing.Point]::new(30,509);Size=[Drawing.Size]::new(590,40);UseVisualStyleBackColor=$false}; $dse.FlatAppearance.BorderSize=0; $form.Controls.Add($dse)
$note=[Windows.Forms.Label]@{Text='Disable schedules the one-time boot options menu. On the next screen, press 7/F7 for DSE.';ForeColor=$muted;TextAlign='TopCenter';Location=[Drawing.Point]::new(31,566);Size=[Drawing.Size]::new(588,25)}; $form.Controls.Add($note)

function Set-Status($key,$label,$kind) {
    $values[$key].Text=$label.ToUpperInvariant()
    $values[$key].ForeColor=switch($kind){'Good'{$green}'Bad'{$red}'Warn'{$orange}default{$muted}}
}
function Set-ActionState($button,[bool]$enabled,$enabledColor) {
    $button.Enabled=$enabled
    if($enabled){
        $button.BackColor=$enabledColor
        $button.ForeColor=if($button -eq $dse){$text}else{[Drawing.Color]::White}
        $button.Cursor=[Windows.Forms.Cursors]::Hand
    }else{
        $button.BackColor=[Drawing.Color]::FromArgb(28,33,45)
        $button.ForeColor=[Drawing.Color]::FromArgb(86,94,112)
        $button.Cursor=[Windows.Forms.Cursors]::Default
    }
}
function Refresh-Status {
    $dg=Get-DeviceGuard; $configured=@($dg.SecurityServicesConfigured); $running=@($dg.SecurityServicesRunning)
    $hypervisorOn=Get-HypervisorPresent
    $vbsOn=($dg -and $dg.VirtualizationBasedSecurityStatus -gt 0) -or (Get-RegValue $dgPath 'EnableVirtualizationBasedSecurity') -eq 1
    $memoryOn=($running -contains 2) -or ($configured -contains 2) -or (Get-RegValue $hvciPath Enabled) -eq 1
    $credentialOn=($running -contains 1) -or ($configured -contains 1) -or (Get-RegValue $lsaPath LsaCfgFlags) -gt 0 -or (Get-RegValue $policyPath LsaCfgFlags) -gt 0
    $systemGuardOn=($running -contains 3) -or ($configured -contains 3) -or (Get-RegValue $sgPath Enabled) -eq 1

    if($hypervisorOn){Set-Status Hypervisor Running Good}else{Set-Status Hypervisor 'Not running' Bad}
    if($dg -and $dg.VirtualizationBasedSecurityStatus -eq 2){Set-Status VBS Running Good}elseif($vbsOn){Set-Status VBS 'Configured / restart' Warn}else{Set-Status VBS Disabled Bad}
    if($running -contains 2){Set-Status Memory Running Good}elseif($memoryOn){Set-Status Memory 'Configured / restart' Warn}else{Set-Status Memory Disabled Bad}
    if($running -contains 1){Set-Status Credential Running Good}elseif($credentialOn){Set-Status Credential 'Configured / restart' Warn}else{Set-Status Credential Disabled Bad}
    if($running -contains 3){Set-Status SystemGuard Running Good}elseif($systemGuardOn){Set-Status SystemGuard 'Configured / restart' Warn}else{Set-Status SystemGuard Disabled Bad}
    $ds=Get-DseStatus; if($ds -eq 'Enforced'){Set-Status DSE $ds Good}elseif($ds -eq 'Unknown'){Set-Status DSE $ds Neutral}else{Set-Status DSE $ds Bad}

    $anythingOn=$hypervisorOn -or $vbsOn -or $memoryOn -or $credentialOn -or $systemGuardOn -or $ds -eq 'Enforced'
    $everythingOn=$hypervisorOn -and $vbsOn -and $memoryOn -and $credentialOn -and $systemGuardOn -and $ds -eq 'Enforced'
    Set-ActionState $disable $anythingOn $red
    Set-ActionState $enable (-not $everythingOn) $accent
    Set-ActionState $dse ($ds -ne 'Disabled this boot') $soft
}
$refresh.Add_Click({Refresh-Status})
$disable.Add_Click({
    try {
        Disable-ActiveProtections | Out-Null
        Start-AdvancedRestart
    }
    catch{[Windows.Forms.MessageBox]::Show($_.Exception.Message,'Unable to disable all protections','OK','Error');Refresh-Status}
})
$enable.Add_Click({
    try {
        Enable-AllProtections
        Restart-Computer
    }
    catch{[Windows.Forms.MessageBox]::Show($_.Exception.Message,'Enable failed','OK','Error');Refresh-Status}
})
$dse.Add_Click({
    $a=[Windows.Forms.MessageBox]::Show("Windows will restart directly to its one-time advanced boot options. Press 7 or F7 for Disable Driver Signature Enforcement.`n`nDSE will be disabled for that boot only. Continue?",'One-boot DSE disable','YesNo','Warning')
    if($a -eq 'Yes'){try{Start-AdvancedRestart}catch{[Windows.Forms.MessageBox]::Show($_.Exception.Message,'Restart failed','OK','Error')}}
})
Refresh-Status
[void]$form.ShowDialog()
