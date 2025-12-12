$defenderremoverver = "12.8.2"

function RunAsTI ($cmd,$arg) { $id='RunAsTI'; $key="Registry::HKU\$(((whoami /user)-split' ')[-1])\Volatile Environment"; $code=@'
 $I=[int32]; $M=$I.module.gettype("System.Runtime.Interop`Services.Mar`shal"); $P=$I.module.gettype("System.Int`Ptr"); $S=[string]
 $D=@(); $T=@(); $DM=[AppDomain]::CurrentDomain."DefineDynami`cAssembly"(1,1)."DefineDynami`cModule"(1); $Z=[uintptr]::size
 0..5|% {$D += $DM."Defin`eType"("AveYo_$_",1179913,[ValueType])}; $D += [uintptr]; 4..6|% {$D += $D[$_]."MakeByR`efType"()}
 $F='kernel','advapi','advapi', ($S,$S,$I,$I,$I,$I,$I,$S,$D[7],$D[8]), ([uintptr],$S,$I,$I,$D[9]),([uintptr],$S,$I,$I,[byte[]],$I)
 0..2|% {$9=$D[0]."DefinePInvok`eMethod"(('CreateProcess','RegOpenKeyEx','RegSetValueEx')[$_],$F[$_]+'32',8214,1,$S,$F[$_+3],1,4)}
 $DF=($P,$I,$P),($I,$I,$I,$I,$P,$D[1]),($I,$S,$S,$S,$I,$I,$I,$I,$I,$I,$I,$I,[int16],[int16],$P,$P,$P,$P),($D[3],$P),($P,$P,$I,$I)
 1..5|% {$k=$_; $n=1; $DF[$_-1]|% {$9=$D[$k]."Defin`eField"('f' + $n++, $_, 6)}}; 0..5|% {$T += $D[$_]."Creat`eType"()}
 0..5|% {nv "A$_" ([Activator]::CreateInstance($T[$_])) -fo}; function F ($1,$2) {$T[0]."G`etMethod"($1).invoke(0,$2)}
 $TI=(whoami /groups)-like'*1-16-16384*'; $As=0; if(!$cmd) {$cmd='control';$arg='admintools'}; if ($cmd-eq'This PC'){$cmd='file:'}
 if (!$TI) {'TrustedInstaller','lsass','winlogon'|% {if (!$As) {$9=sc.exe start $_; $As=@(get-process -name $_ -ea 0|% {$_})[0]}}
 function M ($1,$2,$3) {$M."G`etMethod"($1,[type[]]$2).invoke(0,$3)}; $H=@(); $Z,(4*$Z+16)|% {$H += M "AllocHG`lobal" $I $_}
 M "WriteInt`Ptr" ($P,$P) ($H[0],$As.Handle); $A1.f1=131072; $A1.f2=$Z; $A1.f3=$H[0]; $A2.f1=1; $A2.f2=1; $A2.f3=1; $A2.f4=1
 $A2.f6=$A1; $A3.f1=10*$Z+32; $A4.f1=$A3; $A4.f2=$H[1]; M "StructureTo`Ptr" ($D[2],$P,[boolean]) (($A2 -as $D[2]),$A4.f2,$false)
 $Run=@($null, "powershell -win 1 -nop -c iex `$env:R; # $id", 0, 0, 0, 0x0E080600, 0, $null, ($A4 -as $T[4]), ($A5 -as $T[5]))
 F 'CreateProcess' $Run; return}; $env:R=''; rp $key $id -force; $priv=[diagnostics.process]."GetM`ember"('SetPrivilege',42)[0]
 'SeSecurityPrivilege','SeTakeOwnershipPrivilege','SeBackupPrivilege','SeRestorePrivilege' |% {$priv.Invoke($null, @("$_",2))}
 $HKU=[uintptr][uint32]2147483651; $NT='S-1-5-18'; $reg=($HKU,$NT,8,2,($HKU -as $D[9])); F 'RegOpenKeyEx' $reg; $LNK=$reg[4]
 function L ($1,$2,$3) {sp 'HKLM:\Software\Classes\AppID\{CDCBCFCA-3CDC-436f-A4E2-0E02075250C2}' 'RunAs' $3 -force -ea 0
  $b=[Text.Encoding]::Unicode.GetBytes("\Registry\User\$1"); F 'RegSetValueEx' @($2,'SymbolicLinkValue',0,6,[byte[]]$b,$b.Length)}
 function Q {[int](gwmi win32_process -filter 'name="explorer.exe"'|?{$_.getownersid().sid-eq$NT}|select -last 1).ProcessId}
 $11bug=($((gwmi Win32_OperatingSystem).BuildNumber)-eq'22000')-AND(($cmd-eq'file:')-OR(test-path -lit $cmd -PathType Container))
 if ($11bug) {'System.Windows.Forms','Microsoft.VisualBasic' |% {[Reflection.Assembly]::LoadWithPartialName("'$_")}}
 if ($11bug) {$path='^(l)'+$($cmd -replace '([\+\^\%\~\(\)\[\]])','{$1}')+'{ENTER}'; $cmd='control.exe'; $arg='admintools'}
 L ($key-split'\\')[1] $LNK ''; $R=[diagnostics.process]::start($cmd,$arg); if ($R) {$R.PriorityClass='High'; $R.WaitForExit()}
 if ($11bug) {$w=0; do {if($w-gt40){break}; sleep -mi 250;$w++} until (Q); [Microsoft.VisualBasic.Interaction]::AppActivate($(Q))}
 if ($11bug) {[Windows.Forms.SendKeys]::SendWait($path)}; do {sleep 7} while(Q); L '.Default' $LNK 'Interactive User'
'@; $V='';'cmd','arg','id','key'|%{$V+="`n`$$_='$($(gv $_ -val)-replace"'","''")';"}; sp $key $id $($V,$code) -type 7 -force -ea 0
 start powershell -args "-win 1 -nop -c `n$V `$env:R=(gi `$key -ea 0).getvalue(`$id)-join''; iex `$env:R" -verb runas
}

function Remove-AppxPackages {
    param (
        [string[]]$RemoveAppx = @("SecHealthUI"),
        [string[]]$Skip = @(),
        [string[]]$Users = @('S-1-5-18')
    )

    $Provisioned = Get-AppxProvisionedPackage -Online
    $AppxPackage = Get-AppxPackage -AllUsers
    $Eol = @()
    $Store = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore'
    if (Test-Path $Store) {
        $Users += $((Dir $Store -Ea 0 | Where-Object { $_ -like '*S-1-5-21*' }).PSChildName)
    }
    foreach ($Choice in $RemoveAppx) {
        if ('' -eq $Choice.Trim()) { continue }
        foreach ($Appx in $Provisioned | Where-Object { $_.PackageName -like "*$Choice*" }) {
            $Next = $true
            foreach ($No in $Skip) {
                if ($Appx.PackageName -like "*$No*") { $Next = $false }
            }
            if (-not $Next) { continue }
            $PackageName = $Appx.PackageName
            $PackageFamilyName = ($AppxPackage | Where-Object { $_.Name -eq $Appx.DisplayName }).PackageFamilyName
            New-Item "$Store\Deprovisioned\$PackageFamilyName" -Force | Out-Null
            $PackageFamilyName
            foreach ($Sid in $Users) {
                New-Item "$Store\EndOfLife\$Sid\$PackageName" -Force | Out-Null
            }
            $Eol += $PackageName
            dism /Online /Set-NonRemovableAppPolicy /PackageFamily:$PackageFamilyName /NonRemovable:0 | Out-Null
            Remove-AppxProvisionedPackage -PackageName $PackageName -Online -AllUsers | Out-Null
        }
        foreach ($Appx in $AppxPackage | Where-Object { $_.PackageFullName -like "*$Choice*" }) {
            $Next = $true
            foreach ($No in $Skip) {
                if ($Appx.PackageFullName -like "*$No*") { $Next = $false }
            }
            if (-not $Next) { continue }

            $PackageFullName = $Appx.PackageFullName
            New-Item "$Store\Deprovisioned\$Appx.PackageFamilyName" -Force | Out-Null
            $PackageFullName
            foreach ($Sid in $Users) {
                New-Item "$Store\EndOfLife\$Sid\$PackageFullName" -Force | Out-Null
            }
            $Eol += $PackageFullName
            dism /Online /Set-NonRemovableAppPolicy /PackageFamily:$Appx.PackageFamilyName /NonRemovable:0 | Out-Null
            Remove-AppxPackage -Package $PackageFullName -AllUsers | Out-Null
        }
    }
    return $Eol
}

function Set-WindowsDefenderPolicies {
    Write-Host "Applying Windows Defender policy changes..." -ForegroundColor Cyan

    # Helper to create key if missing
    function Ensure-Key {
        param ([string]$Path)
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
    }

    # Set registry values
    $settings = @{
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowIOAVProtection"                  = @{"value"=0}
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"                                           = @{
            "PUAProtection"=0; "DisableRoutinelyTakingAction"=1; "ServiceKeepAlive"=0;
            "AllowFastServiceStartup"=0; "DisableLocalAdminMerge"=1; "DisableAntiSpyware"=1;
            "RandomizeScheduleTaskTimes"=0
        }
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowArchiveScanning"                 = @{"value"=0}
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowBehaviorMonitoring"              = @{"value"=0}
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowCloudProtection"                 = @{"value"=0}
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowEmailScanning"                   = @{"value"=0}
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowFullScanOnMappedNetworkDrives"    = @{"value"=0}
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowFullScanRemovableDriveScanning"   = @{"value"=0}
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowIntrusionPreventionSystem"        = @{"value"=0}
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowOnAccessProtection"               = @{"value"=0}
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowRealtimeMonitoring"               = @{"value"=0}
        "HKLM:\SOFTWARE\PolicyManager\default\Defender\AllowScanningNetworkFiles"             = @{"value"=0}
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowScriptScanning"                   = @{"value"=1}
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowUserUIAccess"                     = @{"value"=0}
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\AvgCPULoadFactor"                      = @{"value"=50}
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\CheckForSignaturesBeforeRunningScan"   = @{"value"=0}
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\CloudBlockLevel"                       = @{"value"=0}
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\CloudExtendedTimeout"                  = @{"value"=0}
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\DaysToRetainCleanedMalware"             = @{"value"=0}
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\DisableCatchupFullScan"                 = @{"value"=1}
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\DisableCatchupQuickScan"                = @{"value"=1}
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\EnableControlledFolderAccess"          = @{"value"=0}
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\EnableLowCPULoadMode"                  = @{"value"=1}
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\EnableMode"                            = @{"value"=0}
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\ForceDefaultSampleSharing"             = @{"value"=0}
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\HideUserUI"                            = @{"value"=1}
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\PassiveMode"                           = @{"value"=0}
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\PUAProtection"                         = @{"value"=0}
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\RealTimeScanDirection"                 = @{"value"=1}
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\RemediationLevel"                      = @{"value"=0}
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\ReportingLevel"                        = @{"value"=0}
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\ScanAvgCPULoadFactor"                  = @{"value"=50}
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\ScanOnlyIfIdleEnabled"                 = @{"value"=0}
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\ScanRemovableDrivesDuringFullScan"     = @{"value"=0}
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\ScanScheduleDay"                       = @{"value"=0}
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\ScanScheduleQuickScanTime"             = @{"value"='09:00'}
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\ScanScheduleTime"                      = @{"value"='20:00'}
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\SignatureFirstPartyPackageFamilyIdentifiers" = @{"value"=@()}
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\SignatureUpdateFallbackInterval"       = @{"value"=12}
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\SignatureUpdateInterval"               = @{"value"=0}
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\SignatureUpdateOnStartup"              = @{"value"=0}
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\SignatureUpdateTimeout"                = @{"value"=10}
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\SignatureVerification"                 = @{"value"="NotConfigured"}
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\SubmitSamplesConsent"                  = @{"value"=0}
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\ThreatIDBasedProtectionLevel"          = @{"value"=0}
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\ThreatIDDefaultAction"                 = @{"value"='Block'}
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\ThreatIDOnly"                          = @{"value"=1}
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\ThreatIDTimeout"                       = @{"value"=10}
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\ThreatIDUpdateInterval"                = @{"value"=0}
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\ThreatIDUpdates"                       = @{"value"="Disabled"}
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Defender\UseAdvancedProtection"                 = @{"value"=0}
    }

    foreach ($keyPath in $settings.Keys) {
        Ensure-Key -Path $keyPath
        if ($settings[$keyPath].GetType().Name -eq "Hashtable") {
            foreach ($prop in $settings[$keyPath].Keys) {
                Set-ItemProperty -Path $keyPath -Name $prop -Value $settings[$keyPath][$prop] -Type DWord -Force
            }
        } else {
            Set-ItemProperty -Path $keyPath -Name "value" -Value $settings[$keyPath]["value"] -Type DWord -Force
        }
    }

    # Stop and disable services
    $services = @("WdNisSvc", "Sense", "WinDefend", "SecurityHealthService")
    foreach ($service in $services) {
        Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
        Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
    }

    Write-Host "Windows Defender policies applied." -ForegroundColor Green
}

function Remove-DefenderComponents {
    Write-Host "Removing Windows Defender components..." -ForegroundColor Cyan

    # Remove Appx packages
    $removed = Remove-AppxPackages -RemoveAppx @("Microsoft.SecHealthUI", "Microsoft.Windows.SecHealthUI")

    # Remove scheduled tasks
    $tasks = @(
        "\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance",
        "\Microsoft\Windows\Windows Defender\Windows Defender Cleanup",
        "\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan",
        "\Microsoft\Windows\Windows Defender\Windows Defender Verification",
        "\Microsoft\Windows\Windows Defender\Windows Defender Weekly Scheduled Scan",
        "\Microsoft\Windows\SecurityHealth\ScheduleDefScanTask"
    )
    foreach ($task in $tasks) {
        Unregister-ScheduledTask -TaskPath $task -Confirm:$false -ErrorAction SilentlyContinue
    }

    # Remove registry entries for Defender
    $regPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows Defender",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows Defender"
    )
    foreach ($path in $regPaths) {
        if (Test-Path $path) {
            Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    # Use DISM to remove features if possible
    $features = @("Windows-Defender-DefaultDefinitions", "Windows-Defender")
    foreach ($feature in $features) {
        dism /Online /Disable-Feature /FeatureName:$feature /NoRestart | Out-Null
    }

    Write-Host "Defender components removed. Removed Appx packages: $($removed -join ', ')" -ForegroundColor Green
}

# Main execution
Write-Host "Windows Defender Remover v$defenderremoverver" -ForegroundColor Yellow
Write-Host "This script will disable and remove Windows Defender components." -ForegroundColor Yellow

# Run as TrustedInstaller if needed
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Restarting as administrator..." -ForegroundColor Cyan
    RunAsTI -cmd $PSCommandPath
    exit
}

Set-WindowsDefenderPolicies
Remove-DefenderComponents

Write-Host "Process completed. A restart may be required for all changes to take effect." -ForegroundColor Green
