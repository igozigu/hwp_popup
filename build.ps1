$ErrorActionPreference = "Stop"

$csc = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
$wpfDir = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\WPF"
$src = Join-Path $PSScriptRoot "Program.cs"
$dll = Join-Path $PSScriptRoot "FilePathCheckerModuleExample.dll"
$outExe = Join-Path $PSScriptRoot "hwp_popup.exe"

if (-not (Test-Path $csc)) {
    throw "csc.exe not found at $csc"
}
if (-not (Test-Path $dll)) {
    throw "Embedded resource DLL not found at $dll"
}

& $csc `
    /nologo `
    /target:exe `
    /optimize+ `
    /platform:anycpu `
    /out:$outExe `
    /resource:"$dll,FilePathCheckerModuleExample.dll" `
    /reference:"System.dll" `
    /reference:"System.Core.dll" `
    /reference:"System.Drawing.dll" `
    /reference:"System.Management.dll" `
    /reference:"System.Windows.Forms.dll" `
    /reference:"Microsoft.CSharp.dll" `
    /reference:"$wpfDir\UIAutomationClient.dll" `
    /reference:"$wpfDir\UIAutomationTypes.dll" `
    $src

if ($LASTEXITCODE -ne 0) {
    throw "Compilation failed with exit code $LASTEXITCODE"
}

$item = Get-Item $outExe
Write-Host "[BUILD SUCCESS] $($item.FullName) ($($item.Length) bytes)"
