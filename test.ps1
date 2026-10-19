$ErrorActionPreference = "Stop"
$csc = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
$wpfDir = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\WPF"
$testExe = Join-Path $env:TEMP ("AsideHwpGuard-policy-tests-" + [Guid]::NewGuid().ToString("N") + ".exe")
try {
    & $csc /nologo /target:exe /optimize+ /platform:anycpu `
        /main:AsideHwpGuard.RegistrationPolicyTests /out:$testExe `
        /reference:"System.dll" /reference:"System.Core.dll" /reference:"System.Drawing.dll" `
        /reference:"System.Management.dll" /reference:"System.Windows.Forms.dll" /reference:"Microsoft.CSharp.dll" `
        /reference:"$wpfDir\UIAutomationClient.dll" /reference:"$wpfDir\UIAutomationTypes.dll" `
        (Join-Path $PSScriptRoot "Program.cs") (Join-Path $PSScriptRoot "RegistrationPolicyTests.cs")
    if ($LASTEXITCODE -ne 0) { throw "Test compilation failed: $LASTEXITCODE" }
    & $testExe
    if ($LASTEXITCODE -ne 0) { throw "Registration policy regression tests failed: $LASTEXITCODE" }
}
finally {
    if (Test-Path -LiteralPath $testExe) { Remove-Item -LiteralPath $testExe -Force }
}
