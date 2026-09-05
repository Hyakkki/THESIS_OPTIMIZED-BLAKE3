param([string]$Python = "python")

$ErrorActionPreference = "Stop"
$moduleDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $moduleDirectory
try {
    & $Python -m pip install -r requirements.txt "pyinstaller==6.22.2"
    if ($LASTEXITCODE -ne 0) { throw "Dependency installation failed." }
    & $Python -m PyInstaller --noconfirm --clean --onefile `
        --name optimized_blake3_hasher --collect-all blake3 optimized_blake3.py
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller build failed." }
    $builtExecutable = Join-Path $moduleDirectory "dist\optimized_blake3_hasher.exe"
    if (-not (Test-Path -LiteralPath $builtExecutable)) {
        throw "Expected executable was not produced: $builtExecutable"
    }
    Write-Host "Built: $builtExecutable"
    Write-Host "Validate it before replacing the packaged engine:"
    Write-Host "  & '$builtExecutable' --self-test"
}
finally { Pop-Location }
