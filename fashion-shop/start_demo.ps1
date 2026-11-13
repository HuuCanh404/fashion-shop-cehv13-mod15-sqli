$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot
$PhpExe = (Get-Command php -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source)
if (-not $PhpExe) {
    $Candidate = Get-ChildItem "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\PHP.PHP.*\php.exe" -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
    if ($Candidate) { $PhpExe = $Candidate }
}
if (-not $PhpExe) {
    Write-Error "Khong tim thay php.exe trong PATH. Hay cai PHP 8.2+ hoac XAMPP truoc khi chay."
}
Write-Host "Khoi dong Fashion-Shop tai http://127.0.0.1:8080/shopweb/ ..."
Write-Host "Admin Security Dashboard: http://127.0.0.1:8080/shopweb/quantri/security_dashboard.php"
& $PhpExe -S 127.0.0.1:8080 -t "$RepoRoot\fashion-shop" "$RepoRoot\fashion-shop\router.php"
