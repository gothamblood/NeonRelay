<#
  NeonRelay — désinstallation du client Windows.
  Lancer : double-clic sur uninstall.cmd
  Supprime %LOCALAPPDATA%\NeonRelay et retire son dossier bin du PATH utilisateur.
#>
$ErrorActionPreference = 'Stop'

$Dest = Join-Path $env:LOCALAPPDATA 'NeonRelay'
$Bin  = Join-Path $Dest 'bin'

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($userPath) {
  $kept = ($userPath -split ';') | Where-Object { $_ -and $_ -ne $Bin }
  [Environment]::SetEnvironmentVariable('Path', ($kept -join ';'), 'User')
}

if (Test-Path -LiteralPath $Dest) { Remove-Item -LiteralPath $Dest -Recurse -Force }
Write-Host 'Client NeonRelay désinstallé.'
