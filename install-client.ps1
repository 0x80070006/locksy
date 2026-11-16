# Installe le client de bureau Locksy pour l'utilisateur courant (sans droits administrateur).
# Placez ce script à côté de locksy-windows-x64.exe (fichiers de la version), puis :
#   powershell -ExecutionPolicy Bypass -File install-client.ps1 [-Server https://locksy.corp.local]
param([string]$Server = "")
$ErrorActionPreference = "Stop"
$source = @("locksy-windows-x64.exe", "dist\locksy.exe") |
  ForEach-Object { Join-Path $PSScriptRoot $_ } | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $source) { throw "locksy-windows-x64.exe introuvable à côté de ce script." }

$dest = Join-Path $env:LOCALAPPDATA "Programs\Locksy"
New-Item -ItemType Directory -Force $dest | Out-Null
$running = Get-Process -Name "locksy" -ErrorAction SilentlyContinue
if ($running) {
  $running | Stop-Process -Force
  $running | Wait-Process -Timeout 10 -ErrorAction SilentlyContinue
}
Copy-Item $source (Join-Path $dest "locksy.exe") -Force
Unblock-File (Join-Path $dest "locksy.exe")

$shell = New-Object -ComObject WScript.Shell
$targets = @(
  (Join-Path ([Environment]::GetFolderPath("Programs")) "Locksy.lnk"),
  (Join-Path ([Environment]::GetFolderPath("Desktop")) "Locksy.lnk")
)
foreach ($lnk in $targets) {
  $s = $shell.CreateShortcut($lnk)
  $s.TargetPath = Join-Path $dest "locksy.exe"
  $s.WorkingDirectory = $dest
  $s.Description = "Locksy - gestionnaire de mots de passe"
  $s.Save()
}
if ($Server) {
  # Adresse du serveur pré-remplie pour cet utilisateur.
  $cfgDir = Join-Path $env:APPDATA "Locksy"
  New-Item -ItemType Directory -Force $cfgDir | Out-Null
  $cfg = Join-Path $cfgDir "bureau.json"
  $json = if (Test-Path $cfg) { Get-Content $cfg -Raw | ConvertFrom-Json } else { [pscustomobject]@{} }
  $json | Add-Member -NotePropertyName server_url -NotePropertyValue $Server -Force
  [IO.File]::WriteAllText($cfg, ($json | ConvertTo-Json), (New-Object Text.UTF8Encoding $false))
}
Write-Output "Locksy installé dans $dest (raccourcis menu Démarrer et Bureau)."
