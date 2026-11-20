<#
.SYNOPSIS
  Installe le client de bureau Locksy (Windows).

.DESCRIPTION
  Placez ce script à côté de locksy-windows-x64.exe et du fichier SHA256SUMS de
  la version, puis lancez-le :

    powershell -NoProfile -File .\install-client.ps1 [-Server https://locksy.corp.local]

  - En administrateur (et sans -CurrentUser) : installation pour tout le poste
    dans "Program Files\Locksy", raccourcis communs. Avec -Server, l'adresse
    est imposée par C:\ProgramData\Locksy\bureau.json (dossier protégé :
    SYSTEM et Administrateurs en contrôle total, Utilisateurs en lecture).
  - Sans droits administrateur (ou avec -CurrentUser) : installation pour
    l'utilisateur courant dans %LOCALAPPDATA%\Programs\Locksy ; -Server
    pré-remplit seulement l'adresse dans ses préférences.

  L'empreinte SHA-256 de l'exécutable est vérifiée AVANT la copie, puis de
  nouveau sur le fichier copié. Elle est lue dans -Sha256, sinon dans la ligne
  "locksy-windows-x64.exe" du fichier SHA256SUMS posé à côté du script. Sans
  empreinte, l'installation est refusée (sauf -SkipHashCheck, déconseillé).

  Ne contournez pas la stratégie d'exécution (pas de -ExecutionPolicy Bypass) :
  si elle bloque ce script, signez-le avec le certificat de code de
  l'entreprise, ou déployez-le par GPO ou Intune.

.PARAMETER Server
  Adresse du serveur Locksy (https://…, ou http://localhost pour ce poste).
.PARAMETER CurrentUser
  Force l'installation pour l'utilisateur courant, même en administrateur.
.PARAMETER Sha256
  Empreinte SHA-256 attendue de locksy-windows-x64.exe (64 caractères hexadécimaux).
.PARAMETER SkipHashCheck
  Installe sans vérifier l'empreinte (déconseillé).
.PARAMETER NoDesktopShortcut
  Ne crée pas de raccourci sur le Bureau.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
  [string]$Server = "",
  [switch]$CurrentUser,
  [string]$Sha256 = "",
  [switch]$SkipHashCheck,
  [switch]$NoDesktopShortcut
)
$ErrorActionPreference = "Stop"
Set-StrictMode -Version 3

$exeName = "locksy-windows-x64.exe"
$source = @($exeName, "dist\locksy.exe") |
  ForEach-Object { Join-Path $PSScriptRoot $_ } |
  Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
  Select-Object -First 1
if (-not $source) { throw "$exeName introuvable à côté de ce script." }

$Server = $Server.Trim().TrimEnd("/")
if ($Server -and $Server -notmatch '^(https://[^/\s]+|http://(localhost|127\.0\.0\.1|\[::1\])(:\d+)?)(/\S*)?$') {
  throw "Adresse de serveur refusée : utilisez https://… (ou http://localhost pour ce poste)."
}

# ---------------------------------------------------------------- Empreinte

function Get-ExpectedHash {
  if ($Sha256) {
    $h = $Sha256.Trim()
    if ($h -notmatch '^[0-9a-fA-F]{64}$') { throw "-Sha256 doit contenir 64 caractères hexadécimaux." }
    return $h
  }
  $sums = Join-Path $PSScriptRoot "SHA256SUMS"
  if (Test-Path -LiteralPath $sums -PathType Leaf) {
    foreach ($line in Get-Content -LiteralPath $sums) {
      # Format sha256sum : "<hex>  <nom>" (ou "<hex> *<nom>" en mode binaire).
      if ($line -match '^\s*([0-9a-fA-F]{64})\s+\*?(.+?)\s*$' -and $Matches[2] -eq $exeName) {
        return $Matches[1]
      }
    }
  }
  return $null
}

function Assert-Hash([string]$Path, [string]$Expected) {
  # Même calcul que Get-FileHash -Algorithm SHA256, mais qui a lieu aussi avec
  # -WhatIf (Get-FileHash, en 5.1, n'en renvoie alors aucun).
  $sha = [Security.Cryptography.SHA256]::Create()
  $stream = [IO.File]::OpenRead($Path)
  try { $actual = [BitConverter]::ToString($sha.ComputeHash($stream)).Replace("-", "") }
  finally { $stream.Dispose(); $sha.Dispose() }
  if (-not [string]::Equals($actual, $Expected, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Empreinte SHA-256 incorrecte pour $Path : attendue $Expected, obtenue $actual. Installation interrompue."
  }
}

$expected = Get-ExpectedHash
if ($expected) {
  Assert-Hash $source $expected
  Write-Verbose "Empreinte vérifiée : $expected"
} elseif ($SkipHashCheck) {
  Write-Warning "Empreinte SHA-256 non vérifiée (-SkipHashCheck) : assurez-vous de la provenance de $source."
} else {
  throw "Aucune empreinte disponible : fournissez -Sha256 ou placez SHA256SUMS à côté du script (ou, en connaissance de cause, -SkipHashCheck)."
}

# ---------------------------------------------------------------- Emplacements

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$machine = $isAdmin -and -not $CurrentUser

if ($machine) {
  $dest = Join-Path $env:ProgramFiles "Locksy"
  $programs = [Environment]::GetFolderPath("CommonPrograms")
  $desktop = [Environment]::GetFolderPath("CommonDesktopDirectory")
} else {
  $dest = Join-Path $env:LOCALAPPDATA "Programs\Locksy"
  $programs = [Environment]::GetFolderPath("Programs")
  $desktop = [Environment]::GetFolderPath("Desktop")
}
$target = Join-Path $dest "locksy.exe"

# ---------------------------------------------------------------- Copie

if ($PSCmdlet.ShouldProcess($target, "Installer Locksy")) {
  New-Item -ItemType Directory -Force -Path $dest | Out-Null
  # Seuls les processus qui exécutent l'exécutable cible sont arrêtés (le
  # chemin des processus des autres sessions est illisible sans droits).
  $running = @(Get-Process -Name "locksy" -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -and [string]::Equals($_.Path, $target, [StringComparison]::OrdinalIgnoreCase) })
  if ($running.Count -gt 0) {
    $running | Stop-Process -Force
    $running | Wait-Process -Timeout 10 -ErrorAction SilentlyContinue
  }
  # Windows libère le fichier un instant après la fermeture du client : quelques essais.
  for ($i = 1; $i -le 20; $i++) {
    try { Copy-Item -LiteralPath $source -Destination $target -Force -ErrorAction Stop; break }
    catch {
      if ($i -eq 20) { throw "Locksy est encore ouvert : fermez-le puis relancez ce script." }
      Start-Sleep -Milliseconds 500
    }
  }
  if ($expected) {
    try { Assert-Hash $target $expected }
    catch {
      Remove-Item -LiteralPath $target -Force -ErrorAction SilentlyContinue
      throw
    }
  }
}

# ---------------------------------------------------------------- Raccourcis

$links = @(Join-Path $programs "Locksy.lnk")
if (-not $NoDesktopShortcut) { $links += Join-Path $desktop "Locksy.lnk" }
$shell = New-Object -ComObject WScript.Shell
foreach ($lnk in $links) {
  if ($PSCmdlet.ShouldProcess($lnk, "Créer le raccourci")) {
    $s = $shell.CreateShortcut($lnk)
    $s.TargetPath = $target
    $s.WorkingDirectory = $dest
    $s.Description = "Locksy - gestionnaire de mots de passe"
    $s.Save()
  }
}

# ---------------------------------------------------------------- Serveur

function Write-JsonSetting([string]$Path, [string]$Key, [string]$Value) {
  $json = [pscustomobject]@{}
  if (Test-Path -LiteralPath $Path -PathType Leaf) {
    try { $json = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json } catch { $json = [pscustomobject]@{} }
  }
  $json | Add-Member -NotePropertyName $Key -NotePropertyValue $Value -Force
  [IO.File]::WriteAllText($Path, ($json | ConvertTo-Json), (New-Object Text.UTF8Encoding $false))
}

if ($Server -and $machine) {
  # Adresse imposée à tout le poste : dossier en lecture seule pour les utilisateurs.
  $cfgDir = Join-Path $env:ProgramData "Locksy"
  if ($PSCmdlet.ShouldProcess($cfgDir, "Imposer le serveur $Server")) {
    New-Item -ItemType Directory -Force -Path $cfgDir | Out-Null
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false) # héritage coupé
    $inherit = [Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
    $none = [Security.AccessControl.PropagationFlags]::None
    # SID plutôt que noms : indépendant de la langue de Windows.
    $rules = @(
      @("S-1-5-18", "FullControl"),      # SYSTEM
      @("S-1-5-32-544", "FullControl"),  # Administrateurs
      @("S-1-5-32-545", "ReadAndExecute") # Utilisateurs
    )
    foreach ($r in $rules) {
      $sid = New-Object Security.Principal.SecurityIdentifier($r[0])
      $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid, $r[1], $inherit, $none, "Allow")))
    }
    Set-Acl -LiteralPath $cfgDir -AclObject $acl
    Write-JsonSetting (Join-Path $cfgDir "bureau.json") "server_url" $Server
  }
} elseif ($Server) {
  # Adresse pré-remplie pour cet utilisateur (modifiable dans le client).
  $cfgDir = Join-Path $env:APPDATA "Locksy"
  if ($PSCmdlet.ShouldProcess($cfgDir, "Pré-remplir le serveur $Server")) {
    New-Item -ItemType Directory -Force -Path $cfgDir | Out-Null
    Write-JsonSetting (Join-Path $cfgDir "bureau.json") "server_url" $Server
  }
}

$scope = if ($machine) { "pour tous les utilisateurs du poste" } else { "pour l'utilisateur courant" }
Write-Output "Locksy installé $scope dans $dest."
if ($Server -and $machine) { Write-Output "Serveur imposé : $Server (C:\ProgramData\Locksy\bureau.json)." }
