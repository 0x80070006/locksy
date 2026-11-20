# Locksy - HTTPS local : approuve le certificat racine de Caddy (port 443 : option -PareFeu).
# Usage : clic droit > "Executer avec PowerShell" (l'elevation administrateur est demandee).
# Options : -Cert <chemin> pour un autre fichier ; -PareFeu pour ouvrir aussi le port 443.
param(
    [string]$Cert = (Join-Path $PSScriptRoot "..\caddy-root.crt"),
    [switch]$PareFeu
)

$ErrorActionPreference = "Stop"

# Relance en administrateur si besoin.
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    $args = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Cert `"$Cert`""
    if ($PareFeu) { $args += " -PareFeu" }
    Start-Process powershell -Verb RunAs -ArgumentList $args
    exit
}

try {
    $Cert = (Resolve-Path $Cert).Path
    Write-Host "Certificat : $Cert"

    # 1. Certificat racine de confiance (machine)
    $c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($Cert)
    $deja = Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Thumbprint -eq $c.Thumbprint }
    if ($deja) {
        Write-Host "Certificat deja approuve ($($c.Subject))."
    } else {
        Import-Certificate -FilePath $Cert -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
        Write-Host "Certificat approuve : $($c.Subject)"
    }

    # 2. Pare-feu : port 443 en entree (reseaux prive et domaine)
    if ($PareFeu) {
        $nom = "Locksy HTTPS 443"
        if (Get-NetFirewallRule -DisplayName $nom -ErrorAction SilentlyContinue) {
            Write-Host "Regle pare-feu deja presente."
        } else {
            New-NetFirewallRule -DisplayName $nom -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow -Profile Private,Domain | Out-Null
            Write-Host "Regle pare-feu creee : $nom"
        }
    }

    Write-Host ""
    Write-Host "Termine. Redemarrez le navigateur, puis saisissez https://10.20.2.134 dans l'extension."
} catch {
    Write-Host "Erreur : $($_.Exception.Message)" -ForegroundColor Red
}
Read-Host "Appuyez sur Entree pour fermer"
