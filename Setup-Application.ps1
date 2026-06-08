#Requires -Version 5.1
<#
.SYNOPSIS
    First-time setup wizard for PixSmith Authorization Server.

.DESCRIPTION
    Configures application settings, writes secrets, and prepares the initial
    admin user that is created on the first application startup.

    Run from the solution root directory.

.PARAMETER ConfigFile
    Path to a JSON settings file (see setup.example.json for the format).
    Interactive prompts are skipped for any value present in the file.

.PARAMETER Environment
    Target environment: Development (default) or Production.
    In Development, secrets go to dotnet user-secrets.
    In Production, secrets go to .env.production (gitignored).

.EXAMPLE
    # Fully interactive
    .\Setup-Application.ps1

    # Pre-filled from a config file
    .\Setup-Application.ps1 -ConfigFile .\setup.json

    # Production target
    .\Setup-Application.ps1 -ConfigFile .\setup.json -Environment Production
#>
[CmdletBinding()]
param(
    [string]$ConfigFile   = "",
    [string]$Environment  = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Root    = $PSScriptRoot
$ApiDir  = Join-Path $Root "src\AuthServer\AuthServer.API"
$ApiProj = Join-Path $ApiDir "PixSmith.Authorization.API.csproj"

# ─── Console helpers ────────────────────────────────────────────────────────────

function Write-Banner {
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║     PixSmith Authorization Server — First-Time Setup     ║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Section([string]$label) {
    Write-Host ""
    Write-Host "  ── $label " -ForegroundColor Yellow -NoNewline
    $pad = [Math]::Max(0, 54 - $label.Length)
    Write-Host ("─" * $pad) -ForegroundColor DarkGray
}

function Write-Ok([string]$msg)   { Write-Host "  ✓  $msg" -ForegroundColor Green }
function Write-Warn([string]$msg) { Write-Host "  ⚠  $msg" -ForegroundColor Yellow }
function Write-Note([string]$msg) { Write-Host "     $msg" -ForegroundColor DarkGray }

function Stop-Setup([string]$msg) {
    Write-Host "  ✗  $msg" -ForegroundColor Red
    exit 1
}

# ─── Input helpers ──────────────────────────────────────────────────────────────

function Prompt-Value([string]$label, [string]$default = "", [switch]$Required) {
    $hint = if ($default) { " [$default]" } else { "" }
    Write-Host "     $label$hint`: " -ForegroundColor White -NoNewline
    $val = Read-Host
    if ([string]::IsNullOrWhiteSpace($val)) { $val = $default }
    if ($Required -and [string]::IsNullOrWhiteSpace($val)) {
        Write-Host "     This field is required." -ForegroundColor Red
        return Prompt-Value $label $default -Required:$Required
    }
    return $val.Trim()
}

function Prompt-Secret([string]$label) {
    Write-Host "     $label`: " -ForegroundColor White -NoNewline
    return [System.Net.NetworkCredential]::new("", (Read-Host -AsSecureString)).Password
}

function Prompt-Choice([string]$label, [string[]]$choices, [string]$default) {
    $display = ($choices | ForEach-Object { if ($_ -eq $default) { "[$_]" } else { $_ } }) -join " / "
    Write-Host "     $label ($display)`: " -ForegroundColor White -NoNewline
    $val = Read-Host
    if ([string]::IsNullOrWhiteSpace($val)) { return $default }
    $match = $choices | Where-Object { $_ -ieq $val } | Select-Object -First 1
    if (-not $match) {
        Write-Host "     Please choose: $($choices -join ' / ')" -ForegroundColor Red
        return Prompt-Choice $label $choices $default
    }
    return $match
}

# ─── Config file ────────────────────────────────────────────────────────────────

function Import-Config([string]$path) {
    if (-not (Test-Path $path)) { Stop-Setup "Config file not found: $path" }
    try   { return Get-Content $path -Raw | ConvertFrom-Json }
    catch { Stop-Setup "Could not parse config file: $_" }
}

function Get-Cfg($obj, [string]$key, [string]$fallback = "") {
    $val = $obj.$key
    if ($null -eq $val -or [string]::IsNullOrWhiteSpace("$val")) { return $fallback }
    return "$val".Trim()
}

# ─── Validation ──────────────────────────────────────────────────────────────────

function Test-Password([string]$pwd) {
    # Mirrors the default Identity policy in appsettings.json
    $pwd.Length -ge 8 -and
    $pwd -cmatch '[A-Z]' -and
    $pwd -match  '[0-9]' -and
    $pwd -match  '[^a-zA-Z0-9]'
}

# ─── Settings collection ─────────────────────────────────────────────────────────

function Collect-Settings([string]$env, $cfg) {
    $s = @{}
    $s.Environment = $env

    # ── Application URL ──────────────────────────────────────────────────────
    Write-Section "Application URL"
    $defaultUri = if ($env -eq "Production") { "https://yourdomain.com" } else { "https://localhost:7100" }
    $s.BaseUri = Prompt-Value "Base URI where the app is hosted" (Get-Cfg $cfg "BaseUri" $defaultUri) -Required

    # ── Database ─────────────────────────────────────────────────────────────
    Write-Section "Database"
    $s.DatabaseProvider = Prompt-Choice "Database provider" @("Sqlite", "Postgres") (Get-Cfg $cfg "DatabaseProvider" "Sqlite")
    $defaultConn = switch ($s.DatabaseProvider) {
        "Postgres" { "Host=localhost;Database=pixsmith_auth;Username=postgres;Password=postgres" }
        default    { if ($env -eq "Production") { "Data Source=/app/data/auth.db" } else { "Data Source=auth.db" } }
    }
    $s.ConnectionString = Prompt-Value "Connection string" (Get-Cfg $cfg "ConnectionString" $defaultConn) -Required
    if ($env -eq "Production") {
        $s.DataProtectionPath = Prompt-Value "Data-protection key path" (Get-Cfg $cfg "DataProtectionPath" "/app/data/keys")
    } else {
        $s.DataProtectionPath = Get-Cfg $cfg "DataProtectionPath" ""
    }

    # ── Client IDs ───────────────────────────────────────────────────────────
    Write-Section "OIDC Client IDs"
    $s.BlazorClientId = Prompt-Value "Blazor client ID" (Get-Cfg $cfg "BlazorClientId" "blazor-client") -Required
    $s.M2MClientId    = Prompt-Value "M2M client ID"    (Get-Cfg $cfg "M2MClientId"    "m2m-client")    -Required

    # ── M2M Secret ───────────────────────────────────────────────────────────
    Write-Section "M2M Client Secret"
    $fromCfg = Get-Cfg $cfg "M2MClientSecret" ""
    if ($fromCfg) {
        Write-Note "Using M2M secret from config file."
        $s.M2MClientSecret = $fromCfg
    } else {
        $auto = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
        Write-Note "Auto-generated secret (copy this now if you need it elsewhere):"
        Write-Host "     $auto" -ForegroundColor Cyan
        Write-Host "     Press Enter to use it, or type a custom value: " -ForegroundColor White -NoNewline
        $typed = Read-Host
        $s.M2MClientSecret = if ([string]::IsNullOrWhiteSpace($typed)) { $auto } else { $typed.Trim() }
    }

    # ── Initial Admin Account ────────────────────────────────────────────────
    Write-Section "Initial Admin Account"
    $s.AdminEmail = Prompt-Value "Admin email address" (Get-Cfg $cfg "AdminEmail" "") -Required
    $defaultUser  = if ($s.AdminEmail -match "@") { $s.AdminEmail.Split("@")[0] } else { "admin" }
    $s.AdminUsername = Prompt-Value "Admin username" (Get-Cfg $cfg "AdminUsername" $defaultUser) -Required

    $fromCfgPwd = Get-Cfg $cfg "AdminPassword" ""
    if ($fromCfgPwd -and (Test-Password $fromCfgPwd)) {
        $s.AdminPassword = $fromCfgPwd
        Write-Note "Admin password loaded from config file."
    } else {
        if ($fromCfgPwd) {
            Write-Warn "Config password doesn't meet the policy (8+ chars, uppercase, digit, special) — it would silently fail to seed. Enter a replacement."
        }
        do {
            $s.AdminPassword = Prompt-Secret "Admin password (8+ chars, uppercase, digit, special char)"
            if (-not (Test-Password $s.AdminPassword)) {
                Write-Warn "Password must be 8+ characters and include uppercase, a digit, and a special character."
            }
        } while (-not (Test-Password $s.AdminPassword))
    }

    # ── External OAuth Providers ─────────────────────────────────────────────
    Write-Section "External OAuth Providers  (optional — press Enter to skip each)"
    $s.GoogleClientId        = Prompt-Value "Google Client ID"         (Get-Cfg $cfg "GoogleClientId")
    $s.GoogleClientSecret    = Prompt-Value "Google Client Secret"     (Get-Cfg $cfg "GoogleClientSecret")
    $s.MicrosoftClientId     = Prompt-Value "Microsoft Client ID"      (Get-Cfg $cfg "MicrosoftClientId")
    $s.MicrosoftClientSecret = Prompt-Value "Microsoft Client Secret"  (Get-Cfg $cfg "MicrosoftClientSecret")

    return $s
}

# ─── appsettings builder ─────────────────────────────────────────────────────────

function Build-AppSettings($s) {
    # Only non-sensitive settings go here.
    # Secrets (M2M secret, admin password, OAuth keys) go to user-secrets / env vars.
    $doc = [ordered]@{
        Database = [ordered]@{
            Provider = $s.DatabaseProvider
        }
        ConnectionStrings = [ordered]@{
            DefaultConnection = $s.ConnectionString
        }
        OpenIddict = [ordered]@{
            BlazorClient = [ordered]@{
                ClientId = $s.BlazorClientId
                BaseUri  = $s.BaseUri
            }
            M2MClient = [ordered]@{
                ClientId = $s.M2MClientId
            }
        }
    }
    if ($s.DataProtectionPath) {
        $doc.DataProtection = [ordered]@{ KeyPath = $s.DataProtectionPath }
    }
    return $doc | ConvertTo-Json -Depth 10
}

# ─── Secrets (Development) ───────────────────────────────────────────────────────

function Set-UserSecrets($s) {
    $secrets = [ordered]@{
        "OpenIddict:M2MClient:ClientSecret" = $s.M2MClientSecret
        "AdminSeed:Email"                   = $s.AdminEmail
        "AdminSeed:Username"                = $s.AdminUsername
        "AdminSeed:Password"                = $s.AdminPassword
    }
    if ($s.GoogleClientId)        { $secrets["Authentication:Google:ClientId"]       = $s.GoogleClientId }
    if ($s.GoogleClientSecret)    { $secrets["Authentication:Google:ClientSecret"]   = $s.GoogleClientSecret }
    if ($s.MicrosoftClientId)     { $secrets["Authentication:Microsoft:ClientId"]    = $s.MicrosoftClientId }
    if ($s.MicrosoftClientSecret) { $secrets["Authentication:Microsoft:ClientSecret"] = $s.MicrosoftClientSecret }

    foreach ($kv in $secrets.GetEnumerator()) {
        & dotnet user-secrets set "$($kv.Key)" "$($kv.Value)" --project "$ApiProj" | Out-Null
        if ($LASTEXITCODE -ne 0) { Write-Warn "Could not write secret: $($kv.Key)" }
        else                     { Write-Ok   "user-secret: $($kv.Key)" }
    }
}

# ─── Secrets (Production) ────────────────────────────────────────────────────────

function Write-EnvFile($s) {
    $dest = Join-Path $Root ".env.production"

    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add("# PixSmith Authorization Server — Production Environment Variables")
    $lines.Add("# Load these into your container / host before starting the application.")
    $lines.Add("# This file is gitignored. Never commit real secrets.")
    $lines.Add("")
    $lines.Add("# M2M client secret")
    $lines.Add("OpenIddict__M2MClient__ClientSecret=$($s.M2MClientSecret)")
    $lines.Add("")
    $lines.Add("# Initial admin account — REMOVE these env vars after the first successful startup.")
    $lines.Add("AdminSeed__Email=$($s.AdminEmail)")
    $lines.Add("AdminSeed__Username=$($s.AdminUsername)")
    $lines.Add("AdminSeed__Password=<enter-your-admin-password-here>")

    if ($s.GoogleClientId)        { $lines.Add("Authentication__Google__ClientId=$($s.GoogleClientId)") }
    if ($s.GoogleClientSecret)    { $lines.Add("Authentication__Google__ClientSecret=$($s.GoogleClientSecret)") }
    if ($s.MicrosoftClientId)     { $lines.Add("Authentication__Microsoft__ClientId=$($s.MicrosoftClientId)") }
    if ($s.MicrosoftClientSecret) { $lines.Add("Authentication__Microsoft__ClientSecret=$($s.MicrosoftClientSecret)") }

    $lines.Add("")
    $lines.Add("# Docker Compose usage:")
    $lines.Add("#   env_file: [ .env.production ]")
    $lines.Add("# Kubernetes:")
    $lines.Add("#   kubectl create secret generic pixsmith-secrets --from-env-file=.env.production")

    ($lines -join "`n") | Out-File -FilePath $dest -Encoding utf8 -NoNewline
    Write-Ok ".env.production written (gitignored)"
    Write-Warn "Edit .env.production and set AdminSeed__Password before starting the app."
}

# ─── .gitignore update (idempotent) ─────────────────────────────────────────────

function Update-Gitignore {
    $gitignorePath = Join-Path $Root ".gitignore"
    if (-not (Test-Path $gitignorePath)) { return }

    $existing = Get-Content $gitignorePath
    $toAdd    = @("setup.json", ".env.production", ".env.*") | Where-Object { $existing -notcontains $_ }

    if ($toAdd.Count -gt 0) {
        $block = "`n# Setup script outputs`n" + ($toAdd -join "`n") + "`n"
        [System.IO.File]::AppendAllText($gitignorePath, $block)
        Write-Ok ".gitignore updated ($($toAdd -join ', '))"
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
#  Main
# ═══════════════════════════════════════════════════════════════════════════════

Write-Banner

# ── Prerequisites ────────────────────────────────────────────────────────────
Write-Section "Prerequisites"

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    Stop-Setup ".NET SDK not found. Install from https://dotnet.microsoft.com/download"
}
$sdkVersion = & dotnet --version 2>&1
Write-Ok ".NET SDK $sdkVersion"

if (-not (Test-Path $ApiProj)) {
    Stop-Setup "API project not found at $ApiProj — run this script from the solution root."
}
Write-Ok "Solution root verified"

# ── Environment ──────────────────────────────────────────────────────────────
if ([string]::IsNullOrEmpty($Environment)) {
    Write-Host ""
    $Environment = Prompt-Choice "Target environment" @("Development", "Production") "Development"
}
if ($Environment -notin @("Development", "Production")) {
    Stop-Setup "Invalid environment '$Environment'. Must be Development or Production."
}

# ── Config file ──────────────────────────────────────────────────────────────
$cfg = [PSCustomObject]@{}
if ($ConfigFile) {
    $cfg = Import-Config $ConfigFile
    Write-Ok "Loaded: $ConfigFile"
    $envFromFile = Get-Cfg $cfg "Environment" ""
    if ($envFromFile -and -not $PSBoundParameters.ContainsKey("Environment")) {
        $Environment = $envFromFile
    }
}

# ── Collect settings ─────────────────────────────────────────────────────────
$settings = Collect-Settings $Environment $cfg

# ── Write appsettings.{env}.json ─────────────────────────────────────────────
Write-Section "Writing appsettings.$Environment.json"
$targetFile = Join-Path $ApiDir "appsettings.$Environment.json"
if (Test-Path $targetFile) {
    Write-Warn "Overwriting existing file."
}
Build-AppSettings $settings | Out-File -FilePath $targetFile -Encoding utf8
Write-Ok "appsettings.$Environment.json written"

# ── Write secrets ────────────────────────────────────────────────────────────
Write-Section "Writing Secrets"
if ($Environment -eq "Development") {
    Set-UserSecrets $settings
} else {
    Write-EnvFile $settings
}

# ── Update .gitignore ────────────────────────────────────────────────────────
Update-Gitignore

# ── Summary ──────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "  ║                    Setup complete!                       ║" -ForegroundColor Green
Write-Host "  ╚══════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Ok "Environment : $($settings.Environment)"
Write-Ok "Base URI    : $($settings.BaseUri)"
Write-Ok "Admin email : $($settings.AdminEmail)"
Write-Host ""
Write-Host "  Next steps:" -ForegroundColor Yellow

if ($Environment -eq "Development") {
    Write-Host "  1. Start the application:" -ForegroundColor White
    Write-Host "       dotnet run --project src/AuthServer/AuthServer.API" -ForegroundColor Cyan
    Write-Host "  2. Open $($settings.BaseUri) and sign in as the admin." -ForegroundColor White
    Write-Host "  3. Go to Profile and change the admin password after first login." -ForegroundColor White
} else {
    Write-Host "  1. Open .env.production and set AdminSeed__Password." -ForegroundColor White
    Write-Host "  2. Load the env vars in your container or host." -ForegroundColor White
    Write-Host "  3. Start the application — the admin user is created on first boot." -ForegroundColor White
    Write-Host "  4. After first boot, remove the AdminSeed__* env vars." -ForegroundColor White
    Write-Host "  5. For Docker Compose, add:  env_file: [ .env.production ]" -ForegroundColor White
}

Write-Host ""
