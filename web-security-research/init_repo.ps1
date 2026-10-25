# PowerShell Helper Script to Initialize Git Repository and Push to GitHub
param (
    [string]$RemoteUrl = ""
)

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "WEB SECURITY RESEARCH: GITHUB REPOSITORY INITIALIZATION HELPER" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

# Check if git is available
$gitCmd = Get-Command git -ErrorAction SilentlyContinue
if (-not $gitCmd) {
    Write-Host "[!] Git is not currently installed or not in your system PATH." -ForegroundColor Yellow
    Write-Host "[*] To install Git on Windows:" -ForegroundColor Green
    Write-Host "    1. Download from: https://git-scm.com/download/win"
    Write-Host "    2. Or install via winget: winget install --id Git.Git -e --source winget"
    Write-Host "    3. Or use GitHub Desktop: https://desktop.github.com/"
    exit 1
}

Write-Host "[+] Git executable detected: $($gitCmd.Source)" -ForegroundColor Green

# Initialize repository if not already initialized
if (-not (Test-Path ".git")) {
    Write-Host "[*] Initializing local git repository..."
    git init
    git branch -M main
}

# Stage files
Write-Host "[*] Staging all research deliverables and lab files..."
git add .

# Check status
git status -s

# Commit
$commitMsg = "feat: complete web security research deliverables, technical brief, risk matrix, lab, and formal report"
Write-Host "[*] Creating initial commit..."
git commit -m $commitMsg

# Add remote if provided
if ($RemoteUrl -ne "") {
    Write-Host "[*] Setting remote origin to: $RemoteUrl"
    git remote remove origin -ErrorAction SilentlyContinue
    git remote add origin $RemoteUrl
    Write-Host "[*] Pushing to GitHub (main branch)..."
    git push -u origin main
    Write-Host "[+] Successfully pushed to GitHub!" -ForegroundColor Green
} else {
    Write-Host "`n[+] Local repository initialized and committed successfully!" -ForegroundColor Green
    Write-Host "[*] To link and push to your dedicated GitHub repository, run:" -ForegroundColor Yellow
    Write-Host "    git remote add origin https://github.com/<your-username>/<your-repo-name>.git"
    Write-Host "    git push -u origin main"
}
