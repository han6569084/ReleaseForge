param(
  [Parameter(Mandatory = $false)][string]$InputDir = "diagrams",
  [Parameter(Mandatory = $false)][string]$OutputDir = "diagrams\\out",
  [Parameter(Mandatory = $false)][ValidateSet("png","svg")][string]$Format = "png",
  [Parameter(Mandatory = $false)][int]$Width = 1800,
  [Parameter(Mandatory = $false)][int]$Height = 0
)

$ErrorActionPreference = "Stop"

function Test-NodeAvailable {
  if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    throw "node.exe not found. Install Node.js (LTS) first: https://nodejs.org/"
  }
  if (-not (Get-Command npx -ErrorAction SilentlyContinue)) {
    throw "npx not found (it should come with Node.js)."
  }
}

Test-NodeAvailable

$root = Resolve-Path -Path (Join-Path $PSScriptRoot "..")
$inDir = Join-Path $root $InputDir
$outDir = Join-Path $root $OutputDir

if (-not (Test-Path $inDir)) {
  throw "InputDir not found: $inDir"
}
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$mmdFiles = Get-ChildItem -Path $inDir -Filter "*.mmd" -File | Sort-Object Name
if ($mmdFiles.Count -eq 0) {
  Write-Host "No .mmd files found under $inDir" -ForegroundColor Yellow
  exit 0
}

Write-Host "Rendering Mermaid diagrams..." -ForegroundColor Cyan
Write-Host "- Input : $inDir"
Write-Host "- Output: $outDir"
Write-Host "- Format: $Format"

foreach ($f in $mmdFiles) {
  $outFile = Join-Path $outDir ($f.BaseName + "." + $Format)

  $npxParams = @(
    "-y",
    "@mermaid-js/mermaid-cli",
    "-i", $f.FullName,
    "-o", $outFile,
    "-w", $Width
  )

  if ($Height -gt 0) {
    $npxParams += @("-H", $Height)
  }

  Write-Host "- $($f.Name) -> $([IO.Path]::GetFileName($outFile))"
  & npx @npxParams
}

Write-Host "Done." -ForegroundColor Green
