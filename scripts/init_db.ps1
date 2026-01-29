param(
    [string]$Host = $env:DB_HOST,
    [string]$Port = $env:DB_PORT,
    [string]$User = $env:DB_USER,
    [string]$Password = $env:DB_PASSWORD,
    [string]$Database = $env:DB_NAME
)

$schemaPath = Join-Path $PSScriptRoot "schema.sql"

if (-not $Host -or -not $User -or -not $Database) {
    Write-Error "Missing DB_HOST, DB_USER, or DB_NAME (or pass -Host/-User/-Database)."
    exit 1
}

if (-not $Port) { $Port = "3306" }
if (-not (Test-Path $schemaPath)) {
    Write-Error "schema.sql not found at $schemaPath"
    exit 1
}

$env:MYSQL_PWD = $Password
Get-Content -Raw $schemaPath | & mysql --host $Host --port $Port --user $User $Database
