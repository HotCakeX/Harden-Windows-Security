$ErrorActionPreference = 'Stop'

Push-Location -LiteralPath $PSScriptRoot
try {
    # Remove previous package outputs
    Remove-Item -LiteralPath 'MSIXOutputX64', 'MSIXOutputARM64', 'MSIXBundleOutput' -Recurse -Force -ErrorAction Ignore

    dotnet msbuild 'HardenSystemSecurityMCP.csproj' /t:Publish /restore /p:Configuration=Release /p:RuntimeIdentifier=win-x64 /p:PublishProfile=win-x64 '/p:AppxPackageDir=MSIXOutputX64\' /p:GenerateAppxPackageOnBuild=true /p:Platform=x64 -v:minimal -bl:X64MSBuildLog.binlog
    if ($LASTEXITCODE -ne 0) { throw "X64 build failed: $LASTEXITCODE" }

    dotnet msbuild 'HardenSystemSecurityMCP.csproj' /t:Publish /restore /p:Configuration=Release /p:RuntimeIdentifier=win-arm64 /p:PublishProfile=win-arm64 '/p:AppxPackageDir=MSIXOutputARM64\' /p:GenerateAppxPackageOnBuild=true /p:Platform=arm64 -v:minimal -bl:ARM64MSBuildLog.binlog
    if ($LASTEXITCODE -ne 0) { throw "ARM64 build failed: $LASTEXITCODE" }

    [System.IO.FileInfo]$X64MSIX = Get-ChildItem -LiteralPath 'MSIXOutputX64' -Recurse -File -Filter '*_x64.msix' | Select-Object -First 1
    [System.IO.FileInfo]$ARM64MSIX = Get-ChildItem -LiteralPath 'MSIXOutputARM64' -Recurse -File -Filter '*_arm64.msix' | Select-Object -First 1

    if ($null -eq $X64MSIX -or $null -eq $ARM64MSIX) { throw 'An X64 or ARM64 MSIX package was not created.' }

    [System.String]$BundleInput = [System.IO.Path]::Join($PSScriptRoot, 'MSIXBundleOutput')
    [System.IO.Directory]::CreateDirectory($BundleInput) | Out-Null
    Copy-Item -LiteralPath $X64MSIX.FullName, $ARM64MSIX.FullName -Destination $BundleInput

    [System.String]$SdkBin = [System.IO.Path]::Join(${env:ProgramFiles(x86)}, 'Windows Kits', '10', 'bin')
    [System.IO.FileInfo]$MakeAppx = Get-ChildItem -LiteralPath $SdkBin -Filter 'makeappx.exe' -File -Recurse |
        Where-Object { [System.String]::Equals($_.Directory.Name, 'x64', [System.StringComparison]::OrdinalIgnoreCase) } |
        Sort-Object -Property { [System.Version]$_.Directory.Parent.Name } -Descending |
        Select-Object -First 1

    if ($null -eq $MakeAppx) { throw 'Windows SDK makeappx.exe was not found.' }

    [System.String]$Bundle = [System.IO.Path]::Join($BundleInput, 'HardenSystemSecurityMCP.msixbundle')
    & $MakeAppx.FullName bundle /d $BundleInput /p $Bundle /o /v
    if ($LASTEXITCODE -ne 0) { throw "MSIXBundle creation failed: $LASTEXITCODE" }

    Write-Host "MSIXBundle: $Bundle"
}
finally {
    Pop-Location
}
