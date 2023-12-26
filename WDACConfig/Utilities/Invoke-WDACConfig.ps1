# This file is for launching WDACConfig module in VS Code so that it can attach its debugger to the process

# Get the current folder of this script file
[System.String]$ScriptFilePath = ($MyInvocation.MyCommand.path | Split-Path -Parent)

# Import the module into the current scope using the relative path of the module itself
Import-Module -FullyQualifiedName "$ScriptFilePath\..\WDACConfig Module Files\WDACConfig.psd1" -Force

# Replace with any cmdlet of the WDACConfig module that is going to be debugged
Assert-WDACConfigIntegrity -SaveLocally -Verbose