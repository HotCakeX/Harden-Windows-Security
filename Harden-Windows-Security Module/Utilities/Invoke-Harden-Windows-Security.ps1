# This file is for launching Harden-Windows-Security module in VS Code so that it can attach its debugger to the process
$script:ErrorActionPreference = 'Stop'

# Get the current folder of this script file
[System.String]$ScriptFilePath = ($MyInvocation.MyCommand.path | Split-Path -Parent)

# Import the module into the current scope using the relative path of the module itself
Import-Module -FullyQualifiedName "$ScriptFilePath\..\Main files\Harden-Windows-Security-Module.psd1" -Force

Protect-WindowsSecurity -GUI -Verbose
