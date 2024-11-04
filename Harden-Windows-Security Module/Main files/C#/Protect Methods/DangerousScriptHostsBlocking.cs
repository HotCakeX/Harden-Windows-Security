using System;
using System.IO;

#nullable enable

namespace HardenWindowsSecurity
{
    public static partial class DownloadsDefenseMeasures
    {
        /// <summary>
        /// Blocks certain dangerous script hosts using AppControl policy
        /// </summary>
        /// <exception cref="ArgumentNullException"></exception>
        public static void DangerousScriptHostsBlocking()
        {
            if (GlobalVars.path is null)
            {
                throw new ArgumentNullException("GlobalVars.path cannot be null.");
            }

            Logger.LogMessage("Running the Dangerous Script Hosts Blocking section", LogTypeIntel.Information);

            string CIPPath = Path.Combine(GlobalVars.WorkingDir, "Dangerous-Script-Hosts-Blocking.cip");
            string XMLPath = Path.Combine(GlobalVars.path, "Resources", "Dangerous-Script-Hosts-Blocking.xml");

            // Use string interpolation without the @ symbol for multiline
            string script = $@"
                $CurrentBasePolicyNames = [System.Collections.Generic.HashSet[System.String]]@(
                    ((&""$env:SystemDrive\Windows\System32\CiTool.exe"" -lp -json | ConvertFrom-Json).Policies |
                    Where-Object -FilterScript {{ ($_.IsSystemPolicy -ne 'True') -and ($_.PolicyID -eq $_.BasePolicyID) }}).FriendlyName
                )

                if (($null -eq $CurrentBasePolicyNames) -or (-NOT ($CurrentBasePolicyNames.Contains('Dangerous-Script-Hosts-Blocking')))) {{
                    $null = ConvertFrom-CIPolicy -XmlFilePath '{XMLPath}' -BinaryFilePath '{CIPPath}'
                    $null = CiTool.exe --update-policy '{CIPPath}' -json
                }}
                else {{
                    Write-Verbose -Message 'The Dangerous-Script-Hosts-Blocking policy is already deployed' -Verbose
                }}
            ";

            _ = PowerShellExecutor.ExecuteScript(script);
        }
    }
}
