using System;
using System.IO;
using System.Linq;

#nullable enable

namespace HardenWindowsSecurity
{
    internal static class SSHConfigurations
    {

        private readonly static string SSHClientUserConfigDirectory = Path.Combine(Environment.GetEnvironmentVariable("SystemDrive")!, "Users", GlobalVars.userName, ".ssh");
        private readonly static string SSHClientUserConfigFile = Path.Combine(SSHClientUserConfigDirectory, "config");

        // Secure MACs configurations for SSH
        private const string sshConfigContent = "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com";

        internal static void SecureMACs()
        {

            Logger.LogMessage("Checking for SSH client user configuration", LogTypeIntel.Information);

            // Ensure the SSH client directory exists
            if (!Directory.Exists(SSHClientUserConfigDirectory))
            {
                _ = Directory.CreateDirectory(SSHClientUserConfigDirectory);
            }

            // Check if the configuration file exists
            if (!File.Exists(SSHClientUserConfigFile))
            {
                // If the file does not exist, create it with the required content
                File.WriteAllText(SSHClientUserConfigFile, sshConfigContent);
                Logger.LogMessage($"SSH client configuration file created with content: {sshConfigContent} because it didn't exist.", LogTypeIntel.Information);
            }
            else
            {
                // If the file exists, read all lines into a list
                var configLines = File.ReadAllLines(SSHClientUserConfigFile).ToList();

                // Check if any line starts with "MACs "
                bool lineExists = false;

                for (int i = 0; i < configLines.Count; i++)
                {
                    if (configLines[i].StartsWith("MACs ", StringComparison.OrdinalIgnoreCase))
                    {
                        // If a line starts with "MACs ", replace it with the new one
                        configLines[i] = sshConfigContent;
                        lineExists = true;
                        Logger.LogMessage("Existing 'MACs' configuration found and replaced.", LogTypeIntel.Information);
                        break;
                    }
                }

                if (!lineExists)
                {
                    // If no line starts with "MACs ", append the new line to the file
                    configLines.Add(sshConfigContent);
                    Logger.LogMessage("MACs configuration not found, added new configuration.", LogTypeIntel.Information);
                }

                // Writing the modified content back to the file
                File.WriteAllLines(SSHClientUserConfigFile, configLines);
            }
        }


        /// <summary>
        /// First checks user configurations and then system-wide configurations for secure MACs configurations of the SSH client
        /// </summary>
        /// <returns>Returns bool</returns>
        internal static bool TestSecureMACs()
        {
            Logger.LogMessage("Checking for secure MACs in SSH client user configuration", LogTypeIntel.Information);

            // Check if the user configurations directory exists in user directory
            if (Directory.Exists(SSHClientUserConfigDirectory))
            {
                // Check if the configuration file exists
                if (File.Exists(SSHClientUserConfigFile))
                {
                    // Read all lines into a list
                    var configLines = File.ReadAllLines(SSHClientUserConfigFile).ToList();

                    // Check if any line starts with "MACs "
                    for (int i = 0; i < configLines.Count; i++)
                    {
                        if (configLines[i].StartsWith("MACs ", StringComparison.OrdinalIgnoreCase))
                        {
                            if (string.Equals(configLines[i], sshConfigContent, StringComparison.OrdinalIgnoreCase))
                            {
                                Logger.LogMessage("Existing MACs configuration found in the user directory and matches the secure configurations.", LogTypeIntel.Information);
                                return true;
                            }
                            else
                            {
                                // Log when the MACs value does not match the secure configuration
                                Logger.LogMessage($"MACs configuration in the user directory is different: {configLines[i]}", LogTypeIntel.Information);
                                return false;
                            }
                        }
                    }
                }
            }


            Logger.LogMessage("Checking for secure MACs in SSH client system-wide configuration", LogTypeIntel.Information);

            // Check for secure MACs in the system-wide SSH configuration in %programdata%\ssh\ssh_config
            string programDataSSHConfigFile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "ssh", "ssh_config");

            // Check if the system-wide SSH configuration file exists
            if (File.Exists(programDataSSHConfigFile))
            {
                // Read all lines into a list
                var configLines = File.ReadAllLines(programDataSSHConfigFile).ToList();

                // Check if any line starts with "MACs "
                for (int i = 0; i < configLines.Count; i++)
                {
                    if (configLines[i].StartsWith("MACs ", StringComparison.OrdinalIgnoreCase))
                    {
                        if (string.Equals(configLines[i], sshConfigContent, StringComparison.OrdinalIgnoreCase))
                        {
                            Logger.LogMessage("Existing MACs configuration found in the system-wide configuration and matches the secure configurations.", LogTypeIntel.Information);
                            return true;
                        }
                        else
                        {
                            // Log when the MACs value does not match the secure configuration
                            Logger.LogMessage($"MACs configuration in the system-wide configuration is different: {configLines[i]}", LogTypeIntel.Information);
                            return false;
                        }
                    }
                }
            }

            // Log when returning false (no matching or secure MACs found)
            Logger.LogMessage("No secure MACs configuration found in both user and system-wide configurations.", LogTypeIntel.Information);
            return false;
        }
    }
}
