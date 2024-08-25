using System;
using System.Diagnostics;

#nullable enable

namespace HardenWindowsSecurity
{
    public class RunCommandLineCommands
    {
        public static void Run(string command, string arguments)
        {
            ProcessStartInfo processStartInfo = new ProcessStartInfo
            {
                FileName = command,
                Arguments = arguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using (Process? process = Process.Start(processStartInfo))
            {
                if (process == null)
                {
                    throw new InvalidOperationException("Failed to start the process.");
                }

                process.WaitForExit();

                if (process.ExitCode != 0)
                {
                    string error = process.StandardError.ReadToEnd();
                    throw new Exception(error);
                }
            }
        }
    }
}
