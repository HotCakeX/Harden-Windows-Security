﻿using System;
using System.Diagnostics;

#nullable enable

namespace WDACConfig
{
    internal static class ProcessStarter
    {
        internal static void RunCommand(string command, string? arguments = null)
        {

            ProcessStartInfo processInfo;

            if (arguments is not null)
            {
                processInfo = new()
                {
                    FileName = command,
                    Arguments = arguments,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
            }
            else
            {
                processInfo = new()
                {
                    FileName = command,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
            }

            using Process process = new();
            process.StartInfo = processInfo;
            _ = process.Start();

            // Capture output and errors
            string output = process.StandardOutput.ReadToEnd();
            string error = process.StandardError.ReadToEnd();

            process.WaitForExit();

            if (process.ExitCode != 0)
            {
                throw new InvalidOperationException($"Command '{command} {arguments}' failed with exit code {process.ExitCode}. Error: {error}");
            }

        }
    }
}
