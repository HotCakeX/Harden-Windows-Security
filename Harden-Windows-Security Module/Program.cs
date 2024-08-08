using System;
using System.IO;

namespace HardenWindowsSecurity
{
    class Program
    {
        static void Main(string[] args)
        {
            // Acts as PSScriptRoot assignment in the module manifest for the GlobalVars.path variable
            GlobalVars.path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Main files");
                         
            GUI.LoadXaml();

        }
    }
}


