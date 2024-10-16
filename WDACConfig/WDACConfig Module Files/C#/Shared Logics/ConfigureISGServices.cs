using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WDACConfig
{
    internal static class ConfigureISGServices
    {
        /// <summary>
        /// Starts the AppIdTel and sets the appidsvc service to auto start
        /// </summary>
        public static void Configure()
        {
            Logger.Write("Configuring and starting the required ISG related services");

            _ = PowerShellExecutor.ExecuteScript("""
appidtel.exe start
sc.exe config appidsvc start=auto
""");

        }
    }
}
