using AppControlManager.Logging;

namespace AppControlManager
{
    internal static class ConfigureISGServices
    {
        /// <summary>
        /// Starts the AppIdTel and sets the appidsvc service to auto start
        /// </summary>
        internal static void Configure()
        {
            Logger.Write("Configuring and starting the required ISG related services");

            ProcessStarter.RunCommand("appidtel.exe", "start");

            ProcessStarter.RunCommand("sc.exe", "config appidsvc start=auto");

        }
    }
}
