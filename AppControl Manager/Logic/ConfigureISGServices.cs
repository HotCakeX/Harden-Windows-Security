namespace WDACConfig
{
    public static class ConfigureISGServices
    {
        /// <summary>
        /// Starts the AppIdTel and sets the appidsvc service to auto start
        /// </summary>
        public static void Configure()
        {
            Logger.Write("Configuring and starting the required ISG related services");

            ProcessStarter.RunCommand("appidtel.exe", "start");

            ProcessStarter.RunCommand("sc.exe", "config appidsvc start=auto");

        }
    }
}
