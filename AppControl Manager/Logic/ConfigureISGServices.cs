using AppControlManager.Logging;

namespace AppControlManager;

internal static class ConfigureISGServices
{
	/// <summary>
	/// Starts the AppIdTel and sets the AppIDSvc service to auto start
	/// </summary>
	internal static void Configure()
	{
		Logger.Write("Configuring and starting the required ISG related services");


		/*

            // Start the AppID Service
            using ServiceController AppIDService = new("AppIDSvc");

            if (AppIDService.Status is not ServiceControllerStatus.Running)
            {
                Logger.Write("Starting the AppIDSvc service...");
                AppIDService.Start();
                AppIDService.WaitForStatus(ServiceControllerStatus.Running);
                Logger.Write("Service started successfully.");
            }
            else
            {
                Logger.Write("AppIDSvc Service is already running.");
            }

            */


		ProcessStarter.RunCommand("appidtel.exe", "start");

		ProcessStarter.RunCommand("sc.exe", "config appidsvc start=auto");

	}
}
