#nullable enable

namespace HardenWindowsSecurity
{
    public static partial class LockScreen
    {
        public static void LockScreen_CtrlAltDel()
        {
            if (HardenWindowsSecurity.GlobalVars.path is null)
            {
                throw new System.ArgumentNullException("GlobalVars.path cannot be null.");
            }

            HardenWindowsSecurity.Logger.LogMessage("Applying the Enable CTRL + ALT + DEL policy", LogTypeIntel.Information);
            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Security-Baselines-X", "Lock Screen Policies", "Enable CTRL + ALT + DEL", "GptTmpl.inf"), LGPORunner.FileType.INF);
        }
    }
}
