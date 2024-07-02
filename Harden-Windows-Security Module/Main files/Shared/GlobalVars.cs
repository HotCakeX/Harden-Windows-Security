namespace HardeningModule
{
    public static class GlobalVars
    {
        public static int TotalNumberOfTrueCompliantValues = 238;

        // Stores the value of $PSScriptRoot in a global constant variable to allow the internal functions to use it when navigating the module structure
        public static string path;
        public static object MDAVConfigCurrent;
        public static object MDAVPreferencesCurrent;
    }
}
