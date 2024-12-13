using System.Security.Principal;

namespace HardenWindowsSecurity
{
    public static class UserPrivCheck
    {
        // Method to check if the user has Administrator privileges
        public static bool IsAdmin()
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
    }
}
