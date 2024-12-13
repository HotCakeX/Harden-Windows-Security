using System;
using System.Linq;
using System.Security.Principal;

namespace HardenWindowsSecurity
{

    internal sealed class CurrentUserIdentityResult
    {
        internal required string userName;
        internal required string userSID;
        internal string? userFullName;
    }


    internal static class WinIdentityUser
    {
        internal static CurrentUserIdentityResult GetCurrentIdentity()
        {
            // Save the username in the class variable
            WindowsIdentity CurrentUserResult = WindowsIdentity.GetCurrent();
            string userSID = CurrentUserResult.User!.Value.ToString();

            string userName;
            string? userFullName = null;

            // The LocalUserRetriever.Get() method doesn't return SYSTEM so we have to handle it separately
            // In case the Harden Windows Security is running as SYSTEM
            if (CurrentUserResult.IsSystem)
            {
                userName = "SYSTEM";
                userFullName = "SYSTEM";
            }

            else
            {

                try
                {

                    LocalUser CurrentLocalUser = LocalUserRetriever.Get()
        .First(Lu => string.Equals(Lu.SID, userSID, StringComparison.OrdinalIgnoreCase));

                    userName = CurrentLocalUser.Name!;
                    userFullName = CurrentLocalUser.FullName;

                }
                // We don't fail it if username or full name can't be detected
                // Any parts of the Harden Windows Security relying on their values must gracefully handle empty or inaccurate values.
                catch
                {
                    userName = string.Empty;
                    Logger.LogMessage($"Could not find UserName or FullName of the current user with the SID {userSID}", LogTypeIntel.Warning);
                }
            }


            return new CurrentUserIdentityResult
            {
                userName = userName,
                userSID = userSID,
                userFullName = userFullName
            };
        }
    }
}
