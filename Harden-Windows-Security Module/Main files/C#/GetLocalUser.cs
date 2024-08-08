using System;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.Runtime.InteropServices;

namespace HardenWindowsSecurity
{
    // Class to represent a local user account
    public class LocalUser
    {
        public string AccountExpires { get; set; }
        public string Description { get; set; }
        public bool Enabled { get; set; }
        public string FullName { get; set; }
        public string PasswordChangeableDate { get; set; }
        public bool UserMayChangePassword { get; set; }
        public bool PasswordRequired { get; set; }
        public string PasswordLastSet { get; set; }
        public string LastLogon { get; set; }
        public string Name { get; set; }
        public string SID { get; set; }
        public string ObjectClass { get; set; }
        public List<string> Groups { get; set; }
        public List<string> GroupsSIDs { get; set; }
    }


    /// <summary>
    /// Gets user accounts on the system similar to Get-LocalUser cmdlet
    /// It doesn't contain some properties such as PrincipalSource
    /// It doest contain additional properties about each user account such as their group memberships
    /// </summary>
    public class LocalUserRetriever
    {
        // https://learn.microsoft.com/en-us/windows/win32/api/sddl/nf-sddl-convertsidtostringsida
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool ConvertSidToStringSid(IntPtr pSID, out IntPtr ptrSid);

        /// <summary>
        /// Retrieves local user accounts on the system and returns them as a list of LocalUser objects
        /// </summary>
        /// <returns></returns>
        public static List<LocalUser> Get()
        {
            // List to hold retrieved local users
            List<LocalUser> localUsers = new List<LocalUser>();

            // Create a context for the local machine
            // https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.accountmanagement.principalcontext
            using (PrincipalContext context = new PrincipalContext(ContextType.Machine))
            {
                // Create a user principal object used as a query filter
                // https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.accountmanagement.userprincipal
                UserPrincipal userPrincipal = new UserPrincipal(context);

                // Initialize a searcher with the user principal object
                // https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.accountmanagement.principalsearcher
                using (PrincipalSearcher searcher = new PrincipalSearcher(userPrincipal))
                {
                    // Iterate over the search results
                    foreach (var result in searcher.FindAll())
                    {
                        // Cast the result to a UserPrincipal object
                        UserPrincipal user = result as UserPrincipal;
                        if (user != null)
                        {
                            // Create a new LocalUser object and populate its properties
                            LocalUser localUser = new LocalUser
                            {
                                AccountExpires = user.AccountExpirationDate?.ToString(),
                                Description = user.Description,
                                Enabled = user.Enabled.HasValue ? user.Enabled.Value : false,
                                FullName = user.DisplayName,
                                PasswordChangeableDate = user.LastPasswordSet?.ToString(),
                                UserMayChangePassword = !user.UserCannotChangePassword,
                                PasswordRequired = !user.PasswordNotRequired,
                                PasswordLastSet = user.LastPasswordSet?.ToString(),
                                LastLogon = user.LastLogon?.ToString(),
                                Name = user.SamAccountName,
                                SID = user.Sid?.ToString(),
                                ObjectClass = "User",
                                Groups = GetGroupNames(user), // Populate group names
                                GroupsSIDs = GetGroupSIDs(user) // Populate group SIDs
                            };
                            localUsers.Add(localUser);
                        }
                    }
                }
            }

            // Return the list of local users
            return localUsers;
        }

        // Method to retrieve group names for a given user
        private static List<string> GetGroupNames(UserPrincipal user)
        {
            List<string> groupNames = new List<string>();

            // Iterate over the groups the user is a member of
            foreach (var group in user.GetGroups())
            {
                // Add group name to the list
                groupNames.Add(group.Name);
            }

            return groupNames;
        }

        // Method to retrieve group SIDs for a given user
        private static List<string> GetGroupSIDs(UserPrincipal user)
        {
            List<string> groupSIDs = new List<string>();

            // Iterate over the groups the user is a member of
            foreach (var group in user.GetGroups())
            {
                // Add group SID to the list
                groupSIDs.Add(group.Sid.ToString());
            }

            return groupSIDs;
        }
    }
}
