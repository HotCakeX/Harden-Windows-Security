using System.DirectoryServices.AccountManagement;
using System.Security.Principal;

namespace HardenWindowsSecurity;

    internal static class LocalGroupMember
    {
        internal static void Add(string userSid, string groupSid)
        {
            // Convert the group SID to a SecurityIdentifier object
            SecurityIdentifier groupSecurityId = new(groupSid);

            // Convert the user SID to a SecurityIdentifier object
            _ = new SecurityIdentifier(userSid);

            // Create a PrincipalContext for the local machine
            using PrincipalContext ctx = new(ContextType.Machine);

            // Find the group using its SID
            GroupPrincipal group = GroupPrincipal.FindByIdentity(ctx, IdentityType.Sid, groupSecurityId.Value);

            // Check if the group exists
            if (group is not null)
            {
                // Check if the user is already a member of the group
                bool isUserInGroup = false;
                foreach (Principal member in group.GetMembers())
                {
                    if (string.Equals(member.Sid.Value, userSid, System.StringComparison.OrdinalIgnoreCase))
                    {
                        isUserInGroup = true;
                        break;
                    }
                }

                if (!isUserInGroup)
                {
                    // Add the user to the group since they are not already a member
                    group.Members.Add(ctx, IdentityType.Sid, userSid);
                    group.Save();

                    // Inform the user that the member was successfully added to the group
                    Logger.LogMessage($"A user with the SID {userSid} has been successfully added to the group with the SID {groupSid}.", LogTypeIntel.Information);
                }
                else
                {
                    // Inform the user that the account is already in the group
                    Logger.LogMessage($"The User with the SID {userSid} is already a member of the group with the SID {groupSid}.", LogTypeIntel.Information);
                }
            }
            else
            {
                // Inform the user if the group was not found
                Logger.LogMessage($"A group with the SID {groupSid} was not found.", LogTypeIntel.Error);
            }
        }
    }
