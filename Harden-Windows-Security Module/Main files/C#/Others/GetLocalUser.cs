// MIT License
//
// Copyright (c) 2023-Present - Violet Hansen - (aka HotCakeX on GitHub) - Email Address: spynetgirl@outlook.com
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// See here for more information: https://github.com/HotCakeX/Harden-Windows-Security/blob/main/LICENSE
//

using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.Globalization;

namespace HardenWindowsSecurity;

// Class to represent a local user account
internal sealed class LocalUser
{
	internal string? AccountExpires { get; set; }
	internal string? Description { get; set; }
	internal bool Enabled { get; set; }
	internal string? FullName { get; set; }
	internal string? PasswordChangeableDate { get; set; }
	internal bool UserMayChangePassword { get; set; }
	internal bool PasswordRequired { get; set; }
	internal string? PasswordLastSet { get; set; }
	internal string? LastLogon { get; set; }
	internal string? Name { get; set; }
	internal string? SID { get; set; }
	internal string? ObjectClass { get; set; }
	internal List<string>? Groups { get; set; }
	internal List<string>? GroupsSIDs { get; set; }
}


/// <summary>
/// Gets user accounts on the system similar to Get-LocalUser cmdlet
/// It doesn't contain some properties such as PrincipalSource
/// It doesn't contain additional properties about each user account such as their group memberships
/// </summary>
internal static class LocalUserRetriever
{

	/// <summary>
	/// Retrieves local user accounts on the system and returns them as a list of LocalUser objects
	/// </summary>
	/// <returns></returns>
	internal static List<LocalUser> Get()
	{
		// List to hold retrieved local users
		List<LocalUser> localUsers = [];

		// Create a context for the local machine
		// https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.accountmanagement.principalcontext
		using (PrincipalContext context = new(ContextType.Machine))
		{

			// Create a user principal object used as a query filter
			// https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.accountmanagement.userprincipal
			using UserPrincipal userPrincipal = new(context);

			// Initialize a searcher with the user principal object
			// https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.accountmanagement.principalsearcher
			using PrincipalSearcher searcher = new(userPrincipal);

			// Iterate over the search results
			foreach (Principal result in searcher.FindAll())
			{
				// Cast the result to a UserPrincipal object
				if (result is UserPrincipal user)
				{
					// Create a new LocalUser object and populate its properties
					LocalUser localUser = new()
					{
						AccountExpires = user.AccountExpirationDate?.ToString(CultureInfo.InvariantCulture),
						Description = user.Description,
						Enabled = user.Enabled ?? false,
						FullName = user.DisplayName,
						PasswordChangeableDate = user.LastPasswordSet?.ToString(CultureInfo.InvariantCulture),
						UserMayChangePassword = !user.UserCannotChangePassword,
						PasswordRequired = !user.PasswordNotRequired,
						PasswordLastSet = user.LastPasswordSet?.ToString(CultureInfo.InvariantCulture),
						LastLogon = user.LastLogon?.ToString(CultureInfo.InvariantCulture),
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

		// Return the list of local users
		return localUsers;
	}

	// Method to retrieve group names for a given user
	private static List<string> GetGroupNames(UserPrincipal user)
	{
		List<string> groupNames = [];

		// Iterate over the groups the user is a member of
		foreach (Principal group in user.GetGroups())
		{
			// Add group name to the list
			groupNames.Add(group.Name);
		}

		return groupNames;
	}

	// Method to retrieve group SIDs for a given user
	private static List<string> GetGroupSIDs(UserPrincipal user)
	{
		List<string> groupSIDs = [];

		// Iterate over the groups the user is a member of
		foreach (Principal group in user.GetGroups())
		{
			// Add group SID to the list
			groupSIDs.Add(group.Sid.ToString());
		}

		return groupSIDs;
	}
}
