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

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AppControlManager.Others;
using Microsoft.Identity.Client;

namespace AppControlManager.MicrosoftGraph;

internal static class Main
{
	// For Microsoft Graph Command Line Tools
	private const string ClientId = "14d82eec-204b-4c2f-b7e8-296a70dab67e";

	private const string DeviceConfigurationsURL = "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations";

	// Initialize the Public Client Application
	private static readonly IPublicClientApplication App = PublicClientApplicationBuilder.Create(ClientId)
			.WithAuthority(AzureCloudInstance.AzurePublic, "common")
			.WithRedirectUri("http://localhost")
			.Build();


	// Dictionary to store Group names as keys and Group IDs as values
	private static readonly Dictionary<string, string> Groups = [];

	private const string GroupsUrl = "https://graph.microsoft.com/v1.0/groups";

	// To manage Sign in cancellation
	private static CancellationTokenSource? _cts;

	// The correlation between scopes and required permissions
	private static readonly Dictionary<AuthenticationContext, string[]> Scopes = new() {

		// Scopes required to create and assign device configurations for Intune
		// https://learn.microsoft.com/en-us/graph/permissions-reference
		{ AuthenticationContext.Intune, [
		"Group.Read.All", // For Groups enumeration
		"DeviceManagementConfiguration.ReadWrite.All" // For uploading policy
		]},

		// Scopes required to retrieve MDE Advanced Hunting results
		// https://learn.microsoft.com/en-us/graph/api/security-security-runhuntingquery
		{AuthenticationContext.MDEAdvancedHunting,  ["ThreatHunting.Read.All"]}
		};

	// This class defines every account that is authenticated by the user
	private sealed class AccountIdentity
	{
		internal required string AccountIdentifier { get; set; }
		internal required string Username { get; set; }
		internal required string TenantID { get; set; }
		internal required AuthenticationResult AuthResult { get; set; }
		internal required IAccount Account { get; set; }
	}

	// A dictionary to keep the record of all of the authenticated accounts
	private static readonly Dictionary<AuthenticationContext, AccountIdentity> SavedAccounts = [];


	/// <summary>
	/// Perform an Advanced Hunting query using Microsoft Defender for Endpoint
	/// Accepts a device name as an optional parameter for filtering
	/// </summary>
	/// <returns></returns>
	/// <exception cref="InvalidOperationException"></exception>
	internal static async Task<string?> RunMDEAdvancedHuntingQuery(string? deviceName)
	{
		if (!SavedAccounts.TryGetValue(AuthenticationContext.MDEAdvancedHunting, out AccountIdentity? account))
		{
			throw new InvalidOperationException("You need to authenticate first.");
		}

		using SecHttpClient httpClient = new();

		string? output = null;

		// Set up the HTTP headers
		httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", account.AuthResult.AccessToken);
		httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

		QueryPayload queryPayload;

		if (string.IsNullOrWhiteSpace(deviceName))
		{
			// Defining the query
			queryPayload = new()
			{
				Query = """
DeviceEvents
| where ActionType startswith "AppControlCodeIntegrity"
   or ActionType startswith "AppControlCIScriptBlocked"
   or ActionType startswith "AppControlCIScriptAudited"
"""
			};
		}
		else
		{
			queryPayload = new()
			{
				Query = $"""
DeviceEvents
| where (ActionType startswith "AppControlCodeIntegrity"
    or ActionType startswith "AppControlCIScriptBlocked"
    or ActionType startswith "AppControlCIScriptAudited")
    and DeviceName == "{deviceName}"
"""
			};
		}

		string jsonPayload = JsonSerializer.Serialize(queryPayload, IntuneJsonContext.Default.QueryPayload);

		using StringContent content = new(jsonPayload, Encoding.UTF8, "application/json");

		// Make the POST request
		HttpResponseMessage response = await httpClient.PostAsync(new Uri("https://graph.microsoft.com/v1.0/security/runHuntingQuery"), content);

		if (response.IsSuccessStatusCode)
		{
			output = await response.Content.ReadAsStringAsync();
			Logger.Write("MDE Advanced Hunting Query has been Successful.");

			return output;
		}
		else
		{
			Logger.Write($"Failed to run MDE Advanced Hunting Query. Status code: {response.StatusCode}");
			string errorContent = await response.Content.ReadAsStringAsync();
			throw new InvalidOperationException($"Error details: {errorContent}");
		}
	}


	/// <summary>
	/// Fetches the security groups
	/// </summary>
	/// <returns></returns>
	/// <exception cref="InvalidOperationException"></exception>
	internal static async Task FetchGroups()
	{
		if (!SavedAccounts.TryGetValue(AuthenticationContext.Intune, out AccountIdentity? account))
		{
			throw new InvalidOperationException("You need to authenticate first.");
		}

		using SecHttpClient httpClient = new();

		// Set up the HTTP headers
		httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", account.AuthResult.AccessToken);
		httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

		// Make the request to get all groups
		HttpResponseMessage response = await httpClient.GetAsync(new Uri(GroupsUrl));

		if (response.IsSuccessStatusCode)
		{
			string content = await response.Content.ReadAsStringAsync();
			JsonElement groupsJson = JsonSerializer.Deserialize(content, IntuneJsonContext.Default.JsonElement);


			if (groupsJson.TryGetProperty("value", out JsonElement groups))
			{
				Groups.Clear(); // Clear the dictionary before adding new entries

				foreach (JsonElement group in groups.EnumerateArray())
				{
					string? groupName = group.GetProperty("displayName").GetString();
					string? groupId = group.GetProperty("id").GetString();

					if (!string.IsNullOrEmpty(groupName) && !string.IsNullOrEmpty(groupId))
					{
						Groups[groupName] = groupId;
					}
				}

				Logger.Write($"Successfully fetched {Groups.Count} groups.");
			}
			else
			{
				Logger.Write("No groups found in the response.");
			}
		}
		else
		{
			Logger.Write($"Failed to fetch groups. Status code: {response.StatusCode}");
			string errorContent = await response.Content.ReadAsStringAsync();
			throw new InvalidOperationException($"Error details: {errorContent}");
		}

	}


	/// <summary>
	/// Returns the Groups dictionary
	/// </summary>
	/// <returns></returns>
	internal static Dictionary<string, string> GetGroups()
	{
		return Groups;
	}


	/// <summary>
	/// Signs into a tenant
	/// </summary>
	/// <returns></returns>
	internal static async Task SignIn(AuthenticationContext context)
	{

		AuthenticationResult? authResult = null;

		bool error = false;

		if (SavedAccounts.TryGetValue(context, out AccountIdentity? account))
		{
			IEnumerable<IAccount> accounts = await App.GetAccountsAsync();

			if (accounts.Any(x => x == account.Account))
			{
				Logger.Write($"Account with the UserName {account.Username} for the context {context} is already authenticated");
				return;
			}
		}

		// Fall back to interactive login if silent authentication fails
		_cts = new CancellationTokenSource();

		try
		{
			authResult = await App.AcquireTokenInteractive(Scopes[context])
				.WithPrompt(Prompt.SelectAccount)
				.WithUseEmbeddedWebView(false)
				.ExecuteAsync(_cts.Token);
		}
		catch (OperationCanceledException)
		{
			error = true;
			throw new OperationCanceledException("The operation was canceled after 1 minute. Browser might have been closed or timeout occurred.");
		}
		finally
		{
			if (!error && authResult is not null)
			{
				// Add the account that was successfully authenticated to the dictionary
				SavedAccounts[context] = new AccountIdentity
				{
					AuthResult = authResult,
					AccountIdentifier = authResult.Account.HomeAccountId.Identifier,
					Username = authResult.Account.Username,
					TenantID = authResult.TenantId,
					Account = authResult.Account
				};
			}

			_cts.Dispose();
			_cts = null; // Reset for future operations
		}
	}


	/// <summary>
	/// Cancels the current sign-in operation
	/// </summary>
	internal static void CancelSignIn()
	{
		if (_cts is not null && !_cts.Token.IsCancellationRequested)
		{
			_cts.Cancel();
		}
	}


	/// <summary>
	/// Signs out the user
	/// </summary>
	/// <returns></returns>
	internal static async Task SignOut(AuthenticationContext context)
	{
		if (SavedAccounts.TryGetValue(context, out AccountIdentity? account))
		{
			await App.RemoveAsync(account.Account);
			Logger.Write($"Signed out account: {account.Username}");
			if (!SavedAccounts.Remove(context))
			{
				throw new InvalidOperationException($"Failed to remove the account with the username {account.Username} from the saved accounts.");
			}
		}
		else
		{
			Logger.Write($"No user is currently signed in for the context {context}.");
		}
	}


	/// <summary>
	/// Grabs the path to a CIP file and upload it to Intune.
	/// </summary>
	/// <param name="policyPath"></param>
	/// <param name="groupName"></param>
	/// <param name="policyName"></param>
	/// <param name="policyID"></param>
	/// <returns></returns>
	/// <exception cref="InvalidOperationException"></exception>
	internal static async Task UploadPolicyToIntune(string policyPath, string? groupName, string? policyName, string policyID)
	{

		if (!SavedAccounts.TryGetValue(AuthenticationContext.Intune, out AccountIdentity? account))
		{
			throw new InvalidOperationException("You need to authenticate first.");
		}

		DirectoryInfo stagingArea = StagingArea.NewStagingArea("IntuneCIPUpload");

		string tempPolicyPath = Path.Combine(stagingArea.FullName, "policy.bin");

		File.Copy(policyPath, tempPolicyPath, true);

		// https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/deploy-appcontrol-policies-using-intune#deploy-app-control-policies-with-custom-oma-uri
		string base64String = ConvertBinFileToBase64(tempPolicyPath, 350000);

		// Call Microsoft Graph API to create the custom policy
		string? policyId = await CreateCustomIntunePolicy(account.AuthResult.AccessToken, base64String, policyName, policyID);

		Logger.Write($"{policyId} is the ID of the policy that was created");

		if (!string.IsNullOrWhiteSpace(groupName) && policyId is not null)
		{
			if (Groups.TryGetValue(groupName, out string? groupId))
			{
				await AssignIntunePolicyToGroup(policyId, account.AuthResult.AccessToken, groupId);
			}
		}

		// await GetPoliciesAndAssignments(result.AccessToken);
	}


	/// <summary>
	/// Assigns a group to the created Intune policy
	/// </summary>
	/// <param name="policyId"></param>
	/// <param name="accessToken"></param>
	/// <param name="groupID"></param>
	/// <returns></returns>
	/// <exception cref="InvalidOperationException"></exception>
	private static async Task AssignIntunePolicyToGroup(string policyId, string accessToken, string groupID)
	{
		using SecHttpClient httpClient = new();

		// Set up the HTTP headers
		httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
		httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

		// Create the payload with a Dictionary to handle special characters like @odata.type
		AssignmentPayload assignmentPayload = new()
		{
			Target = new Dictionary<string, object>
			{
				{ "@odata.type", "#microsoft.graph.groupAssignmentTarget" },
				{ "groupId", groupID }
			}
		};

		// Serialize the assignment payload to JSON
		string jsonPayload = JsonSerializer.Serialize(assignmentPayload, IntuneJsonContext.Default.AssignmentPayload);

		using StringContent content = new(jsonPayload, Encoding.UTF8, "application/json");

		// Send the POST request to assign the policy to the group
		HttpResponseMessage response = await httpClient.PostAsync(
			new Uri($"{DeviceConfigurationsURL}/{policyId}/assignments"),
			content
		);

		// Process the response
		if (response.IsSuccessStatusCode)
		{
			string responseContent = await response.Content.ReadAsStringAsync();
			Logger.Write("Policy assigned successfully:");
			Logger.Write(responseContent);
		}
		else
		{
			Logger.Write($"Failed to assign policy. Status code: {response.StatusCode}");
			string errorContent = await response.Content.ReadAsStringAsync();
			throw new InvalidOperationException($"Error details: {errorContent}");
		}
	}


	/// <summary>
	/// https://learn.microsoft.com/en-us/mem/intune/configuration/custom-settings-windows-10
	/// </summary>
	/// <param name="accessToken"></param>
	/// <param name="policyData"></param>
	/// <param name="policyID"></param>
	/// <param name="policyName"></param>
	/// <returns></returns>
	private static async Task<string?> CreateCustomIntunePolicy(string accessToken, string policyData, string? policyName, string policyID)
	{

		string descriptionText = $"Application Control Policy Uploaded from AppControl Manager on {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss 'UTC'}";

		string displayNameText = !string.IsNullOrWhiteSpace(policyName) ? $"{policyName} App Control Policy" : "App Control Policy";

		// Making sure the policy ID doesn't have the curly brackets
		// https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/deploy-appcontrol-policies-using-intune#deploy-custom-app-control-policies-on-windows-10-1903
		policyID = policyID.Trim('{', '}');

		// Create the policy object
		Windows10CustomConfiguration customPolicy = new()
		{
			ODataType = "#microsoft.graph.windows10CustomConfiguration",
			DisplayName = displayNameText,
			Description = descriptionText,
			OmaSettings =
			[
				new OmaSettingBase64
				{
					ODataType = "microsoft.graph.omaSettingBase64",
					DisplayName = displayNameText,
					Description = descriptionText,
					OmaUri = $"./Vendor/MSFT/ApplicationControl/Policies/{policyID}/Policy",
					FileName = "Policy.bin",
					Value = policyData
				}
			],
			Platforms = ["windows10AndLater"]
		};

		// Serialize the policy object to JSON
		string jsonPayload = JsonSerializer.Serialize(customPolicy, IntuneJsonContext.Default.Windows10CustomConfiguration);

		using SecHttpClient httpClient = new();

		// Set up the HTTP headers
		httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
		httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

		using StringContent content = new(jsonPayload, Encoding.UTF8, "application/json");

		// Send the POST request
		HttpResponseMessage response = await httpClient.PostAsync(
			new Uri(DeviceConfigurationsURL),
			content
		);

		// Process the response
		if (response.IsSuccessStatusCode)
		{
			string responseContent = await response.Content.ReadAsStringAsync();
			Logger.Write("Custom policy created successfully:");
			Logger.Write(responseContent);

			// Extract the policy ID from the response
			JsonElement responseJson = JsonSerializer.Deserialize(responseContent, IntuneJsonContext.Default.JsonElement);

			return responseJson.GetProperty("id").GetString();
		}
		else
		{
			Logger.Write($"Failed to create custom policy. Status code: {response.StatusCode}");
			string errorContent = await response.Content.ReadAsStringAsync();
			throw new InvalidOperationException($"Error details: {errorContent}");
		}
	}


	/*
	private static async Task GetPoliciesAndAssignments(string accessToken)
	{
		using SecHttpClient httpClient = new();

		// Set up the HTTP headers
		httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
		httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

		// Fetch all policies
		HttpResponseMessage response = await httpClient.GetAsync(new Uri(DeviceConfigurationsURL));

		if (response.IsSuccessStatusCode)
		{
			string content = await response.Content.ReadAsStringAsync();
			JsonElement policiesJson = JsonSerializer.Deserialize<JsonElement>(content);

			// Iterate through each policy
			if (policiesJson.TryGetProperty("value", out JsonElement policies))
			{
				foreach (JsonElement policy in policies.EnumerateArray())
				{
					string? policyId = policy.GetProperty("id").GetString();
					string? policyName = policy.GetProperty("displayName").GetString();
					Logger.Write($"Policy ID: {policyId}");
					Logger.Write($"Policy Name: {policyName}");

					// Fetch assignments for the current policy
					HttpResponseMessage assignmentsResponse = await httpClient.GetAsync(new Uri($"{DeviceConfigurationsURL}/{policyId}/assignments"));

					if (assignmentsResponse.IsSuccessStatusCode)
					{
						string assignmentsContent = await assignmentsResponse.Content.ReadAsStringAsync();
						JsonElement assignmentsJson = JsonSerializer.Deserialize<JsonElement>(assignmentsContent);

						if (assignmentsJson.TryGetProperty("value", out JsonElement assignments))
						{
							Logger.Write("Assignments:");
							foreach (JsonElement assignment in assignments.EnumerateArray())
							{
								JsonElement target = assignment.GetProperty("target");
								string? targetType = target.GetProperty("@odata.type").GetString();
								Logger.Write($" - Target Type: {targetType}");

								if (targetType == "#microsoft.graph.groupAssignmentTarget" && target.TryGetProperty("groupId", out JsonElement groupId))
								{
									Logger.Write($"   Group ID: {groupId.GetString()}");
								}
							}
						}
						else
						{
							Logger.Write("No assignments found.");
						}
					}
					else
					{
						Logger.Write($"Failed to fetch assignments for Policy ID: {policyId}. Status code: {assignmentsResponse.StatusCode}");
					}

					Logger.Write(""); // Add a blank line between policies
				}
			}
		}
		else
		{
			Logger.Write($"Failed to fetch policies. Status code: {response.StatusCode}");
			string errorContent = await response.Content.ReadAsStringAsync();
			throw new InvalidOperationException($"Error details: {errorContent}");
		}
	}
	*/


	/// <summary>
	/// Converts a binary file to a Base64 string after checking its size against a specified limit.
	/// </summary>
	/// <param name="filePath">Specifies the location of the binary file to be converted.</param>
	/// <param name="maxSizeInBytes">Defines the maximum allowable size for the file before conversion.</param>
	/// <returns>Returns the Base64 encoded string of the file's contents.</returns>
	/// <exception cref="InvalidOperationException">Thrown when the file size exceeds the specified maximum limit.</exception>
	private static string ConvertBinFileToBase64(string filePath, int maxSizeInBytes)
	{
		FileInfo fileInfo = new(filePath);

		// Check the file size
		if (fileInfo.Length > maxSizeInBytes)
		{
			throw new InvalidOperationException($"The CIP policy file size exceeds the limit of {maxSizeInBytes} bytes.");
		}

		// Read the file and convert to Base64
		byte[] fileBytes = File.ReadAllBytes(filePath);
		return Convert.ToBase64String(fileBytes);
	}

}
