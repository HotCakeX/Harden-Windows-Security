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
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Broker;

namespace AppControlManager.MicrosoftGraph;

internal static class Main
{

	private static ViewModel ViewModelMSGraph { get; } = AppControlManager.App.AppHost.Services.GetRequiredService<ViewModel>();

	/// <summary>
	/// For Microsoft Graph Command Line Tools
	/// </summary>
	private const string ClientId = "14d82eec-204b-4c2f-b7e8-296a70dab67e";

	/// <summary>
	/// URL for Intune related operations
	/// </summary>
	private static readonly Uri DeviceConfigurationsURL = new("https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations");

	/// <summary>
	/// URL for M365 Groups
	/// </summary>
	private static readonly Uri GroupsUrl = new("https://graph.microsoft.com/v1.0/groups");

	/// <summary>
	/// URL for Microsoft Defender for Endpoint Advanced Hunting queries
	/// </summary>
	private static readonly Uri MDEAH = new("https://graph.microsoft.com/v1.0/security/runHuntingQuery");

	/// <summary>
	/// Initialize the Public Client Application
	/// </summary>
	private static readonly IPublicClientApplication App = PublicClientApplicationBuilder.Create(ClientId)
			.WithAuthority(AzureCloudInstance.AzurePublic, "common")
			.WithRedirectUri("http://localhost")
			.WithLegacyCacheCompatibility(false)
			.Build();


	#region For WAM based application

	private readonly static BrokerOptions OptionsForBroker = new(BrokerOptions.OperatingSystems.Windows)
	{
		Title = "AppControl Manager"
	};

	/// <summary>
	/// Helper method for WithParentActivityOrWindow that returns the window handle.
	/// </summary>
	/// <returns></returns>
	private static nint GetWindowHandle() => GlobalVars.hWnd;

	private readonly static IPublicClientApplication AppWAMBased = PublicClientApplicationBuilder.Create(ClientId)
		.WithDefaultRedirectUri()
		.WithParentActivityOrWindow(GetWindowHandle)
		.WithLegacyCacheCompatibility(false)
		.WithBroker(OptionsForBroker)
		.Build();

	#endregion


	/// <summary>
	/// The correlation between scopes and required permissions
	/// </summary>
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

	/// <summary>
	/// Interface to restrict access to the following two properties only within the Main class.
	/// </summary>
	internal interface IRestrictedAuthenticatedAccounts
	{
		AuthenticationResult AuthResult { get; set; }
		IAccount Account { get; set; }
	}

	/// <summary>
	/// Performs an Advanced Hunting query using Microsoft Defender for Endpoint
	/// Accepts a device name as an optional parameter for filtering
	/// </summary>
	/// <returns></returns>
	/// <exception cref="InvalidOperationException"></exception>
	internal static async Task<string?> RunMDEAdvancedHuntingQuery(string? deviceName, AuthenticatedAccounts? account)
	{

		if (account is null)
			return null;

		using SecHttpClient httpClient = new();

		string? output = null;

		// Set up the HTTP headers
		httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ((IRestrictedAuthenticatedAccounts)account).AuthResult.AccessToken);
		httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

		QueryPayload queryPayload;

		if (string.IsNullOrWhiteSpace(deviceName))
		{
			// Defining the query
			queryPayload = new(
				query: """
DeviceEvents
| where ActionType startswith "AppControlCodeIntegrity"
   or ActionType startswith "AppControlCIScriptBlocked"
   or ActionType startswith "AppControlCIScriptAudited"
"""
			);
		}
		else
		{
			queryPayload = new(
				query: $"""
DeviceEvents
| where (ActionType startswith "AppControlCodeIntegrity"
    or ActionType startswith "AppControlCIScriptBlocked"
    or ActionType startswith "AppControlCIScriptAudited")
    and DeviceName == "{deviceName}"
"""
			);
		}

		string jsonPayload = JsonSerializer.Serialize(queryPayload, MSGraphJsonContext.Default.QueryPayload);

		using StringContent content = new(jsonPayload, Encoding.UTF8, "application/json");

		// Make the POST request
		HttpResponseMessage response = await httpClient.PostAsync(MDEAH, content);

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
	/// Fetches the M365 security groups
	/// </summary>
	/// <returns></returns>
	/// <exception cref="InvalidOperationException"></exception>
	internal static async Task<Dictionary<string, string>> FetchGroups(AuthenticatedAccounts? account)
	{

		Dictionary<string, string> output = [];

		if (account is null)
			return output;

		using SecHttpClient httpClient = new();

		// Set up the HTTP headers
		httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ((IRestrictedAuthenticatedAccounts)account).AuthResult.AccessToken);
		httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

		// Make the request to get all groups
		HttpResponseMessage response = await httpClient.GetAsync(GroupsUrl);

		if (response.IsSuccessStatusCode)
		{
			string content = await response.Content.ReadAsStringAsync();
			JsonElement groupsJson = JsonSerializer.Deserialize(content, MSGraphJsonContext.Default.JsonElement);

			if (groupsJson.TryGetProperty("value", out JsonElement groups))
			{
				foreach (JsonElement group in groups.EnumerateArray())
				{
					string? groupName = group.GetProperty("displayName").GetString();
					string? groupId = group.GetProperty("id").GetString();

					if (!string.IsNullOrEmpty(groupName) && !string.IsNullOrEmpty(groupId))
					{
						output[groupName] = groupId;
					}
				}

				Logger.Write($"Successfully fetched {output.Count} groups.");
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

		return output;
	}



	/// <summary>
	/// Signs into a tenant
	/// </summary>
	/// <returns></returns>
	internal static async Task<(bool, CancellationTokenSource?, AuthenticatedAccounts?)> SignIn(AuthenticationContext context, SignInMethods signInMethod)
	{
		AuthenticationResult? authResult = null;
		bool error = false;

		// Create a CancellationTokenSource for this sign-in operation
		CancellationTokenSource cts = new();

		AuthenticatedAccounts? newAccount = null;

		try
		{

			switch (signInMethod)
			{
				case SignInMethods.WebBrowser:
					{
						// Perform the interactive token acquisition with the cancellation token
						authResult = await App.AcquireTokenInteractive(Scopes[context])
							.WithPrompt(Prompt.SelectAccount)
							.WithUseEmbeddedWebView(false)
							.ExecuteAsync(cts.Token);

						break;
					}
				case SignInMethods.WebAccountManager:
					{
						authResult = await AppWAMBased.AcquireTokenInteractive(Scopes[context])
							.ExecuteAsync(cts.Token);

						break;
					}
				default:
					{
						throw new InvalidOperationException("Invalid sign in method was used");
					}
			}

		}
		catch (OperationCanceledException)
		{
			error = true;
			throw new OperationCanceledException("The sign-in operation was canceled by the caller.");
		}
		finally
		{
			// If successful, store the result in SavedAccounts
			if (!error && authResult is not null)
			{

				// Add the account that was successfully authenticated to the dictionary
				newAccount = new(
					accountIdentifier: authResult.Account.HomeAccountId.Identifier,
					userName: authResult.Account.Username,
					tenantID: authResult.TenantId,
					permissions: string.Join(", ", Scopes[context]),
					authContext: context,
					authResult: authResult,
					account: authResult.Account
				);


				AuthenticatedAccounts? possibleDuplicate = ViewModelMSGraph.AuthenticatedAccounts.FirstOrDefault(x => string.Equals(authResult.Account.HomeAccountId.Identifier, x.AccountIdentifier, StringComparison.OrdinalIgnoreCase) &&
				string.Equals(authResult.Account.Username, x.Username, StringComparison.OrdinalIgnoreCase) &&
				string.Equals(authResult.TenantId, x.TenantID, StringComparison.OrdinalIgnoreCase) &&
				string.Equals(newAccount.Permissions, x.Permissions, StringComparison.OrdinalIgnoreCase));

				// Check if the account is already authenticated
				if (possibleDuplicate is not null)
				{
					Logger.Write($"An account with the Username {authResult.Account.Username} that has the same permissions, TenantID and Identifier already exists, removing it and replacing it with the new one.");

					_ = ViewModelMSGraph.AuthenticatedAccounts.Remove(possibleDuplicate);
				}

				ViewModelMSGraph.AuthenticatedAccounts.Add(newAccount);
			}

		}

		return (!error, cts, newAccount);
	}


	/// <summary>
	/// Signs out the user
	/// </summary>
	/// <returns></returns>
	internal static async Task SignOut(AuthenticatedAccounts? account)
	{

		if (account is null)
			return;

		await App.RemoveAsync(((IRestrictedAuthenticatedAccounts)account).Account);
		_ = ViewModelMSGraph.AuthenticatedAccounts.Remove(account);
		Logger.Write($"Signed out account: {account.Username}");
	}


	/// <summary>
	/// Grabs the path to a CIP file and upload it to Intune.
	/// </summary>
	/// <param name="policyPath"></param>
	/// <param name="groupIds"></param>
	/// <param name="policyName"></param>
	/// <param name="policyID"></param>
	/// <param name="descriptionText"></param>
	/// <param name="account"></param>
	/// <returns></returns>
	/// <exception cref="InvalidOperationException"></exception>
	internal static async Task UploadPolicyToIntune(AuthenticatedAccounts? account, string policyPath, List<string> groupIds, string? policyName, string policyID, string descriptionText)
	{

		if (account is null)
			return;

		DirectoryInfo stagingArea = StagingArea.NewStagingArea("IntuneCIPUpload");

		string tempPolicyPath = Path.Combine(stagingArea.FullName, "policy.bin");

		File.Copy(policyPath, tempPolicyPath, true);

		// https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/deploy-appcontrol-policies-using-intune#deploy-app-control-policies-with-custom-oma-uri
		string base64String = ConvertBinFileToBase64(tempPolicyPath, 350000);

		// Call Microsoft Graph API to create the custom policy
		string? policyId = await CreateCustomIntunePolicy(((IRestrictedAuthenticatedAccounts)account).AuthResult.AccessToken, base64String, policyName, policyID, descriptionText);

		Logger.Write($"{policyId} is the ID of the policy that was created");

		if (groupIds.Count > 0 && policyId is not null)
		{
			await AssignIntunePolicyToGroup(policyId, ((IRestrictedAuthenticatedAccounts)account).AuthResult.AccessToken, groupIds);
		}

		// await GetPoliciesAndAssignments(result.AccessToken);
	}


	/// <summary>
	/// Assigns a group to the created Intune policy for multiple groups.
	/// </summary>
	/// <param name="policyId">The ID of the policy to assign.</param>
	/// <param name="accessToken">The access token used for authentication.</param>
	/// <param name="groupIds">An enumerable collection of group IDs to which the policy will be assigned.</param>
	/// <returns>A task that represents the asynchronous assignment operation.</returns>
	/// <exception cref="InvalidOperationException">Thrown when the assignment fails for any of the groups.</exception>
	private static async Task AssignIntunePolicyToGroup(string policyId, string accessToken, IEnumerable<string> groupIds)
	{
		using SecHttpClient httpClient = new();

		// Set up the HTTP headers.
		httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
		httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

		foreach (string groupId in groupIds)
		{
			// Create the payload for each group.
			AssignmentPayload assignmentPayload = new(
				target: new Dictionary<string, object>
				{
				{ "@odata.type", "#microsoft.graph.groupAssignmentTarget" },
				{ "groupId", groupId }
				}
			);

			// Serialize the assignment payload to JSON.
			string jsonPayload = JsonSerializer.Serialize(assignmentPayload, MSGraphJsonContext.Default.AssignmentPayload);

			using StringContent content = new(jsonPayload, Encoding.UTF8, "application/json");

			// Send the POST request to assign the policy to the group.
			HttpResponseMessage response = await httpClient.PostAsync(
				new Uri($"{DeviceConfigurationsURL.OriginalString}/{policyId}/assignments"),
				content
			);

			// Process the response for the current group.
			if (response.IsSuccessStatusCode)
			{
				string responseContent = await response.Content.ReadAsStringAsync();
				Logger.Write($"Policy assigned successfully to group: {groupId}");
				Logger.Write(responseContent);
			}
			else
			{
				string errorContent = await response.Content.ReadAsStringAsync();
				Logger.Write($"Failed to assign policy to group: {groupId}. Status code: {response.StatusCode}");
				throw new InvalidOperationException($"Error details for group {groupId}: {errorContent}");
			}
		}
	}



	/// <summary>
	/// https://learn.microsoft.com/en-us/mem/intune/configuration/custom-settings-windows-10
	/// </summary>
	/// <param name="accessToken"></param>
	/// <param name="policyData"></param>
	/// <param name="policyID"></param>
	/// <param name="policyName"></param>
	/// <param name="descriptionText"></param>
	/// <returns></returns>
	private static async Task<string?> CreateCustomIntunePolicy(string accessToken, string policyData, string? policyName, string policyID, string descriptionText)
	{

		string displayNameText = !string.IsNullOrWhiteSpace(policyName) ? $"{policyName} App Control Policy" : "App Control Policy";

		// Making sure the policy ID doesn't have the curly brackets
		// https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/deploy-appcontrol-policies-using-intune#deploy-custom-app-control-policies-on-windows-10-1903
		policyID = policyID.Trim('{', '}');

		// Create the policy object
		Windows10CustomConfiguration customPolicy = new(

			oDataType: "#microsoft.graph.windows10CustomConfiguration",
			displayName: displayNameText,
			description: descriptionText,
			omaSettings:
			[
				new OmaSettingBase64
				(
					oDataType: "microsoft.graph.omaSettingBase64",
					displayName: displayNameText,
					description: descriptionText,
					omaUri: $"./Vendor/MSFT/ApplicationControl/Policies/{policyID}/Policy",
					fileName: "Policy.bin",
					value: policyData
				)
			],
			platforms: ["windows10AndLater"]
		);

		// Serialize the policy object to JSON
		string jsonPayload = JsonSerializer.Serialize(customPolicy, MSGraphJsonContext.Default.Windows10CustomConfiguration);

		using SecHttpClient httpClient = new();

		// Set up the HTTP headers
		httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
		httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

		using StringContent content = new(jsonPayload, Encoding.UTF8, "application/json");

		// Send the POST request
		HttpResponseMessage response = await httpClient.PostAsync(
			DeviceConfigurationsURL,
			content
		);

		// Process the response
		if (response.IsSuccessStatusCode)
		{
			string responseContent = await response.Content.ReadAsStringAsync();
			Logger.Write("Custom policy created successfully:");
			Logger.Write(responseContent);

			// Extract the policy ID from the response
			JsonElement responseJson = JsonSerializer.Deserialize(responseContent, MSGraphJsonContext.Default.JsonElement);

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
		HttpResponseMessage response = await httpClient.GetAsync(DeviceConfigurationsURL);

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
					HttpResponseMessage assignmentsResponse = await httpClient.GetAsync(new Uri($"{DeviceConfigurationsURL.OriginalString}/{policyId}/assignments"));

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


	/// <summary>
	/// Retrieves the custom policies available in Intune
	/// </summary>
	/// <returns></returns>
	/// <exception cref="InvalidOperationException"></exception>
	internal static async Task<DeviceConfigurationPoliciesResponse?> RetrieveDeviceConfigurations(AuthenticatedAccounts account)
	{

		using SecHttpClient httpClient = new();

		// Set up the HTTP headers for the request.
		httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ((IRestrictedAuthenticatedAccounts)account).AuthResult.AccessToken);
		httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

		// Use GET instead of POST as the endpoint expects a GET request.
		HttpResponseMessage response = await httpClient.GetAsync(new Uri("https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations"));

		if (response.IsSuccessStatusCode)
		{
			string jsonResponse = await response.Content.ReadAsStringAsync();
			Logger.Write("Device configurations retrieved successfully.");

			// Deserialize the JSON response using the source-generated context.
			DeviceConfigurationPoliciesResponse? policies = JsonSerializer.Deserialize(
				jsonResponse, MSGraphJsonContext.Default.DeviceConfigurationPoliciesResponse);

			return policies;
		}
		else
		{
			Logger.Write($"Failed to retrieve device configurations. Status code: {response.StatusCode}");
			string errorContent = await response.Content.ReadAsStringAsync();
			throw new InvalidOperationException($"Error details: {errorContent}");
		}
	}


	/// <summary>
	/// Deletes a custom Intune policy identified by the given policy ID.
	/// </summary>
	/// <param name="policyId">The ID of the policy to delete.</param>
	/// <param name="account"></param>
	/// <returns>A task that represents the asynchronous delete operation.</returns>
	/// <exception cref="InvalidOperationException">Thrown when the user is not authenticated or the deletion fails.</exception>
	internal static async Task DeletePolicy(AuthenticatedAccounts? account, string policyId)
	{

		if (account is null)
			return;

		using SecHttpClient httpClient = new();

		// Set up the HTTP headers.
		httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ((IRestrictedAuthenticatedAccounts)account).AuthResult.AccessToken);
		httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

		// Construct the DELETE URL using the base DeviceConfigurationsURL.
		string deleteUrl = $"{DeviceConfigurationsURL.OriginalString}/{policyId}";

		// Send the DELETE request.
		HttpResponseMessage response = await httpClient.DeleteAsync(new Uri(deleteUrl));

		// Process the response.
		if (response.IsSuccessStatusCode)
		{
			Logger.Write($"Policy {policyId} deleted successfully.");
		}
		else
		{
			string errorContent = await response.Content.ReadAsStringAsync();
			throw new InvalidOperationException($"Failed to delete policy {policyId}. Status code: {response.StatusCode}. Error details: {errorContent}");
		}
	}

}
