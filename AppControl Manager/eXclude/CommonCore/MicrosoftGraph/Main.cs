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

using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
#if APP_CONTROL_MANAGER
using AppControlManager.SiPolicy;
#endif
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Broker;
using Microsoft.Identity.Client.Extensions.Msal;

namespace CommonCore.MicrosoftGraph;

internal static class Main
{

	/// <summary>
	/// For Microsoft Graph Command Line Tools
	/// </summary>
	private const string ClientId = "14d82eec-204b-4c2f-b7e8-296a70dab67e";

	/// <summary>
	/// Returns the base Graph URL for the specific Azure environment.
	/// </summary>
	private static string GetGraphBaseUrl(AzureCloudInstance environment) =>
		 environment == AzureCloudInstance.AzureUsGovernment ? "https://graph.microsoft.us" : "https://graph.microsoft.com";

	/// <summary>
	/// URL for Intune related operations
	/// </summary>
	private static Uri GetDeviceConfigurationsURL(AzureCloudInstance environment) => new($"{GetGraphBaseUrl(environment)}/v1.0/deviceManagement/deviceConfigurations");

	/// <summary>
	/// URL for Device Health Scripts
	/// </summary>
	private static Uri GetDeviceHealthScriptsURL(AzureCloudInstance environment) => new($"{GetGraphBaseUrl(environment)}/beta/deviceManagement/deviceHealthScripts");

	/// <summary>
	/// URL for M365 Groups
	/// </summary>
	private static Uri GetGroupsUrl(AzureCloudInstance environment) => new($"{GetGraphBaseUrl(environment)}/v1.0/groups");

	/// <summary>
	/// URL for Microsoft Defender for Endpoint Advanced Hunting queries
	/// </summary>
	private static Uri GetMDEAHUrl(AzureCloudInstance environment) => new($"{GetGraphBaseUrl(environment)}/v1.0/security/runHuntingQuery");

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

	#endregion

	/// <summary>
	/// Provides a thread-safe cache for storing instances of public client applications, keyed by sign-in method, Azure
	/// cloud environment, and whether local token caching is enabled.
	/// </summary>
	private static readonly ConcurrentDictionary<(SignInMethods, AzureCloudInstance, bool), IPublicClientApplication> AppCache = new();

	/// <summary>
	/// Provides a thread-safe cache for storing instances of MSAL cache helpers to ensure they can be unregistered properly.
	/// </summary>
	private static readonly ConcurrentDictionary<(SignInMethods, AzureCloudInstance, bool), MsalCacheHelper> CacheHelpers = new();

	private static readonly SemaphoreSlim AppCacheLock = new(1, 1);

	// Prevents file locking IOExceptions if metadata is read/written rapidly.
	private static readonly SemaphoreSlim MetadataFileLock = new(1, 1);

	// The location where token cache and metadata JSON files are saved to.
	private static readonly string TokenCacheDiskLocation = Directory.CreateDirectory(Path.Combine(Microsoft.Windows.Storage.ApplicationData.GetDefault().LocalCachePath, "CachedAuthTokens")).FullName;

	/// <summary>
	/// Lazily creates or gets an IPublicClientApplication configured for the specific Sign In Method and Azure Cloud Environment.
	/// Automatically sets up on-disk caching too if enabled.
	/// </summary>
	private static async Task<IPublicClientApplication> GetAppAsync(SignInMethods method, AzureCloudInstance environment, bool useCache)
	{
		(SignInMethods, AzureCloudInstance, bool) key = (method, environment, useCache);

		if (AppCache.TryGetValue(key, out IPublicClientApplication? cachedApp))
		{
			return cachedApp;
		}

		await AppCacheLock.WaitAsync();
		try
		{
			if (AppCache.TryGetValue(key, out cachedApp))
			{
				return cachedApp;
			}

			string authorityAudience = environment == AzureCloudInstance.AzureUsGovernment ? "organizations" : "common";

			IPublicClientApplication app = method == SignInMethods.WebAccountManager
				? PublicClientApplicationBuilder.Create(ClientId)
					.WithDefaultRedirectUri()
					.WithParentActivityOrWindow(GetWindowHandle)
					.WithLegacyCacheCompatibility(false)
					.WithBroker(OptionsForBroker)
					.WithAuthority(environment, authorityAudience)
					.Build()
				: PublicClientApplicationBuilder.Create(ClientId)
					.WithAuthority(environment, authorityAudience)
					.WithRedirectUri("http://localhost")
					.WithLegacyCacheCompatibility(false)
					.Build();

			if (useCache)
			{
				StorageCreationProperties storageProperties = new StorageCreationPropertiesBuilder($"msal_{method}_{environment}.cache", TokenCacheDiskLocation)
					.Build();

				// Setup cache helper securely bound to app instance
				MsalCacheHelper cacheHelper = await MsalCacheHelper.CreateAsync(storageProperties);
				cacheHelper.RegisterCache(app.UserTokenCache);

				_ = CacheHelpers.TryAdd(key, cacheHelper);
			}

			_ = AppCache.TryAdd(key, app);
			return app;
		}
		finally
		{
			_ = AppCacheLock.Release();
		}
	}

	/// <summary>
	/// The correlation between scopes and required permissions
	/// </summary>
	private static readonly Dictionary<AuthenticationContext, string[]> Scopes = new() {

		// Scopes required to create and assign device configurations for Intune
		// https://learn.microsoft.com/graph/permissions-reference
		{ AuthenticationContext.Intune, [
		"Group.ReadWrite.All", // For Groups enumeration, deletion and addition.
		"DeviceManagementConfiguration.ReadWrite.All", // For uploading and removing policies and scripts.
		"DeviceManagementScripts.ReadWrite.All" // AppLocker Managed Installer policy read/write
		]},

		// Scopes required to retrieve MDE Advanced Hunting results
		// https://learn.microsoft.com/graph/api/security-security-runhuntingquery
		{AuthenticationContext.MDEAdvancedHunting,  ["ThreatHunting.Read.All"]}

	};

	/// <summary>
	/// Helper method to retrieve a valid access token. It performs a proactive (10 minute) refresh using AcquireTokenSilent.
	/// Uses the account's recorded SignIn method to decide which IPublicClientApplication instance to use.
	/// If the access token is still sufficiently valid it is returned directly.
	/// Updates the stored AuthenticationResult upon successful silent refresh.
	/// Throws MsalUiRequiredException if user interaction is required (caller may trigger interactive sign-in).
	/// </summary>
	/// <param name="account">The authenticated account wrapper.</param>
	/// <param name="cancellationToken">Cancellation token.</param>
	/// <returns>Fresh or cached access token string.</returns>
	internal static async Task<string> GetValidAccessTokenAsync(AuthenticatedAccounts account, CancellationToken cancellationToken)
	{
		// Proactive refresh window to avoid near-expiry usage
		TimeSpan proactiveWindow = TimeSpan.FromMinutes(10);

		AuthenticationResult? currentResult = account.AuthResult;
		DateTimeOffset now = DateTimeOffset.UtcNow;

		// If token is sufficiently valid, return it immediately
		if (currentResult is not null && (currentResult.ExpiresOn - now > proactiveWindow))
		{
			return currentResult.AccessToken;
		}

		// Select correct application based on original sign-in method, environment, and cache policy
		IPublicClientApplication selectedApp = await GetAppAsync(account.MethodUsed, account.Environment, account.UseCache);

		// Perform silent acquisition using the original scopes for this authentication context
		AuthenticationResult refreshedResult = await selectedApp
			.AcquireTokenSilent(Scopes[account.AuthContext], account.Account)
			.ExecuteAsync(cancellationToken);

		// Update stored result so subsequent calls benefit
		account.AuthResult = refreshedResult;

		Logger.Write(string.Format(
			GlobalVars.GetStr("SuccessfullyRefreshedMSGraphTokenMsg"),
			account.Username));

		return refreshedResult.AccessToken;
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

		string? output = null;

		// Obtain a valid access token (silent refresh if needed)
		string accessToken = await GetValidAccessTokenAsync(account, CancellationToken.None);

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

		// Make the POST request
		using HttpResponseMessage response = await HTTPHandler.ExecuteHttpWithRetryAsync(
			"RunMDEAdvancedHuntingQuery",
			() =>
			{
				HttpRequestMessage request = new(HttpMethod.Post, GetMDEAHUrl(account.Environment));
				request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
				request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
				request.Content = new StringContent(jsonPayload, Encoding.UTF8, "application/json");
				return request;
			}
		);

		if (response.IsSuccessStatusCode)
		{
			output = await response.Content.ReadAsStringAsync();
			Logger.Write(GlobalVars.GetStr("MDEAdvancedHuntingQuerySuccessfulMessage"));

			return output;
		}
		else
		{
			Logger.Write(string.Format(
				GlobalVars.GetStr("FailedToRunMDEAdvancedHuntingQueryMessage"),
				response.StatusCode));

			string errorContent = await response.Content.ReadAsStringAsync();

			throw new InvalidOperationException(string.Format(
				GlobalVars.GetStr("ErrorDetailsMessage"),
				errorContent));
		}
	}


	/// <summary>
	/// Fetches the M365/Entra ID groups.
	/// </summary>
	/// <returns></returns>
	/// <exception cref="InvalidOperationException"></exception>
	internal static async Task<List<IntuneGroupItemListView>> FetchGroups(AuthenticatedAccounts account)
	{

		List<IntuneGroupItemListView> output = [];

		// Obtain a valid access token (silent refresh if needed)
		string accessToken = await GetValidAccessTokenAsync(account, CancellationToken.None);

		// Start with initial endpoint
		string? nextLink = GetGroupsUrl(account.Environment).ToString();

		while (!string.IsNullOrEmpty(nextLink))
		{
			using HttpResponseMessage response = await HTTPHandler.ExecuteHttpWithRetryAsync(
				"FetchGroups",
				() =>
				{
					HttpRequestMessage request = new(HttpMethod.Get, new Uri(nextLink));
					request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
					request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
					return request;
				}
			);

			if (response.IsSuccessStatusCode)
			{
				string content = await response.Content.ReadAsStringAsync();
				JsonElement root = JsonSerializer.Deserialize(content, MSGraphJsonContext.Default.JsonElement);

				if (root.TryGetProperty("value", out JsonElement groups))
				{
					foreach (JsonElement group in groups.EnumerateArray())
					{
						string? groupName = group.GetProperty("displayName").GetString();
						string? groupId = group.GetProperty("id").GetString();
						string? description = group.GetProperty("description").GetString();
						string? securityIdentifier = group.GetProperty("securityIdentifier").GetString();
						DateTime createdDateTime = group.GetProperty("createdDateTime").GetDateTime();

						if (!string.IsNullOrEmpty(groupName) && !string.IsNullOrEmpty(groupId))
						{
							output.Add(new IntuneGroupItemListView(
								groupName: groupName,
								groupID: groupId,
								description: description,
								securityIdentifier: securityIdentifier,
								createdDateTime: createdDateTime
							));
						}
					}
				}
				else
				{
					Logger.Write(GlobalVars.GetStr("NoGroupsFoundInResponseMessage"));
				}

				// Follow pagination if present
				nextLink = root.TryGetProperty("@odata.nextLink", out JsonElement nextLinkElement) ? nextLinkElement.GetString() : null;
			}
			else
			{
				Logger.Write(string.Format(
					GlobalVars.GetStr("FailedToFetchGroupsMessage"),
					response.StatusCode));

				string errorContent = await response.Content.ReadAsStringAsync();

				throw new InvalidOperationException(string.Format(
					GlobalVars.GetStr("ErrorDetailsMessage"),
					errorContent));
			}
		}

		Logger.Write(string.Format(
			GlobalVars.GetStr("SuccessfullyFetchedGroupsMessage"),
			output.Count));

		return output;
	}


	/// <summary>
	/// Signs into a tenant
	/// </summary>
	/// <returns></returns>
	internal static async Task<(bool, AuthenticatedAccounts?)> SignIn(
	AuthenticationContext context,
	SignInMethods signInMethod,
	AzureCloudInstance environment,
	CancellationToken cancellationToken)
	{
		AuthenticationResult? authResult = null;
		bool error = false;

		// Capture the specific user choice regarding cache at sign in time
		bool useCache = GlobalVars.Settings.CacheAuthenticationTokensLocally;

		AuthenticatedAccounts? newAccount = null;

		try
		{
			IPublicClientApplication app = await GetAppAsync(signInMethod, environment, useCache);

			switch (signInMethod)
			{
				case SignInMethods.WebBrowser:
					{
						// Perform the interactive token acquisition with the cancellation token
						authResult = await app.AcquireTokenInteractive(Scopes[context])
							.WithPrompt(Prompt.SelectAccount)
							.WithUseEmbeddedWebView(false)
							.ExecuteAsync(cancellationToken);

						break;
					}
				case SignInMethods.WebAccountManager:
					{
						authResult = await app.AcquireTokenInteractive(Scopes[context])
							.ExecuteAsync(cancellationToken);

						break;
					}
				default:
					throw new InvalidOperationException(
						GlobalVars.GetStr("InvalidSignInMethodUsedMessage"));
			}
		}
		catch (OperationCanceledException)
		{
			error = true;
			throw new OperationCanceledException(
				GlobalVars.GetStr("SignInOperationCanceledByCallerMessage"));
		}
		finally
		{
			// If successful, store the result in SavedAccounts
			if (!error && authResult is not null)
			{
				// Add the account that was successfully authenticated to the dictionary
				newAccount = new(
					accountIdentifier: authResult.Account.HomeAccountId.Identifier,
					username: authResult.Account.Username,
					tenantID: authResult.TenantId,
					permissions: string.Join(", ", Scopes[context]),
					authContext: context,
					authResult: authResult,
					account: authResult.Account,
					methodUsed: signInMethod, // Record the method used for future silent refresh
					environment: environment,
					useCache: useCache // Bind this sign in session strictly to this cache setting
				);

				AuthenticatedAccounts? possibleDuplicate =
					AuthenticationCompanion.AuthenticatedAccounts
						.FirstOrDefault(x =>
							string.Equals(authResult.Account.HomeAccountId.Identifier, x.AccountIdentifier, StringComparison.OrdinalIgnoreCase) &&
							string.Equals(authResult.Account.Username, x.Username, StringComparison.OrdinalIgnoreCase) &&
							string.Equals(authResult.TenantId, x.TenantID, StringComparison.OrdinalIgnoreCase) &&
							string.Equals(newAccount.Permissions, x.Permissions, StringComparison.OrdinalIgnoreCase) &&
							x.AuthContext == context &&
							x.Environment == environment
						);

				// Check if the account is already authenticated
				if (possibleDuplicate is not null)
				{
					Logger.Write(string.Format(
						GlobalVars.GetStr("DuplicateAccountReplacedMessage"),
						authResult.Account.Username));

					_ = AuthenticationCompanion.AuthenticatedAccounts.Remove(possibleDuplicate);
				}

				AuthenticationCompanion.AuthenticatedAccounts.Add(newAccount);
				await SaveAccountsMetadataAsync();
			}
		}

		return (!error, newAccount);
	}


	/// <summary>
	/// Signs out the user
	/// </summary>
	/// <returns></returns>
	internal static async Task SignOut(AuthenticatedAccounts account)
	{
		// Make sure we select the exact same instance used for token creation
		IPublicClientApplication app = await GetAppAsync(account.MethodUsed, account.Environment, account.UseCache);
		await app.RemoveAsync(account.Account);
		_ = AuthenticationCompanion.AuthenticatedAccounts.Remove(account);
		await SaveAccountsMetadataAsync();

		Logger.Write(string.Format(
			GlobalVars.GetStr("SignedOutAccountMessage"),
			account.Username));
	}

#if APP_CONTROL_MANAGER
	/// <summary>
	/// Gets a CIP file content as ReadOnlySpan<byte> and uploads it to Intune.
	/// </summary>
	/// <param name="account">The account whose authentication we use for upload.</param>
	/// <param name="policyObj">The policy to upload to Intune.</param>
	/// <param name="groupIds">ID(s) of the Intune group(s) to assign to the uploaded policy.</param>
	/// <param name="policyName">The name of the policy to upload.</param>
	/// <param name="descriptionText">A descriptive text for the policy we are uploading.</param>
	/// <param name="policyBytes">The actual policy's bytes that will be uploaded.</param>
	/// <returns></returns>
	/// <exception cref="InvalidOperationException"></exception>
	internal static async Task UploadPolicyToIntune(AuthenticatedAccounts account, byte[] policyBytes, SiPolicy policyObj, List<string> groupIds, string? policyName, string descriptionText)
	{
		// https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/deployment/deploy-appcontrol-policies-using-intune#deploy-app-control-policies-with-custom-oma-uri
		const int maxPolicySize = 350000;

		// Check the file size
		if (policyBytes.Length > maxPolicySize)
		{
			throw new InvalidOperationException(string.Format(
				GlobalVars.GetStr("CipPolicyFileSizeExceedsLimitMessage"),
				policyName,
				maxPolicySize,
				policyBytes.Length));
		}

		// Read the file and convert to Base64
		string base64String = Convert.ToBase64String(policyBytes);

		// Obtain a valid access token (silent refresh if needed)
		string accessToken = await GetValidAccessTokenAsync(account, CancellationToken.None);

		// Call Microsoft Graph API to create the custom policy
		string? intunePolicyId = await CreateCustomIntunePolicy(accessToken, base64String, policyName, policyObj.PolicyID, descriptionText, account.Environment);

		Logger.Write(string.Format(
			GlobalVars.GetStr("PolicyCreatedMessage"),
			intunePolicyId));

		if (groupIds.Count > 0 && intunePolicyId is not null)
		{
			await AssignIntunePolicyToGroup(intunePolicyId, accessToken, groupIds, account.Environment);
		}
	}
#endif

	/// <summary>
	/// Assigns a group to the created Intune policy for multiple groups.
	/// </summary>
	/// <param name="policyId">The ID of the policy to assign.</param>
	/// <param name="accessToken">The access token used for authentication.</param>
	/// <param name="groupIds">An enumerable collection of group IDs to which the policy will be assigned.</param>
	/// <returns>A task that represents the asynchronous assignment operation.</returns>
	/// <exception cref="InvalidOperationException">Thrown when the assignment fails for any of the groups.</exception>
	private static async Task AssignIntunePolicyToGroup(string policyId, string accessToken, IEnumerable<string> groupIds, AzureCloudInstance environment)
	{
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

			// Send the POST request to assign the policy to the group.
			using HttpResponseMessage response = await HTTPHandler.ExecuteHttpWithRetryAsync(
				"AssignIntunePolicyToGroup",
				() =>
				{
					HttpRequestMessage request = new(
						HttpMethod.Post,
						new Uri($"{GetDeviceConfigurationsURL(environment).OriginalString}/{policyId}/assignments"));

					request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
					request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
					request.Content = new StringContent(jsonPayload, Encoding.UTF8, "application/json");
					return request;
				}
			);

			// Process the response for the current group.
			if (response.IsSuccessStatusCode)
			{
				string responseContent = await response.Content.ReadAsStringAsync();
				Logger.Write(string.Format(
					GlobalVars.GetStr("PolicyAssignedSuccessfullyToGroupMessage"),
					groupId));
				Logger.Write(responseContent);
			}
			else
			{
				string errorContent = await response.Content.ReadAsStringAsync();

				Logger.Write(string.Format(
					GlobalVars.GetStr("FailedToAssignPolicyToGroupMessage"),
					groupId,
					response.StatusCode));

				throw new InvalidOperationException(string.Format(
					GlobalVars.GetStr("ErrorDetailsForGroupMessage"),
					groupId,
					errorContent));
			}
		}
	}


	/// <summary>
	/// https://learn.microsoft.com/mem/intune/configuration/custom-settings-windows-10
	/// </summary>
	/// <param name="accessToken"></param>
	/// <param name="policyData"></param>
	/// <param name="policyID"></param>
	/// <param name="policyName"></param>
	/// <param name="descriptionText"></param>
	/// <returns></returns>
	private static async Task<string?> CreateCustomIntunePolicy(string accessToken, string policyData, string? policyName, string policyID, string descriptionText, AzureCloudInstance environment)
	{

		string displayNameText = !string.IsNullOrWhiteSpace(policyName) ? $"{policyName} App Control Policy" : "App Control Policy";

		// Making sure the policy ID doesn't have the curly brackets
		// https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/deployment/deploy-appcontrol-policies-using-intune#deploy-custom-app-control-policies-on-windows-10-1903
		policyID = policyID.Trim('{', '}');

		// Create the policy object
		Windows10CustomConfiguration customPolicy = new(

			oDataType: "#microsoft.graph.windows10CustomConfiguration",
			displayName: displayNameText,
			description: descriptionText,
			id: null, // Automatically set by Intune
			createdDateTime: null, // Automatically set by Intune
			lastModifiedDateTime: null, // Automatically set by Intune
			roleScopeTagIds: null,  // Automatically set by Intune
			supportsScopeTags: true,
			version: 1,
			omaSettings:
			[
				new OmaSettingBase64
				(
					oDataType: "#microsoft.graph.omaSettingBase64",
					displayName: displayNameText,
					description: descriptionText,
					omaUri: $"./Vendor/MSFT/ApplicationControl/Policies/{policyID}/Policy",
					fileName: "Policy.bin",
					value: policyData
				)
			]
		);

		// Serialize the policy object to JSON
		string jsonPayload = JsonSerializer.Serialize(customPolicy, MSGraphJsonContext.Default.Windows10CustomConfiguration);

		// Send the POST request
		using HttpResponseMessage response = await HTTPHandler.ExecuteHttpWithRetryAsync(
			"CreateCustomIntunePolicy",
			() =>
			{
				HttpRequestMessage request = new(HttpMethod.Post, GetDeviceConfigurationsURL(environment));
				request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
				request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
				request.Content = new StringContent(jsonPayload, Encoding.UTF8, "application/json");
				return request;
			}
		);

		// Process the response
		if (response.IsSuccessStatusCode)
		{
			string responseContent = await response.Content.ReadAsStringAsync();
			Logger.Write(GlobalVars.GetStr("CustomPolicyCreatedSuccessMessage"));
			Logger.Write(responseContent);

			// Extract the policy ID from the response
			JsonElement responseJson = JsonSerializer.Deserialize(responseContent, MSGraphJsonContext.Default.JsonElement);

			return responseJson.GetProperty("id").GetString();
		}
		else
		{
			Logger.Write(string.Format(
				GlobalVars.GetStr("FailedToCreateCustomPolicyMessage"),
				response.StatusCode));

			string errorContent = await response.Content.ReadAsStringAsync();

			throw new InvalidOperationException(string.Format(
				GlobalVars.GetStr("ErrorDetailsMessage"),
				errorContent));
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
	/// Retrieves the custom policies available in Intune
	/// </summary>
	/// <returns></returns>
	/// <exception cref="InvalidOperationException"></exception>
	internal static async Task<DeviceConfigurationPoliciesResponse?> RetrieveDeviceConfigurations(AuthenticatedAccounts account)
	{

		// Obtain a valid access token (silent refresh if needed)
		string accessToken = await GetValidAccessTokenAsync(account, CancellationToken.None);

		// Initial request URL.
		// Applying a filter to retrieve only the policies for Windows custom configurations
		string nextLink = $"{GetGraphBaseUrl(account.Environment)}/beta/deviceManagement/deviceConfigurations?$filter=isof('microsoft.graph.windows10CustomConfiguration')";

		// Accumulators for all pages.
		List<Windows10CustomConfiguration> allPolicies = [];

		// Capture these from the first successful page (if present).
		string? oDataContext = null;
		string? msGraphTips = null;

		while (!string.IsNullOrEmpty(nextLink))
		{
			using HttpResponseMessage response = await HTTPHandler.ExecuteHttpWithRetryAsync(
				"RetrieveDeviceConfigurations",
				() =>
				{
					HttpRequestMessage request = new(HttpMethod.Get, new Uri(nextLink));
					request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
					request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
					return request;
				}
			);

			if (!response.IsSuccessStatusCode)
			{
				Logger.Write(string.Format(
					GlobalVars.GetStr("FailedToRetrieveDeviceConfigurationsMessage"),
					response.StatusCode));

				string errorContentFailed = await response.Content.ReadAsStringAsync();

				throw new InvalidOperationException(string.Format(
					GlobalVars.GetStr("ErrorDetailsMessage"),
					errorContentFailed));
			}

			string jsonResponse = await response.Content.ReadAsStringAsync();

			JsonElement root;
			DeviceConfigurationPoliciesResponse? page;

			try
			{
				// Root element for pagination handling.
				root = JsonSerializer.Deserialize(
					jsonResponse,
					MSGraphJsonContext.Default.JsonElement);

				// Deserialize the page into the existing strongly typed response model to reuse mapping.
				page = JsonSerializer.Deserialize(
						jsonResponse,
						MSGraphJsonContext.Default.DeviceConfigurationPoliciesResponse);
			}
			catch
			{
				Logger.Write($"Failed to deserialize the following JSON response: {jsonResponse}");
				throw;
			}

			// Capture context / tips only once (from first page that provides them).
			if (oDataContext is null && root.TryGetProperty("@odata.context", out JsonElement ctxEl))
			{
				oDataContext = ctxEl.GetString();
			}
			if (msGraphTips is null && root.TryGetProperty("@microsoft.graph.tips", out JsonElement tipsEl))
			{
				msGraphTips = tipsEl.GetString();
			}

			// Aggregate page policies.
			if (page?.Value is not null && page.Value.Count > 0)
			{
				allPolicies.AddRange(page.Value);
			}

			// Determine if there is another page.
			nextLink = root.TryGetProperty("@odata.nextLink", out JsonElement nextLinkElement)
				? nextLinkElement.GetString() ?? string.Empty
				: string.Empty;
		}

		// Log after all pages processed.
		Logger.Write(GlobalVars.GetStr("DeviceConfigurationsRetrievedSuccessfullyMessage"));

		// Return aggregated response.
		return new DeviceConfigurationPoliciesResponse(
			oDataContext,
			msGraphTips,
			allPolicies);
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

		// Obtain a valid access token (silent refresh if needed)
		string accessToken = await GetValidAccessTokenAsync(account, CancellationToken.None);

		// Construct the DELETE URL using the base DeviceConfigurationsURL.
		string deleteUrl = $"{GetDeviceConfigurationsURL(account.Environment).OriginalString}/{policyId}";

		// Send the DELETE request.
		using HttpResponseMessage response = await HTTPHandler.ExecuteHttpWithRetryAsync(
			"DeletePolicy",
			() =>
			{
				HttpRequestMessage request = new(HttpMethod.Delete, new Uri(deleteUrl));
				request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
				request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
				return request;
			}
		);

		// Process the response.
		if (response.IsSuccessStatusCode)
		{
			Logger.Write(string.Format(
				GlobalVars.GetStr("PolicyDeletedSuccessfullyMessage"),
				policyId));
		}
		else
		{
			string errorContent = await response.Content.ReadAsStringAsync();
			throw new InvalidOperationException(string.Format(
				GlobalVars.GetStr("FailedToDeletePolicyExceptionMessage"),
				policyId,
				response.StatusCode,
				errorContent));
		}
	}

	/// <summary>
	/// Creates a new group (Security or Microsoft 365 Unified) in Microsoft Entra via Microsoft Graph.
	/// </summary>
	/// <param name="account">The authenticated account context.</param>
	/// <param name="displayName">Display name of the group (required).</param>
	/// <param name="description">Optional description.</param>
	/// <param name="unifiedGroup">
	/// If true, creates a Microsoft 365 (Unified) group.
	/// If false, creates a Security group.
	/// </param>
	/// <returns></returns>
	/// <exception cref="ArgumentException">Thrown if displayName is null or empty.</exception>
	/// <exception cref="InvalidOperationException">Thrown if Graph returns a failure.</exception>
	internal static async Task CreateGroup(
		AuthenticatedAccounts account,
		string displayName,
		string? description,
		bool unifiedGroup)
	{

		if (string.IsNullOrWhiteSpace(displayName))
		{
			throw new ArgumentException(GlobalVars.GetStr("GroupDisplayNameEmptyError"), nameof(displayName));
		}

		// Obtain a valid access token (silent refresh if needed)
		string accessToken = await GetValidAccessTokenAsync(account, CancellationToken.None);

		// mailNickname is required by Graph for group creation. Sanitize it.
		string mailNickname = new(displayName.Where(char.IsLetterOrDigit).ToArray());

		if (string.IsNullOrWhiteSpace(mailNickname))
		{
			// Fallback if everything was stripped
			mailNickname = "Group" + Guid.NewGuid().ToString("N")[..8];
		}

		// Prepare payload according to group type.
		// Security group: mailEnabled = false, securityEnabled = true, groupTypes = []
		// Unified (M365) group: mailEnabled = true, securityEnabled = false, groupTypes = ["Unified"]
		Group payload = new(
			displayName: displayName,
			description: string.IsNullOrWhiteSpace(description) ? null : description,
			mailEnabled: unifiedGroup,
			mailNickname: mailNickname,
			securityEnabled: !unifiedGroup,
			groupTypes: unifiedGroup ? ["Unified"] : []
		);

		string jsonPayload = JsonSerializer.Serialize(
			payload,
			MSGraphJsonContext.Default.Group);

		using HttpResponseMessage response = await HTTPHandler.ExecuteHttpWithRetryAsync(
			"CreateGroup",
			() =>
			{
				HttpRequestMessage request = new(HttpMethod.Post, GetGroupsUrl(account.Environment));
				request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
				request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
				request.Content = new StringContent(jsonPayload, Encoding.UTF8, "application/json");
				return request;
			}
		);

		if (response.IsSuccessStatusCode)
		{
			string content = await response.Content.ReadAsStringAsync();

			JsonElement groupJson = JsonSerializer.Deserialize(content, MSGraphJsonContext.Default.JsonElement);

			// Get the details of the newly created group for logging.
			string? id = groupJson.GetProperty("id").GetString();
			string? dn = groupJson.GetProperty("displayName").GetString();
			string? desc = groupJson.TryGetProperty("description", out JsonElement dEl) ? dEl.GetString() : null;
			string? secId = groupJson.TryGetProperty("securityIdentifier", out JsonElement sidEl) ? sidEl.GetString() : null;
			DateTime created = groupJson.TryGetProperty("createdDateTime", out JsonElement cdtEl)
				? cdtEl.GetDateTime() : DateTime.UtcNow;

			Logger.Write(string.Format(
				GlobalVars.GetStr("SuccessfullyCreatedGroupMessage"),
				dn,
				desc,
				id,
				secId,
				created));
		}
		else
		{
			string errorContent = await response.Content.ReadAsStringAsync();

			Logger.Write(string.Format(
				GlobalVars.GetStr("FailedCreatingGroupError"),
				response.StatusCode,
				errorContent));

			throw new InvalidOperationException(errorContent);
		}
	}

	/// <summary>
	/// Deletes a Microsoft Entra group by its ID.
	/// </summary>
	/// <param name="account">Authenticated account context.</param>
	/// <param name="groupId">Target group ID.</param>
	/// <returns></returns>
	/// <exception cref="InvalidOperationException"></exception>
	internal static async Task DeleteGroup(AuthenticatedAccounts? account, string groupId)
	{
		if (account is null)
		{
			return;
		}
		if (string.IsNullOrWhiteSpace(groupId))
		{
			throw new ArgumentException("groupId is null or empty", nameof(groupId));
		}

		// Obtain a valid access token (silent refresh if needed)
		string accessToken = await GetValidAccessTokenAsync(account, CancellationToken.None);

		Uri deleteUri = new($"{GetGroupsUrl(account.Environment)}/{groupId}");

		using HttpResponseMessage response = await HTTPHandler.ExecuteHttpWithRetryAsync(
			"DeleteGroup",
			() =>
			{
				HttpRequestMessage request = new(HttpMethod.Delete, deleteUri);
				request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
				request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
				return request;
			}
		);

		if (response.IsSuccessStatusCode)
		{
			Logger.Write($"Deleted group {groupId}");
			return;
		}
		else
		{
			string errorContent = await response.Content.ReadAsStringAsync();
			Logger.Write($"Failed to delete group {groupId} - {response.StatusCode}");
			throw new InvalidOperationException(errorContent);
		}
	}

	/// <summary>
	/// Get all of the non-Custom-OMAURI policies.
	/// </summary>
	/// <param name="account"></param>
	/// <returns></returns>
	/// <exception cref="InvalidOperationException"></exception>
	internal static async Task<List<DeviceManagementConfigurationPolicy>> RetrieveConfigurationPolicies(AuthenticatedAccounts account)
	{
		List<DeviceManagementConfigurationPolicy> allPolicies = [];

		// Obtain a valid access token (silent refresh if needed)
		string accessToken = await GetValidAccessTokenAsync(account, CancellationToken.None);

		// Beta endpoint for configuration policies (standard, non-custom).
		string nextLink = $"{GetGraphBaseUrl(account.Environment)}/beta/deviceManagement/configurationPolicies";

		while (!string.IsNullOrEmpty(nextLink))
		{
			using HttpResponseMessage response = await HTTPHandler.ExecuteHttpWithRetryAsync(
				"RetrieveConfigurationPolicies",
				() =>
				{
					HttpRequestMessage request = new(HttpMethod.Get, new Uri(nextLink));
					request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
					request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
					return request;
				}
			);

			if (!response.IsSuccessStatusCode)
			{
				string errorContent = await response.Content.ReadAsStringAsync();
				Logger.Write(string.Format(
					GlobalVars.GetStr("FailedToRetrieveDeviceConfigurationsMessage"),
					response.StatusCode));
				throw new InvalidOperationException(string.Format(
					GlobalVars.GetStr("ErrorDetailsMessage"),
					errorContent));
			}

			string jsonResponse = await response.Content.ReadAsStringAsync();

			JsonElement root = JsonSerializer.Deserialize(
				jsonResponse,
				MSGraphJsonContext.Default.JsonElement);

			DeviceManagementConfigurationPoliciesResponse? page = JsonSerializer.Deserialize(
				jsonResponse,
				MSGraphJsonContext.Default.DeviceManagementConfigurationPoliciesResponse);

			if (page?.Value is not null && page.Value.Count > 0)
			{
				allPolicies.AddRange(page.Value);
			}

			nextLink = root.TryGetProperty("@odata.nextLink", out JsonElement nextLinkElement)
				? nextLinkElement.GetString() ?? string.Empty
				: string.Empty;
		}

		Logger.Write(GlobalVars.GetStr("DeviceConfigurationsRetrievedSuccessfullyMessage"));
		return allPolicies;
	}


	/// <summary>
	/// Creates an Intune configuration policy from a JSON file.
	/// </summary>
	/// <param name="account"></param>
	/// <param name="jsonFilePath"></param>
	/// <returns></returns>
	/// <exception cref="ArgumentException"></exception>
	/// <exception cref="InvalidOperationException"></exception>
	internal static async Task<string?> CreateConfigurationPolicyFromJson(AuthenticatedAccounts account, string jsonFilePath)
	{
		if (account is null)
			return null;

		if (string.IsNullOrEmpty(jsonFilePath) || !File.Exists(jsonFilePath))
		{
			throw new ArgumentException("Policy JSON file path is invalid or does not exist.", nameof(jsonFilePath));
		}

		// Read JSON payload from disk (as-is). We post it directly to Graph.
		string jsonPayload = await File.ReadAllTextAsync(jsonFilePath);

		// Obtain a valid access token (silent refresh if needed)
		string accessToken = await GetValidAccessTokenAsync(account, CancellationToken.None);

		// Beta endpoint for creating configuration policies.
		Uri createUri = new($"{GetGraphBaseUrl(account.Environment)}/beta/deviceManagement/configurationPolicies");

		using HttpResponseMessage response = await HTTPHandler.ExecuteHttpWithRetryAsync(
			"CreateConfigurationPolicyFromJson",
			() =>
			{
				HttpRequestMessage request = new(HttpMethod.Post, createUri);
				request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
				request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
				request.Content = new StringContent(jsonPayload, Encoding.UTF8, "application/json");
				return request;
			}
		);

		string responseContent = await response.Content.ReadAsStringAsync();

		if (response.IsSuccessStatusCode)
		{
			Logger.Write(GlobalVars.GetStr("CustomPolicyCreatedSuccessMessage"));
			Logger.Write(responseContent);

			// Extract ID from response
			JsonElement root = JsonSerializer.Deserialize(
				responseContent,
				MSGraphJsonContext.Default.JsonElement);

			string? id = root.TryGetProperty("id", out JsonElement idEl) ? idEl.GetString() : null;
			return id;
		}
		else
		{
			Logger.Write(string.Format(
				GlobalVars.GetStr("FailedToCreateCustomPolicyMessage"),
				response.StatusCode));

			throw new InvalidOperationException(string.Format(
				GlobalVars.GetStr("ErrorDetailsMessage"),
				responseContent));
		}

	}

	/// <summary>
	/// Assigns a configuration policy to multiple Entra ID groups.
	/// Endpoint: POST /beta/deviceManagement/configurationPolicies/{id}/assign
	/// </summary>
	/// <param name="account">Authenticated account.</param>
	/// <param name="policyId">Configuration policy ID.</param>
	/// <param name="groupIds">Group IDs to assign to.</param>
	internal static async Task AssignConfigurationPolicyToGroups(AuthenticatedAccounts account, string policyId, List<string> groupIds)
	{
		// Obtain a valid access token (silent refresh if needed)
		string accessToken = await GetValidAccessTokenAsync(account, CancellationToken.None);

		// Build the assignments payload using strongly-typed envelope.
		List<AssignmentPayload> assignments = new();

		foreach (string gid in CollectionsMarshal.AsSpan(groupIds))
		{
			Dictionary<string, object> target = new()
			{
				{ "@odata.type", "#microsoft.graph.groupAssignmentTarget" },
				{ "groupId", gid }
			};

			assignments.Add(new AssignmentPayload(target));
		}

		ConfigurationPolicyAssignmentsEnvelope envelope = new(assignments);

		// Serialize using the source-generated context
		string jsonPayload = JsonSerializer.Serialize(
			envelope,
			MSGraphJsonContext.Default.ConfigurationPolicyAssignmentsEnvelope);

		Uri assignUri = new($"{GetGraphBaseUrl(account.Environment)}/beta/deviceManagement/configurationPolicies/{policyId}/assign");

		using HttpResponseMessage response = await HTTPHandler.ExecuteHttpWithRetryAsync(
			"AssignConfigurationPolicyToGroups",
			() =>
			{
				HttpRequestMessage request = new(HttpMethod.Post, assignUri);
				request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
				request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
				request.Content = new StringContent(jsonPayload, Encoding.UTF8, "application/json");
				return request;
			}
		);

		string responseContent = await response.Content.ReadAsStringAsync();

		if (response.IsSuccessStatusCode)
		{
			Logger.Write($"Assigned configuration policy {policyId} to {groupIds.Count} groups.");
			Logger.Write(responseContent);
		}
		else
		{
			Logger.Write($"Failed to assign configuration policy {policyId} - {response.StatusCode}");
			throw new InvalidOperationException(string.Format(
				GlobalVars.GetStr("ErrorDetailsMessage"),
				responseContent));
		}
	}

	/// <summary>
	/// Deletes a configuration policy by ID.
	/// Endpoint: DELETE /beta/deviceManagement/configurationPolicies/{id}
	/// </summary>
	/// <param name="account">Authenticated account.</param>
	/// <param name="policyId">Policy ID to delete.</param>
	internal static async Task DeleteConfigurationPolicy(AuthenticatedAccounts account, string policyId)
	{
		// Obtain a valid access token (silent refresh if needed)
		string accessToken = await GetValidAccessTokenAsync(account, CancellationToken.None);

		Uri deleteUri = new($"{GetGraphBaseUrl(account.Environment)}/beta/deviceManagement/configurationPolicies/{policyId}");

		using HttpResponseMessage response = await HTTPHandler.ExecuteHttpWithRetryAsync(
			"DeleteConfigurationPolicy",
			() =>
			{
				HttpRequestMessage request = new(HttpMethod.Delete, deleteUri);
				request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
				request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
				return request;
			}
		);

		if (response.IsSuccessStatusCode)
		{
			Logger.Write($"Deleted configuration policy {policyId}");
		}
		else
		{
			string errorContent = await response.Content.ReadAsStringAsync();
			Logger.Write($"Failed to delete configuration policy {policyId} - {response.StatusCode}");
			throw new InvalidOperationException(string.Format(
				GlobalVars.GetStr("ErrorDetailsMessage"),
				errorContent));
		}
	}

	/// <summary>
	/// Retrieves Device Health Scripts (for Managed Installer policies).
	/// </summary>
	/// <param name="account"></param>
	/// <returns></returns>
	internal static async Task<List<DeviceHealthScript>> RetrieveDeviceHealthScripts(AuthenticatedAccounts account)
	{
		List<DeviceHealthScript> allScripts = [];

		// Obtain a valid access token (silent refresh if needed)
		string accessToken = await GetValidAccessTokenAsync(account, CancellationToken.None);

		// Filter for Managed Installer scripts
		string nextLink = $"{GetDeviceHealthScriptsURL(account.Environment).OriginalString}?$filter=deviceHealthScriptType eq 'managedInstallerScript'";

		while (!string.IsNullOrEmpty(nextLink))
		{
			using HttpResponseMessage response = await HTTPHandler.ExecuteHttpWithRetryAsync(
				"RetrieveDeviceHealthScripts",
				() =>
				{
					HttpRequestMessage request = new(HttpMethod.Get, new Uri(nextLink));
					request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
					request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
					return request;
				}
			);

			if (!response.IsSuccessStatusCode)
			{
				string errorContent = await response.Content.ReadAsStringAsync();
				Logger.Write(string.Format(
					GlobalVars.GetStr("FailedToRetrieveDeviceConfigurationsMessage"),
					response.StatusCode));
				throw new InvalidOperationException(string.Format(
					GlobalVars.GetStr("ErrorDetailsMessage"),
					errorContent));
			}

			string jsonResponse = await response.Content.ReadAsStringAsync();

			// Parse response
			JsonElement root = JsonSerializer.Deserialize(jsonResponse, MSGraphJsonContext.Default.JsonElement);
			DeviceHealthScriptsResponse? page = JsonSerializer.Deserialize(jsonResponse, MSGraphJsonContext.Default.DeviceHealthScriptsResponse);

			if (page?.Value is not null)
			{
				allScripts.AddRange(page.Value);
			}

			nextLink = root.TryGetProperty("@odata.nextLink", out JsonElement nextLinkElement)
				? nextLinkElement.GetString() ?? string.Empty
				: string.Empty;
		}

		return allScripts;
	}

	/// <summary>
	/// Creates the specific Managed Installer policy/script in Intune.
	/// </summary>
	/// <param name="account"></param>
	/// <returns>The ID of the created policy</returns>
	internal static async Task<string?> CreateManagedInstallerPolicy(AuthenticatedAccounts account)
	{
		if (account is null) return null;

		string accessToken = await GetValidAccessTokenAsync(account, CancellationToken.None);

		// Create the payload for the Managed Installer policy
		DeviceHealthScript payload = new()
		{
			DeviceHealthScriptType = "managedInstallerScript",
			DisplayName = "Managed Installer Policy",
			Description = "Enables or disables Intune Management Extensions as the Managed Installer on the targeted devices. Deployed by the AppControl Manager.",
			RunAsAccount = "system",
			EnforceSignatureCheck = true,
			Publisher = "AppControl Manager",
			RunAs32Bit = true,
			DetectionScriptParameters =
			[
				new DeviceHealthScriptStringParameter
				{
					Name = "Enabled",
					Description = "Enable Managed Installer. Deployed by the AppControl Manager.",
					IsRequired = true,
					ApplyDefaultValueWhenNotAssigned = true,
					DefaultValue = "True"
				}
			]
		};

		string jsonPayload = JsonSerializer.Serialize(payload, MSGraphJsonContext.Default.DeviceHealthScript);

		using HttpResponseMessage response = await HTTPHandler.ExecuteHttpWithRetryAsync(
			"CreateManagedInstallerPolicy",
			() =>
			{
				HttpRequestMessage request = new(HttpMethod.Post, GetDeviceHealthScriptsURL(account.Environment));
				request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
				request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
				request.Content = new StringContent(jsonPayload, Encoding.UTF8, "application/json");
				return request;
			}
		);

		string responseContent = await response.Content.ReadAsStringAsync();

		if (response.IsSuccessStatusCode)
		{
			Logger.Write("Managed Installer Policy created successfully.");
			JsonElement root = JsonSerializer.Deserialize(responseContent, MSGraphJsonContext.Default.JsonElement);
			return root.TryGetProperty("id", out JsonElement idEl) ? idEl.GetString() : null;
		}
		else
		{
			Logger.Write($"Failed to create Managed Installer Policy: {response.StatusCode}");
			throw new InvalidOperationException($"Error details: {responseContent}");
		}
	}

	/// <summary>
	/// Deletes a Managed Installer policy (device health script).
	/// </summary>
	/// <param name="account"></param>
	/// <param name="policyId"></param>
	internal static async Task DeleteManagedInstallerPolicy(AuthenticatedAccounts? account, string policyId)
	{
		if (account is null) return;

		string accessToken = await GetValidAccessTokenAsync(account, CancellationToken.None);

		Uri deleteUri = new($"{GetDeviceHealthScriptsURL(account.Environment).OriginalString}/{policyId}");

		using HttpResponseMessage response = await HTTPHandler.ExecuteHttpWithRetryAsync(
			"DeleteManagedInstallerPolicy",
			() =>
			{
				HttpRequestMessage request = new(HttpMethod.Delete, deleteUri);
				request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
				request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
				return request;
			}
		);

		if (response.IsSuccessStatusCode)
		{
			Logger.Write($"Deleted managed installer policy {policyId}");
		}
		else
		{
			string errorContent = await response.Content.ReadAsStringAsync();
			throw new InvalidOperationException($"Failed to delete policy {policyId}: {response.StatusCode} - {errorContent}");
		}
	}

	/// <summary>
	/// Retrieves assignments for a given policy and resolves Group IDs to Names.
	/// </summary>
	internal static async Task<List<PolicyAssignmentDisplay>> GetPolicyAssignments(AuthenticatedAccounts account, string policyId, bool isManagedInstaller)
	{
		string accessToken = await GetValidAccessTokenAsync(account, CancellationToken.None);
		string assignmentsUrl = isManagedInstaller
			? $"{GetDeviceHealthScriptsURL(account.Environment).OriginalString}/{policyId}/assignments"
			: $"{GetDeviceConfigurationsURL(account.Environment).OriginalString}/{policyId}/assignments";

		List<PolicyAssignmentDisplay> results = [];

		using HttpResponseMessage response = await HTTPHandler.ExecuteHttpWithRetryAsync(
			"GetPolicyAssignments",
			() =>
			{
				HttpRequestMessage request = new(HttpMethod.Get, new Uri(assignmentsUrl));
				request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
				request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
				return request;
			}
		);

		if (!response.IsSuccessStatusCode)
		{
			string err = await response.Content.ReadAsStringAsync();
			throw new InvalidOperationException($"Failed to fetch assignments: {response.StatusCode} - {err}");
		}

		string content = await response.Content.ReadAsStringAsync();
		PolicyAssignmentResponse? data = JsonSerializer.Deserialize(content, MSGraphJsonContext.Default.PolicyAssignmentResponse);

		if (data?.Value is null) return results;

		List<Task<PolicyAssignmentDisplay?>> tasks = [];

		foreach (PolicyAssignmentObject item in data.Value)
		{
			if (item.Target is null) continue;

			// item.Id is the Assignment Object ID required for deletion
			string? assignmentId = item.Id;

			string? oType = item.Target.ODataType;

			if (string.Equals(oType, "#microsoft.graph.allLicensedUsersAssignmentTarget", StringComparison.OrdinalIgnoreCase))
			{
				results.Add(new PolicyAssignmentDisplay("All Users", "Virtual Group", null, assignmentId));
			}
			else if (string.Equals(oType, "#microsoft.graph.allDevicesAssignmentTarget", StringComparison.OrdinalIgnoreCase))
			{
				results.Add(new PolicyAssignmentDisplay("All Devices", "Virtual Group", null, assignmentId));
			}
			else if (string.Equals(oType, "#microsoft.graph.groupAssignmentTarget", StringComparison.OrdinalIgnoreCase))
			{
				string? gid = item.Target.GroupId;
				if (!string.IsNullOrEmpty(gid))
				{
					// Resolve group name in parallel
					tasks.Add(GetGroupDisplayInfo(accessToken, gid, assignmentId, account.Environment));
				}
			}
			else
			{
				// Fallback for other types
				results.Add(new PolicyAssignmentDisplay("Unknown Target", oType ?? "Unknown", null, assignmentId));
			}
		}

		// Wait for all group lookups
		PolicyAssignmentDisplay?[] groupResults = await Task.WhenAll(tasks);
		foreach (PolicyAssignmentDisplay? res in groupResults)
		{
			if (res is not null) results.Add(res);
		}

		return results;
	}

	/// <summary>
	/// Helper to get a group's display name by ID.
	/// </summary>
	private static async Task<PolicyAssignmentDisplay?> GetGroupDisplayInfo(string accessToken, string groupId, string? assignmentId, AzureCloudInstance environment)
	{
		try
		{
			using HttpResponseMessage response = await HTTPHandler.ExecuteHttpWithRetryAsync(
				"GetGroupDisplayInfo",
				() =>
				{
					HttpRequestMessage request = new(HttpMethod.Get, new Uri($"{GetGroupsUrl(environment)}/{groupId}?$select=displayName,description"));
					request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
					request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
					return request;
				}
			);

			if (response.IsSuccessStatusCode)
			{
				string content = await response.Content.ReadAsStringAsync();
				using JsonDocument doc = JsonDocument.Parse(content);
				JsonElement root = doc.RootElement;
				string displayName = root.TryGetProperty("displayName", out JsonElement dn) ? dn.GetString() ?? "Unknown Group" : "Unknown Group";
				return new PolicyAssignmentDisplay(displayName, "Group", groupId, assignmentId);
			}
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
		return new PolicyAssignmentDisplay(groupId, "Group (ID Only)", groupId, assignmentId);
	}

	/// <summary>
	/// Deletes a specific assignment for a policy.
	/// </summary>
	/// <param name="account">Authenticated account.</param>
	/// <param name="policyId">The ID of the policy (Device Configuration ID or Device Health Script ID).</param>
	/// <param name="assignmentId">The ID of the assignment to delete.</param>
	/// <param name="isManagedInstaller">Whether the policy is a Managed Installer (different endpoint).</param>
	internal static async Task DeletePolicyAssignment(AuthenticatedAccounts account, string policyId, string assignmentId, bool isManagedInstaller)
	{
		string accessToken = await GetValidAccessTokenAsync(account, CancellationToken.None);

		// Construct URL based on policy type
		string deleteUrl = isManagedInstaller
			? $"{GetDeviceHealthScriptsURL(account.Environment).OriginalString}/{policyId}/assignments/{assignmentId}"
			: $"{GetDeviceConfigurationsURL(account.Environment).OriginalString}/{policyId}/assignments/{assignmentId}";

		using HttpResponseMessage response = await HTTPHandler.ExecuteHttpWithRetryAsync(
			"DeletePolicyAssignment",
			() =>
			{
				HttpRequestMessage request = new(HttpMethod.Delete, new Uri(deleteUrl));
				request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
				request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
				return request;
			}
		);

		if (response.IsSuccessStatusCode)
		{
			Logger.Write($"Successfully deleted assignment {assignmentId} from policy {policyId}");
		}
		else
		{
			string errorContent = await response.Content.ReadAsStringAsync();
			throw new InvalidOperationException($"Failed to delete assignment {assignmentId}: {response.StatusCode} - {errorContent}");
		}
	}

	/// <summary>
	/// Persist current signed in accounts metadata so it can be restored on app restart.
	/// </summary>
	internal static async Task SaveAccountsMetadataAsync()
	{
		await MetadataFileLock.WaitAsync();
		try
		{
			string metadataFilePath = Path.Combine(TokenCacheDiskLocation, "AccountsMetadata.json");

			List<SavedAccountMetadata> metadataList = [];

			foreach (AuthenticatedAccounts a in AuthenticationCompanion.AuthenticatedAccounts)
			{
				// Only save accounts that were originally signed in with caching requested
				if (a.UseCache)
				{
					metadataList.Add(new SavedAccountMetadata
					(
						accountIdentifier: a.AccountIdentifier,
						username: a.Username,
						tenantID: a.TenantID,
						permissions: a.Permissions,
						authContext: a.AuthContext,
						methodUsed: a.MethodUsed,
						environment: a.Environment,
						useCache: a.UseCache
					));
				}
			}

			string json = JsonSerializer.Serialize(metadataList, MSGraphJsonContext.Default.ListSavedAccountMetadata);

			// Cross-process file writing safety with retry loop
			for (int i = 0; i < 5; i++)
			{
				try
				{
					using FileStream stream = new(metadataFilePath, FileMode.Create, FileAccess.Write, FileShare.None);
					using StreamWriter writer = new(stream);
					await writer.WriteAsync(json);
					break;
				}
				catch (IOException) when (i < 4)
				{
					await Task.Delay(100);
				}
			}
		}
		catch (Exception ex)
		{
			Logger.Write($"Failed to save account metadata: {ex.Message}");
		}
		finally
		{
			_ = MetadataFileLock.Release();
		}
	}

	/// <summary>
	/// Clears the locally stored token cache metadata from the disk.
	/// </summary>
	internal static async Task ClearLocalCacheAsync()
	{
		await MetadataFileLock.WaitAsync();
		try
		{
			await AppCacheLock.WaitAsync();
			try
			{
				// Clean up MSAL apps and accounts from memory and disk first to ensure native disk-purging hooks run
				foreach (IPublicClientApplication app in AppCache.Values)
				{
					try
					{
						IEnumerable<IAccount> accounts = await app.GetAccountsAsync();
						foreach (IAccount acc in accounts)
						{
							await app.RemoveAsync(acc);
						}
					}
					catch (Exception ex)
					{
						Logger.Write($"Failed to clear MSAL accounts for an app instance: {ex.Message}");
					}
				}

				// Unregister cache helpers after accounts are removed to prevent memory leaks and file locking issues
				foreach (KeyValuePair<(SignInMethods, AzureCloudInstance, bool), MsalCacheHelper> kvp in CacheHelpers)
				{
					try
					{
						if (AppCache.TryGetValue(kvp.Key, out IPublicClientApplication? app))
						{
							kvp.Value.UnregisterCache(app.UserTokenCache);
						}
					}
					catch (Exception ex)
					{
						Logger.Write($"Failed to unregister MSAL cache helper: {ex.Message}");
					}
				}
				CacheHelpers.Clear();

				// Completely clear the AppCache dictionary to prevent memory leaks
				AppCache.Clear();
			}
			finally
			{
				_ = AppCacheLock.Release();
			}

			if (Directory.Exists(TokenCacheDiskLocation))
			{
				string[] files = Directory.GetFiles(TokenCacheDiskLocation);
				foreach (string file in files)
				{
					// Retry loop for cross-process delays
					for (int i = 0; i < 5; i++)
					{
						try
						{
							File.Delete(file);
							break;
						}
						catch (Exception ex)
						{
							if (i == 4)
							{
								Logger.Write($"Failed to delete cache file {file}: {ex.Message}");
							}
							else
							{
								await Task.Delay(100);
							}
						}
					}
				}
			}
		}
		finally
		{
			_ = MetadataFileLock.Release();
		}
	}

	/// <summary>
	/// Automatically restores authenticated accounts mapped from metadata using the silently cached tokens.
	/// Called via UI initialization context once.
	/// </summary>
	internal static async Task RestoreCachedAccountsAsync()
	{
		string metadataFilePath = Path.Combine(TokenCacheDiskLocation, "AccountsMetadata.json");

		string json = string.Empty;
		bool fileExists = false;

		await MetadataFileLock.WaitAsync();
		try
		{
			if (File.Exists(metadataFilePath))
			{
				for (int i = 0; i < 5; i++)
				{
					try
					{
						using FileStream stream = new(metadataFilePath, FileMode.Open, FileAccess.Read, FileShare.Read);
						using StreamReader reader = new(stream);
						json = await reader.ReadToEndAsync();
						fileExists = true;
						break;
					}
					catch (IOException) when (i < 4)
					{
						await Task.Delay(100);
					}
				}
			}
		}
		catch (Exception ex)
		{
			Logger.Write($"Failed to read account metadata: {ex.Message}");
		}
		finally
		{
			_ = MetadataFileLock.Release();
		}

		if (!fileExists || string.IsNullOrWhiteSpace(json))
		{
			return;
		}

		List<SavedAccountMetadata>? metadataList = null;

		try
		{
			metadataList = JsonSerializer.Deserialize(json, MSGraphJsonContext.Default.ListSavedAccountMetadata);
		}
		catch (Exception ex)
		{
			Logger.Write($"Failed to deserialize cached accounts metadata (possible corruption): {ex.Message}. Clearing local cache to prevent orphaned files.");

			// If serialization fails, the metadata file is corrupt. Clear the cache entirely to avoid persistent orphan MSAL files.
			await ClearLocalCacheAsync();
			return;
		}

		if (metadataList is not null)
		{
			bool metadataNeedsUpdate = false;

			foreach (SavedAccountMetadata meta in metadataList)
			{
				IPublicClientApplication app = await GetAppAsync(meta.MethodUsed, meta.Environment, meta.UseCache);
				IAccount? account = await app.GetAccountAsync(meta.AccountIdentifier);

				if (account is not null)
				{
					AuthenticationResult? authResult = null;
					bool skipAccount = false;

					try
					{
						authResult = await app.AcquireTokenSilent(Scopes[meta.AuthContext], account).ExecuteAsync();
					}
					catch (MsalUiRequiredException)
					{
						// Token is completely expired and can't be refreshed automatically.
						// The user will need to sign in again interactively. We don't restore it.
						skipAccount = true;
						metadataNeedsUpdate = true; // Mark orphaned entry for JSON cleanup
					}
					catch (Exception ex)
					{
						// Network error or other transient issue. We still populate the account in the UI
						// but leave AuthResult as null. GetValidAccessTokenAsync will handle performing a network request to refresh it later.
						Logger.Write($"Failed to silently acquire token for cached account {meta.Username} during restoration (offline?): {ex.Message}");
					}

					if (!skipAccount)
					{
						AuthenticatedAccounts restoredAccount = new(
							accountIdentifier: meta.AccountIdentifier,
							username: meta.Username,
							tenantID: meta.TenantID,
							permissions: meta.Permissions,
							authContext: meta.AuthContext,
							authResult: authResult,
							account: account,
							methodUsed: meta.MethodUsed,
							environment: meta.Environment,
							useCache: meta.UseCache
						);

						bool exists = AuthenticationCompanion.AuthenticatedAccounts.Any(x =>
							string.Equals(x.AccountIdentifier, meta.AccountIdentifier, StringComparison.OrdinalIgnoreCase) &&
							x.AuthContext == meta.AuthContext &&
							x.Environment == meta.Environment);

						if (!exists)
						{
							AuthenticationCompanion.AuthenticatedAccounts.Add(restoredAccount);
						}
					}
				}
				else
				{
					// Account was completely removed from the MSAL cache but remained in our JSON metadata
					metadataNeedsUpdate = true;
				}
			}

			// If we detected any missing/expired sessions, overwrite the JSON to clean up dead entries
			if (metadataNeedsUpdate)
			{
				await SaveAccountsMetadataAsync();
			}
		}
	}
}
