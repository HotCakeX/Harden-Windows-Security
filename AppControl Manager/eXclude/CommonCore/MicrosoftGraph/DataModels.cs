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
using System.Text;
using System.Text.Json.Serialization;
using Microsoft.Identity.Client;
using Microsoft.UI.Xaml;

namespace CommonCore.MicrosoftGraph;

internal sealed class AssignmentPayload(Dictionary<string, object>? target)
{
	[JsonInclude]
	[JsonPropertyName("target")]
	internal Dictionary<string, object>? Target => target;
}

/// <summary>
/// Used to determine which scope to use
/// </summary>
internal enum AuthenticationContext
{
	Intune,
	MDEAdvancedHunting
}

/// <summary>
/// The Device Health Script object.
/// https://learn.microsoft.com/graph/api/resources/intune-devices-devicehealthscript?view=graph-rest-beta
/// </summary>
internal sealed class DeviceHealthScript
{
	[JsonInclude]
	[JsonPropertyName("id")]
	internal string? Id { get; set; }

	[JsonInclude]
	[JsonPropertyName("publisher")]
	internal string? Publisher { get; set; }

	[JsonInclude]
	[JsonPropertyName("version")]
	internal string? Version { get; set; }

	[JsonInclude]
	[JsonPropertyName("displayName")]
	internal string? DisplayName { get; set; }

	[JsonInclude]
	[JsonPropertyName("description")]
	internal string? Description { get; set; }

	/// <summary>
	/// Binary in the doc, Base64 string in JSON
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("detectionScriptContent")]
	internal string? DetectionScriptContent { get; set; }

	/// <summary>
	/// Binary in the doc, Base64 string in JSON
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("remediationScriptContent")]
	internal string? RemediationScriptContent { get; set; }

	[JsonInclude]
	[JsonPropertyName("createdDateTime")]
	internal DateTimeOffset? CreatedDateTime { get; set; }

	[JsonInclude]
	[JsonPropertyName("lastModifiedDateTime")]
	internal DateTimeOffset? LastModifiedDateTime { get; set; }

	[JsonInclude]
	[JsonPropertyName("runAsAccount")]
	internal string? RunAsAccount { get; set; }

	[JsonInclude]
	[JsonPropertyName("enforceSignatureCheck")]
	internal bool? EnforceSignatureCheck { get; set; }

	[JsonInclude]
	[JsonPropertyName("runAs32Bit")]
	internal bool? RunAs32Bit { get; set; }

	[JsonInclude]
	[JsonPropertyName("roleScopeTagIds")]
	internal List<string>? RoleScopeTagIds { get; set; }

	[JsonInclude]
	[JsonPropertyName("isGlobalScript")]
	internal bool? IsGlobalScript { get; set; }

	[JsonInclude]
	[JsonPropertyName("highestAvailableVersion")]
	internal string? HighestAvailableVersion { get; set; }

	/// <summary>
	/// https://learn.microsoft.com/graph/api/resources/intune-devices-devicehealthscripttype?view=graph-rest-beta
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("deviceHealthScriptType")]
	internal string? DeviceHealthScriptType { get; set; }

	[JsonInclude]
	[JsonPropertyName("detectionScriptParameters")]
	internal List<DeviceHealthScriptStringParameter>? DetectionScriptParameters { get; set; }

	[JsonInclude]
	[JsonPropertyName("remediationScriptParameters")]
	internal List<DeviceHealthScriptStringParameter>? RemediationScriptParameters { get; set; }
}

/// <summary>
/// A string parameter for the Device Health Script.
/// https://learn.microsoft.com/graph/api/resources/intune-devices-devicehealthscriptstringparameter?view=graph-rest-beta
/// </summary>
internal sealed class DeviceHealthScriptStringParameter
{
	[JsonInclude]
	[JsonPropertyName("@odata.type")]
	internal string ODataType { get; set; } = "#microsoft.graph.deviceHealthScriptStringParameter";

	[JsonInclude]
	[JsonPropertyName("name")]
	internal string? Name { get; set; }

	[JsonInclude]
	[JsonPropertyName("description")]
	internal string? Description { get; set; }

	[JsonInclude]
	[JsonPropertyName("isRequired")]
	internal bool IsRequired { get; set; }

	[JsonInclude]
	[JsonPropertyName("applyDefaultValueWhenNotAssigned")]
	internal bool ApplyDefaultValueWhenNotAssigned { get; set; }

	[JsonInclude]
	[JsonPropertyName("defaultValue")]
	internal string? DefaultValue { get; set; }
}

/// <summary>
/// Envelope for listing Device Health Scripts.
/// </summary>
internal sealed class DeviceHealthScriptsResponse
{
	[JsonInclude]
	[JsonPropertyName("@odata.context")]
	internal string? ODataContext { get; set; }

	[JsonInclude]
	[JsonPropertyName("@microsoft.graph.tips")]
	internal string? MicrosoftGraphTips { get; set; }

	[JsonInclude]
	[JsonPropertyName("value")]
	internal List<DeviceHealthScript>? Value { get; set; }
}

/// <summary>
/// Represents the response from the Graph API that contains a list of device configuration policies.
/// </summary>
internal sealed class DeviceConfigurationPoliciesResponse(
	string? oDataContext,
	string? microsoftGraphTips,
	List<Windows10CustomConfiguration>? value
)
{
	/// <summary>
	/// OData context information.
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("@odata.context")]
	internal string? ODataContext => oDataContext;

	/// <summary>
	/// Additional Microsoft Graph tips.
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("@microsoft.graph.tips")]
	internal string? MicrosoftGraphTips => microsoftGraphTips;

	/// <summary>
	/// The list of device configuration policies.
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("value")]
	internal List<Windows10CustomConfiguration>? Value => value;
}

/// <summary>
/// Represents a standard (non-custom OMA-URI) device management configuration policy.
/// https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfigv2-devicemanagementconfigurationpolicy?view=graph-rest-beta
/// </summary>
internal sealed class DeviceManagementConfigurationPolicy(
	string? id,
	string? name,
	string? description,
	string? platforms,
	string? technologies,
	int? settingCount,
	DateTimeOffset? createdDateTime,
	DateTimeOffset? lastModifiedDateTime,
	List<string>? roleScopeTagIds
)
{
	[JsonInclude]
	[JsonPropertyName("id")]
	internal string? Id => id;

	[JsonInclude]
	[JsonPropertyName("name")]
	internal string? Name => name;

	[JsonInclude]
	[JsonPropertyName("description")]
	internal string? Description => description;

	[JsonInclude]
	[JsonPropertyName("platforms")]
	internal string? Platforms => platforms;

	[JsonInclude]
	[JsonPropertyName("technologies")]
	internal string? Technologies => technologies;

	[JsonInclude]
	[JsonPropertyName("settingCount")]
	internal int? SettingCount => settingCount;

	[JsonInclude]
	[JsonPropertyName("createdDateTime")]
	internal DateTimeOffset? CreatedDateTime => createdDateTime;

	[JsonInclude]
	[JsonPropertyName("lastModifiedDateTime")]
	internal DateTimeOffset? LastModifiedDateTime => lastModifiedDateTime;

	[JsonInclude]
	[JsonPropertyName("roleScopeTagIds")]
	internal List<string>? RoleScopeTagIds => roleScopeTagIds;
}

/// <summary>
/// Response container for configuration policies listing (pagination supported).
/// </summary>
internal sealed class DeviceManagementConfigurationPoliciesResponse(
	string? oDataContext,
	List<DeviceManagementConfigurationPolicy>? value
)
{
	[JsonInclude]
	[JsonPropertyName("@odata.context")]
	internal string? ODataContext => oDataContext;

	[JsonInclude]
	[JsonPropertyName("value")]
	internal List<DeviceManagementConfigurationPolicy>? Value => value;
}

/// <summary>
/// https://learn.microsoft.com/graph/api/resources/group?view=graph-rest-beta
/// </summary>
internal sealed class Group(
	string? displayName,
	string? description,
	bool mailEnabled,
	string mailNickname,
	bool securityEnabled,
	List<string> groupTypes
)
{
	[JsonInclude]
	[JsonPropertyName("displayName")]
	internal string? DisplayName => displayName;

	[JsonInclude]
	[JsonPropertyName("description")]
	internal string? Description => description;

	[JsonInclude]
	[JsonPropertyName("mailEnabled")]
	internal bool MailEnabled => mailEnabled;

	[JsonInclude]
	[JsonPropertyName("mailNickname")]
	internal string MailNickname => mailNickname;

	[JsonInclude]
	[JsonPropertyName("securityEnabled")]
	internal bool SecurityEnabled => securityEnabled;

	[JsonInclude]
	[JsonPropertyName("groupTypes")]
	internal List<string> GroupTypes => groupTypes;
}

// Host interface for ViewModels that want to use the GraphAuthPanel user control.
internal interface IGraphAuthHost
{
	AuthenticationCompanion AuthCompanionCLS { get; }
	bool AreElementsEnabled { get; }
}

/// <summary>
/// Data type for hardening policy JSON files listing in the ComboBox.
/// </summary>
internal sealed class IntunePolicyFileItem(string fileName, string fullPath)
{
	internal string FileName => fileName;
	internal string FullPath => fullPath;
}

/// <summary>
/// Represents a payload for a query with an optional query string. The query string can be serialized to JSON.
/// </summary>
internal sealed class QueryPayload(
	string? query
)
{
	[JsonInclude]
	[JsonPropertyName("Query")]
	internal string? Query => query;
}

/// <summary>
/// Define the class structure for the custom policy.
/// https://learn.microsoft.com/graph/api/resources/intune-deviceconfig-windows10customconfiguration?view=graph-rest-beta
/// </summary>
internal sealed class Windows10CustomConfiguration(
	string? oDataType,
	string? displayName,
	string? description,
	string? id,
	DateTimeOffset? lastModifiedDateTime,
	List<string>? roleScopeTagIds,
	bool supportsScopeTags,
	DateTimeOffset? createdDateTime,
	int version,
	List<OmaSettingBase64>? omaSettings
)
{
	/// <summary>
	/// Represents the OData type.
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("@odata.type")]
	internal string? ODataType => oDataType;

	/// <summary>
	/// The display name of the custom configuration.
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("displayName")]
	internal string? DisplayName => displayName;

	/// <summary>
	/// The description of the custom configuration.
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("description")]
	internal string? Description => description;

	/// <summary>
	/// Unique identifier for the policy.
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("id")]
	internal string? Id => id;

	/// <summary>
	/// Date and time when the policy was last modified.
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("lastModifiedDateTime")]
	internal DateTimeOffset? LastModifiedDateTime => lastModifiedDateTime;

	/// <summary>
	/// List of role scope tag identifiers.
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("roleScopeTagIds")]
	internal List<string>? RoleScopeTagIds => roleScopeTagIds;

	/// <summary>
	/// Indicates whether the policy supports scope tags.
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("supportsScopeTags")]
	internal bool SupportsScopeTags => supportsScopeTags;

	/// <summary>
	/// Date and time when the policy was created.
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("createdDateTime")]
	internal DateTimeOffset? CreatedDateTime => createdDateTime;

	/// <summary>
	/// Version of the policy.
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("version")]
	internal int Version => version;

	/// <summary>
	/// The OMA settings associated with the configuration.
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("omaSettings")]
	internal List<OmaSettingBase64>? OmaSettings => omaSettings;
}

/// <summary>
/// Different methods for the sign in process
/// </summary>
internal enum SignInMethods : int
{
	WebAccountManager = 0,
	WebBrowser = 1
}

internal sealed class AuthenticationContextComboBox(
	string name,
	SignInMethods authContext,
	string image)
{
	internal string Name => name;
	internal SignInMethods AuthContext => authContext;
	internal string Image => image;
}

/// <summary>
/// Represents the response containing a list of assignments from Graph API.
/// </summary>
internal sealed class PolicyAssignmentResponse(List<PolicyAssignmentObject> value)
{
	[JsonPropertyName("value")]
	[JsonInclude]
	internal List<PolicyAssignmentObject> Value => value;
}

/// <summary>
/// Represents a single assignment object from Graph API.
/// </summary>
internal sealed class PolicyAssignmentObject(string id, PolicyAssignmentTarget target)
{
	[JsonPropertyName("id")]
	[JsonInclude]
	internal string Id => id;

	[JsonPropertyName("target")]
	[JsonInclude]
	internal PolicyAssignmentTarget Target => target;
}

internal sealed class PolicyAssignmentTarget(string? oDataType, string? groupId)
{
	[JsonPropertyName("@odata.type")]
	[JsonInclude]
	internal string? ODataType => oDataType;

	[JsonPropertyName("groupId")]
	[JsonInclude]
	internal string? GroupId => groupId;
}

/// <summary>
/// Class used to display assignment info in the UI.
/// </summary>
internal sealed class PolicyAssignmentDisplay(string name, string type, string? targetId, string? assignmentId)
{
	internal string Name => name;
	internal string Type => type;

	/// <summary>
	/// The ID of the Group/User/Device (Display purposes)
	/// </summary>
	internal string? TargetId => targetId;

	/// <summary>
	/// The ID of the Assignment Object itself (Required for deletion)
	/// </summary>
	internal string? AssignmentId => assignmentId;

	internal Visibility IdVisibility => string.IsNullOrEmpty(targetId) ? Visibility.Collapsed : Visibility.Visible;
}

/// <summary>
/// Represents a configuration setting with properties for OData type, display name, description, URI, file name, and
/// value.
/// https://learn.microsoft.com/graph/api/resources/intune-deviceconfig-omasettingbase64?view=graph-rest-beta
/// </summary>
internal sealed class OmaSettingBase64(
	string? oDataType,
	string? displayName,
	string? description,
	string? omaUri,
	string? fileName,
	string? value
)
{
	[JsonInclude]
	[JsonPropertyName("@odata.type")]
	internal string? ODataType => oDataType;

	[JsonInclude]
	[JsonPropertyName("displayName")]
	internal string? DisplayName => displayName;

	[JsonInclude]
	[JsonPropertyName("description")]
	internal string? Description => description;

	[JsonInclude]
	[JsonPropertyName("omaUri")]
	internal string? OmaUri => omaUri;

	[JsonInclude]
	[JsonPropertyName("fileName")]
	internal string? FileName => fileName;

	[JsonInclude]
	[JsonPropertyName("value")]
	internal string? Value => value;
}

/// <summary>
/// Envelope for configuration policy assignments.
/// </summary>
internal sealed class ConfigurationPolicyAssignmentsEnvelope(
	List<AssignmentPayload> assignments
)
{
	[JsonInclude]
	[JsonPropertyName("assignments")]
	internal List<AssignmentPayload> Assignments => assignments;
}

/// <summary>
/// Provides a view model for binding the Azure Cloud environment to a ComboBox.
/// </summary>
internal sealed class AzureCloudEnvironmentComboBoxItem(string name, AzureCloudInstance environment)
{
	internal string Name => name;
	internal AzureCloudInstance Environment => environment;
}

internal sealed class AuthenticatedAccounts(
	string accountIdentifier,
	string username,
	string tenantID,
	string permissions,
	AuthenticationContext authContext,
	AuthenticationResult? authResult,
	IAccount account,
	SignInMethods methodUsed,
	AzureCloudInstance environment,
	bool useCache)
{
	internal string AccountIdentifier => accountIdentifier;
	internal string Username => username;
	internal string TenantID => tenantID;
	internal string Permissions => permissions;
	internal AuthenticationContext AuthContext => authContext;
	internal AuthenticationResult? AuthResult { get; set; } = authResult;
	internal IAccount Account => account;
	internal SignInMethods MethodUsed => methodUsed;
	internal AzureCloudInstance Environment => environment;
	internal bool UseCache => useCache;

	public override bool Equals(object? obj)
	{
		if (ReferenceEquals(this, obj))
			return true;
		if (obj is null || obj.GetType() != GetType())
			return false;
		AuthenticatedAccounts other = (AuthenticatedAccounts)obj;

		// Intentionally omitting 'UseCache' from equality to allow re-authentication overriding the prior cache settings
		return StringComparer.OrdinalIgnoreCase.Equals(AccountIdentifier, other.AccountIdentifier)
			&& StringComparer.OrdinalIgnoreCase.Equals(Username, other.Username)
			&& StringComparer.OrdinalIgnoreCase.Equals(TenantID, other.TenantID)
			&& StringComparer.OrdinalIgnoreCase.Equals(Permissions, other.Permissions)
			&& Environment == other.Environment;
	}

	public override int GetHashCode()
	{
		unchecked
		{
			return HashCode.Combine(
				StringComparer.OrdinalIgnoreCase.GetHashCode(AccountIdentifier),
				StringComparer.OrdinalIgnoreCase.GetHashCode(Username),
				StringComparer.OrdinalIgnoreCase.GetHashCode(TenantID),
				StringComparer.OrdinalIgnoreCase.GetHashCode(Permissions),
				Environment);
		}
	}

	public static bool operator ==(AuthenticatedAccounts? left, AuthenticatedAccounts? right)
	{
		if (ReferenceEquals(left, right))
			return true;
		if (left is null || right is null)
			return false;
		return left.Equals(right);
	}

	public static bool operator !=(AuthenticatedAccounts? left, AuthenticatedAccounts? right) => !(left == right);
}

/// <summary>
/// A lightweight class used to persist the required metadata needed to restore an account on application startup.
/// </summary>
internal sealed class SavedAccountMetadata(
	string accountIdentifier,
	string username,
	string tenantID,
	string permissions,
	AuthenticationContext authContext,
	SignInMethods methodUsed,
	AzureCloudInstance environment,
	bool useCache)
{
	[JsonInclude]
	[JsonPropertyName("accountIdentifier")]
	internal string AccountIdentifier => accountIdentifier;

	[JsonInclude]
	[JsonPropertyName("username")]
	internal string Username => username;

	[JsonInclude]
	[JsonPropertyName("tenantID")]
	internal string TenantID => tenantID;

	[JsonInclude]
	[JsonPropertyName("permissions")]
	internal string Permissions => permissions;

	[JsonInclude]
	[JsonPropertyName("authContext")]
	internal AuthenticationContext AuthContext => authContext;

	[JsonInclude]
	[JsonPropertyName("methodUsed")]
	internal SignInMethods MethodUsed => methodUsed;

	[JsonInclude]
	[JsonPropertyName("environment")]
	internal AzureCloudInstance Environment => environment;

	[JsonInclude]
	[JsonPropertyName("useCache")]
	internal bool UseCache => useCache;
}

/// <summary>
/// Used to store Intune group Names/ID and is served as a DataType for ListViews that show them
/// </summary>
internal sealed class IntuneGroupItemListView(
	string groupName,
	string groupID,
	string? description,
	string? securityIdentifier,
	DateTime createdDateTime)
{
	[JsonInclude]
	[JsonPropertyName("Name")]
	internal string GroupName => groupName;

	[JsonInclude]
	[JsonPropertyName("ID")]
	internal string GroupID => groupID;

	[JsonInclude]
	[JsonPropertyName("Description")]
	internal string? Description => description;

	[JsonInclude]
	[JsonPropertyName("Security Identifier")]
	internal string? SecurityIdentifier => securityIdentifier;

	[JsonInclude]
	[JsonPropertyName("creation Date")]
	internal DateTime CreatedDateTime => createdDateTime;
}

/// <summary>
/// JSON source generated context for <see cref="IntuneGroupItemListView"/> type.
/// </summary>
[JsonSourceGenerationOptions(
	WriteIndented = true
)]
[JsonSerializable(typeof(IntuneGroupItemListView))]
[JsonSerializable(typeof(List<IntuneGroupItemListView>))]
internal sealed partial class IntuneGroupItemListViewJsonSerializationContext : JsonSerializerContext
{
}
