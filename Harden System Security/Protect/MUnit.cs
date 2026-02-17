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
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using AppControlManager.CustomUIElements;
using AppControlManager.ViewModels;
using CommonCore.GroupPolicy;
using HardenSystemSecurity.Helpers;
using HardenSystemSecurity.ViewModels;
using Microsoft.UI.Xaml;

namespace HardenSystemSecurity.Protect;

// IMPORTANT NOTES
// 1. DO NOT use "**del." for "ValueName" in JSON files for items with "Source": 0" (aka Group Policies) if the intent is to remove them from the system.
//    Instead, set the "PolicyAction: 1" and keep the "ValueName" as is without the "**del." prefix. It will correctly be matched/found and removed from the POL file.

/// <summary>
/// Execution timing for specialized strategies so we can define what code runs before or after the main Remove/Apply codes.
/// This is used only for Security Measures applied via JSON files, aka those that use Group Policy or Registry keys.
/// </summary>
internal enum ExecutionTiming
{
	/// <summary>
	/// Execute before the main operation
	/// </summary>
	Before,

	/// <summary>
	/// Execute after the main operation
	/// </summary>
	After
}

/// <summary>
/// Defines the type of dependency relationship between MUnits.
/// </summary>
internal enum DependencyType
{
	/// <summary>
	/// Dependencies that are applied when primary is applied
	/// </summary>
	Apply,

	/// <summary>
	/// Dependencies that are removed when primary is removed
	/// </summary>
	Remove,

	/// <summary>
	/// Dependencies that follow both apply and remove operations.
	/// </summary>
	Both
}

/// <summary>
/// Represents a dependency relationship between MUnits.
/// </summary>
internal sealed class MUnitDependency(Guid dependentMUnitId, DependencyType type, ExecutionTiming timing)
{
	/// <summary>
	/// The unique identifier of the dependent MUnit.
	/// </summary>
	internal Guid DependentMUnitId => dependentMUnitId;

	/// <summary>
	/// The type of dependency.
	/// </summary>
	internal DependencyType Type => type;

	/// <summary>
	/// When the dependency should be executed relative to the primary operation.
	/// </summary>
	internal ExecutionTiming Timing => timing;
}

/// <summary>
/// Registry for managing MUnit dependencies.
/// </summary>
internal static class MUnitDependencyRegistry
{
	/// <summary>
	/// Key: Primary MUnit identifier (ID)
	/// Value: List of dependent MUnit identifiers with their types
	/// </summary>
	private static readonly Dictionary<Guid, List<MUnitDependency>> _dependencies = [];

	/// <summary>
	/// Registers a dependency relationship between two <see cref="MUnit"/> using their <see cref="MUnit.ID"/>.
	/// </summary>
	/// <param name="primaryMUnitId">The identifier of the primary MUnit</param>
	/// <param name="dependentMUnitId">The identifier of the dependent MUnit</param>
	/// <param name="type">The type of dependency</param>
	/// <param name="timing">When the dependency should be executed</param>
	internal static void RegisterDependency(Guid primaryMUnitId, Guid dependentMUnitId, DependencyType type, ExecutionTiming timing)
	{
		ref List<MUnitDependency>? listRef = ref CollectionsMarshal.GetValueRefOrAddDefault(_dependencies, primaryMUnitId, out _);
		listRef ??= [];
		listRef.Add(new(dependentMUnitId, type, timing));
		Logger.Write(string.Format(GlobalVars.GetStr("JSONDependencyRegistered"), primaryMUnitId, dependentMUnitId, type, timing));
	}

	/// <summary>
	/// Gets dependencies for a specific MUnit and operation
	/// </summary>
	/// <param name="mUnitId">The MUnit identifier</param>
	/// <param name="operation">The operation being performed</param>
	/// <param name="timing">The execution timing</param>
	/// <returns>List of dependent MUnit identifiers</returns>
	internal static List<Guid> GetDependencies(Guid mUnitId, MUnitOperation operation, ExecutionTiming timing)
	{
		if (!_dependencies.TryGetValue(mUnitId, out List<MUnitDependency>? dependencies))
			return [];

		return dependencies
			.Where(dep => dep.Timing == timing &&
						 (dep.Type == DependencyType.Both ||
						  (operation == MUnitOperation.Apply && dep.Type == DependencyType.Apply) ||
						  (operation == MUnitOperation.Remove && dep.Type == DependencyType.Remove)))
			.Select(dep => dep.DependentMUnitId)
			.ToList();
	}
}

/// <summary>
/// The apply strategy interface.
/// </summary>
internal interface IApplyStrategy
{
	void Apply();
}

/// <summary>
/// A marker + payload strategy for Group Policy application.
/// </summary>
internal interface IApplyGroupPolicy : IApplyStrategy
{
	/// <summary>
	/// The Group Policy that needs to be applied for this specific protection measure.
	/// </summary>
	RegistryPolicyEntry Policy { get; }
}

/// <summary>
/// Implementation of the <see cref="IApplyGroupPolicy"/> strategy.
/// </summary>
/// <param name="policy"></param>
internal sealed class GroupPolicyApply(RegistryPolicyEntry policy) : IApplyGroupPolicy
{
	public RegistryPolicyEntry Policy => policy;

	// This will never be called on its own: we bulk-invoke ApplyPolicies instead.
	public void Apply() => throw new InvalidOperationException(GlobalVars.GetStr("GroupPolicyApplyBulkInvokeError"));
}

/// <summary>
/// A marker + payload strategy for Registry application.
/// </summary>
internal interface IApplyRegistry : IApplyStrategy
{
	/// <summary>
	/// The Registry policy that needs to be applied for this specific protection measure.
	/// </summary>
	RegistryPolicyEntry Policy { get; }
}

/// <summary>
/// Implementation of the <see cref="IApplyRegistry"/> strategy.
/// </summary>
/// <param name="policy"></param>
internal sealed class RegistryApply(RegistryPolicyEntry policy) : IApplyRegistry
{
	public RegistryPolicyEntry Policy => policy;

	// This will never be called on its own: we bulk-invoke ApplyPolicies instead.
	public void Apply() => throw new InvalidOperationException(GlobalVars.GetStr("RegistryApplyBulkInvokeError"));
}

/// <summary>
/// A delegate‑based apply strategy whose logic is provided at construction time.
/// </summary>
internal sealed class DefaultApply(Action action) : IApplyStrategy
{
	public void Apply() => action();
}

/// <summary>
/// The verify strategy interface.
/// </summary>
internal interface IVerifyStrategy
{
	bool Verify();
}

/// <summary>
/// Interface for specialized verification strategies that can be used as fallback.
/// </summary>
internal interface ISpecializedVerificationStrategy
{
	/// <summary>
	/// Verifies the strategy using an optional target policy as context.
	/// </summary>
	/// <param name="targetPolicy">The policy being verified, allowing the strategy to adapt to specific expected values.</param>
	/// <returns>True if the condition is met.</returns>
	bool Verify(RegistryPolicyEntry? targetPolicy = null);
}

/// <summary>
/// Interface for specialized apply strategies that provide additional functionality.
/// </summary>
internal interface ISpecializedApplyStrategy
{
	/// <summary>
	/// Executes the specialized apply logic.
	/// </summary>
	void Apply();

	/// <summary>
	/// Specifies when this strategy should be executed relative to the main apply operation.
	/// </summary>
	ExecutionTiming Timing { get; }
}

/// <summary>
/// Interface for specialized remove strategies that provide additional functionality.
/// </summary>
internal interface ISpecializedRemoveStrategy
{
	/// <summary>
	/// Executes the specialized remove logic.
	/// </summary>
	void Remove();

	/// <summary>
	/// Specifies when this strategy should be executed relative to the main remove operation.
	/// </summary>
	ExecutionTiming Timing { get; }
}

/// <summary>
/// A marker + payload strategy for Group Policy verification.
/// </summary>
internal interface IVerifyGroupPolicy : IVerifyStrategy
{
	/// <summary>
	/// The Group Policy that needs to be verified for this specific protection measure.
	/// </summary>
	RegistryPolicyEntry Policy { get; }
}

/// <summary>
/// Implementation of the <see cref="IVerifyGroupPolicy"/> strategy.
/// </summary>
/// <param name="policy"></param>
internal sealed class GroupPolicyVerify(RegistryPolicyEntry policy) : IVerifyGroupPolicy
{
	public RegistryPolicyEntry Policy => policy;

	// This will never be called on its own.
	public bool Verify() =>
		throw new InvalidOperationException(GlobalVars.GetStr("SecurityPolicyRegistryVerifyBulkInvokeError"));
}

/// <summary>
/// A marker + payload strategy for Registry verification.
/// </summary>
internal interface IVerifyRegistry : IVerifyStrategy
{
	/// <summary>
	/// The Registry policy that needs to be verified for this specific protection measure.
	/// </summary>
	RegistryPolicyEntry Policy { get; }
}

/// <summary>
/// Implementation of the <see cref="IVerifyRegistry"/> strategy.
/// </summary>
/// <param name="policy"></param>
internal sealed class RegistryVerify(RegistryPolicyEntry policy) : IVerifyRegistry
{
	public RegistryPolicyEntry Policy => policy;

	// This will never be called on its own.
	public bool Verify() =>
		throw new InvalidOperationException(GlobalVars.GetStr("SecurityPolicyRegistryVerifyBulkInvokeError"));
}

/// <summary>
/// A delegate‐based verify strategy whose logic is provided at construction time.
/// </summary>
internal sealed class DefaultVerify(Func<bool> func) : IVerifyStrategy
{
	public bool Verify() => func();
}

/// <summary>
/// The Remove strategy interface.
/// </summary>
internal interface IRemoveStrategy
{
	void Remove();
}

/// <summary>
/// A delegate‑based remove strategy whose logic is provided at construction time.
/// </summary>
internal sealed class DefaultRemove(Action action) : IRemoveStrategy
{
	public void Remove() => action();
}

/// <summary>
/// A marker + payload strategy for Group Policy removal.
/// </summary>
internal interface IRemoveGroupPolicy : IRemoveStrategy
{
	/// <summary>
	/// The Group Policy that needs to be removed for this specific protection measure.
	/// </summary>
	RegistryPolicyEntry Policy { get; }
}

/// <summary>
/// Implementation of the <see cref="IRemoveGroupPolicy"/> strategy.
/// </summary>
/// <param name="policy"></param>
internal sealed class GroupPolicyRemove(RegistryPolicyEntry policy) : IRemoveGroupPolicy
{
	public RegistryPolicyEntry Policy => policy;

	// This will never be called on its own.
	public void Remove() =>
		throw new InvalidOperationException(GlobalVars.GetStr("SecurityPolicyRegistryVerifyBulkInvokeError"));
}

/// <summary>
/// A marker + payload strategy for Registry removal.
/// </summary>
internal interface IRemoveRegistry : IRemoveStrategy
{
	/// <summary>
	/// The Registry policy that needs to be removed for this specific protection measure.
	/// </summary>
	RegistryPolicyEntry Policy { get; }
}

/// <summary>
/// Implementation of the <see cref="IRemoveRegistry"/> strategy.
/// </summary>
/// <param name="policy"></param>
internal sealed class RegistryRemove(RegistryPolicyEntry policy) : IRemoveRegistry
{
	public RegistryPolicyEntry Policy => policy;

	// This will never be called on its own.
	public void Remove() =>
		throw new InvalidOperationException(GlobalVars.GetStr("SecurityPolicyRegistryVerifyBulkInvokeError"));
}

/// <summary>
/// Repository for managing specialized strategies for verification, apply and remove operations.
/// </summary>
internal static class SpecializedStrategiesRegistry
{
	internal static readonly Dictionary<string, ISpecializedVerificationStrategy> _verificationStrategies = new(StringComparer.OrdinalIgnoreCase);
	internal static readonly Dictionary<string, List<ISpecializedApplyStrategy>> _applyStrategies = new(StringComparer.OrdinalIgnoreCase);
	internal static readonly Dictionary<string, List<ISpecializedRemoveStrategy>> _removeStrategies = new(StringComparer.OrdinalIgnoreCase);

	/// <summary>
	/// Registers a specialized verification strategy for a specific policy.
	/// </summary>
	/// <param name="policyKey">The policy key in format "KeyName|ValueName"</param>
	/// <param name="strategy">The specialized verification strategy</param>
	internal static void RegisterSpecializedVerification(string policyKey, ISpecializedVerificationStrategy strategy) =>
		_verificationStrategies[policyKey] = strategy;

	/// <summary>
	/// Registers a specialized apply strategy for a specific policy.
	/// </summary>
	/// <param name="policyKey">The policy key in format "KeyName|ValueName"</param>
	/// <param name="strategy">The specialized apply strategy</param>
	internal static void RegisterSpecializedApply(string policyKey, ISpecializedApplyStrategy strategy)
	{
		ref List<ISpecializedApplyStrategy>? applyListRef = ref CollectionsMarshal.GetValueRefOrAddDefault(_applyStrategies, policyKey, out _);
		applyListRef ??= new(2);
		applyListRef.Add(strategy);
	}

	/// <summary>
	/// Registers a specialized remove strategy for a specific policy.
	/// </summary>
	/// <param name="policyKey">The policy key in format "KeyName|ValueName"</param>
	/// <param name="strategy">The specialized remove strategy</param>
	internal static void RegisterSpecializedRemove(string policyKey, ISpecializedRemoveStrategy strategy)
	{
		ref List<ISpecializedRemoveStrategy>? removeListRef = ref CollectionsMarshal.GetValueRefOrAddDefault(_removeStrategies, policyKey, out _);
		removeListRef ??= [];
		removeListRef.Add(strategy);
	}

	/// <summary>
	/// One-time guard to avoid duplicate registration attempts.
	/// 0 = not started
	/// 1 = in progress
	/// 2 = completed
	/// </summary>
	private static int _wmiJsonRegistrationState;

	/// <summary>
	/// Signals completion of the registration (success or failure) so that concurrent callers can wait.
	/// </summary>
	private static readonly ManualResetEventSlim _wmiRegistrationDone = new(false);

	/// <summary>
	/// One-time registration from the JSON file.
	/// All concurrent callers block until initialization finishes (like Lazy<T> ExecutionAndPublication).
	/// Subsequent calls return immediately.
	/// </summary>
	internal static void RegisterWmiSpecializedVerificationsOnceFromFile()
	{
		// Fast path for when already completed
		if (Volatile.Read(ref _wmiJsonRegistrationState) == 2)
		{
			return;
		}

		// Try to become the initializing thread
		int prior = Interlocked.CompareExchange(ref _wmiJsonRegistrationState, 1, 0);

		// If we were the first, perform initialization
		if (prior == 0)
		{
			try
			{
				byte[] json = File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Resources", "WMI", "WMISettings.json"));
				List<WmiSpecialVerificationItem>? items =
					JsonSerializer.Deserialize(json, WmiSpecialVerificationJsonContext.Default.ListWmiSpecialVerificationItem);

				if (items is null || items.Count == 0)
				{
					Logger.Write("No WMI specialized verification entries found in JSON.");
				}
				else
				{
					RegisterWmiSpecializedVerificationsCore(items);
				}
			}
			catch (Exception ex)
			{
				// Still mark as completed so waiters are released.
				Logger.Write(ex);
			}
			finally
			{
				// Mark completed and release all waiting threads.
				Volatile.Write(ref _wmiJsonRegistrationState, 2);
				_wmiRegistrationDone.Set();
			}
		}
		else
		{
			// Another thread is performing initialization so wait until it completes.
			_wmiRegistrationDone.Wait();
		}
	}

	/// <summary>
	/// Core registrar.
	/// </summary>
	/// <param name="items">WMI verification items.</param>
	private static void RegisterWmiSpecializedVerificationsCore(List<WmiSpecialVerificationItem> items)
	{
		foreach (WmiSpecialVerificationItem item in CollectionsMarshal.AsSpan(items))
		{
			ISpecializedVerificationStrategy strategy = new WmiJsonVerificationStrategy(
				item.Category,
				item.WMINamespace,
				item.WMIClass,
				item.WMIProperty,
				item.DesiredWMIValues
			);

			_verificationStrategies[item.PolicyKey] = strategy;
#if DEBUG
			Logger.Write($"Created a {typeof(WmiSpecialVerificationItem)} for category '{item.Category}', namespace '{item.WMINamespace}', class '{item.WMIClass}', property '{item.WMIProperty}' and desired values '{string.Join(',', item.DesiredWMIValues.Select(x => x.Value))}'");
#endif
		}
	}

	/// <summary>
	/// Unified specialized verification strategy derived from JSON specification.
	/// </summary>
	private sealed class WmiJsonVerificationStrategy(
			string category,
			string wmiNamespace,
			string wmiClass,
			string wmiProperty,
			List<WmiDesiredValue> desiredValues) : ISpecializedVerificationStrategy
	{
		public bool Verify(RegistryPolicyEntry? targetPolicy = null)
		{
			try
			{
				// Availability check
				if (string.Equals(category, nameof(Categories.MicrosoftDefender), StringComparison.OrdinalIgnoreCase))
				{
					if (!MicrosoftDefenderVM.IsWmiPropertyAvailable(wmiNamespace, wmiClass, wmiProperty))
					{
						return false;
					}
				}

				if (desiredValues.Count == 0)
					return false;

				string command = $"get {wmiNamespace} {wmiClass} {wmiProperty}"; // Remove double quotes as some like SmartAppControlState get it coming from ComManager service

				string rawResult = QuantumRelayHSS.Client.RunCommand(GlobalVars.ComManagerProcessPath, command).Trim();
				string result;

				// Attempt to interpret the output as a JSON string first to properly handle escaped characters (like backslashes in paths).
				// ComManager outputs properly formatted JSON (strings are quoted and escaped).
				if (rawResult.StartsWith('"') && rawResult.EndsWith('"'))
				{
					try
					{
						result = JsonSerializer.Deserialize(rawResult, StringJsonContext.Default.String) ?? string.Empty;
					}
					catch
					{
						// if deserialization fails
						result = rawResult.Trim('"');
					}
				}
				else
				{
					// For boolean/numeric/null etc. outputs from ComManager which aren't quoted strings
					result = rawResult;
				}

				// If any of the desired values match then it means the security measure is applied on the system.
				foreach (WmiDesiredValue dv in CollectionsMarshal.AsSpan(desiredValues))
				{
					if (string.Equals(dv.Type, "string", StringComparison.OrdinalIgnoreCase))
					{
						if (string.Equals(result, dv.Value, StringComparison.OrdinalIgnoreCase))
						{
							return true;
						}
					}
					else if (string.Equals(dv.Type, "int", StringComparison.OrdinalIgnoreCase))
					{
						if (int.TryParse(result, out int actual) && int.TryParse(dv.Value, out int desired))
						{
							if (actual == desired)
							{
								return true;
							}
						}
					}
					else if (string.Equals(dv.Type, "bool", StringComparison.OrdinalIgnoreCase))
					{
						// Support canonical "true"/"false" and numeric "1"/"0" representations.
						if (!bool.TryParse(dv.Value, out bool desiredBool))
						{
							desiredBool = string.Equals(dv.Value, "1", StringComparison.OrdinalIgnoreCase) || (string.Equals(dv.Value, "0", StringComparison.OrdinalIgnoreCase)
									? false
									: throw new InvalidOperationException($"Unrecognized desired boolean format: '{dv.Value}'"));
						}

						if (!bool.TryParse(result, out bool actualBool))
						{
							actualBool = string.Equals(result, "1", StringComparison.OrdinalIgnoreCase) || (string.Equals(result, "0", StringComparison.OrdinalIgnoreCase)
									? false
									: throw new InvalidOperationException($"Unrecognized actual boolean format: '{result}'"));
						}

						if (actualBool == desiredBool)
						{
							return true;
						}
					}
					else
					{
						throw new InvalidOperationException($"Unrecognized desired value type: '{dv.Type}'");
					}
				}

				return false;
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
				return false;
			}
		}
	}
}

/// <summary>
/// Represents a unit that can contain any security measure.
/// It defines how to apply, remove and verify it.
/// </summary>
internal sealed partial class MUnit(
	Categories category,
	string? name,
	List<Intent> deviceIntents,
	Guid id,
	IApplyStrategy applyStrategy,
	IVerifyStrategy? verifyStrategy = null,
	IRemoveStrategy? removeStrategy = null,
	SubCategories? subCategory = null,
	string? url = null) : ViewModelBase
{
	/// <summary>
	/// The category this unit belongs to.
	/// </summary>
	[JsonInclude]
	[JsonPropertyOrder(1)]
	[JsonPropertyName("Category")]
	internal Categories Category => category;

	/// <summary>
	/// The name of this unit.
	/// </summary>
	[JsonInclude]
	[JsonPropertyName("Name")]
	[JsonPropertyOrder(0)]
	internal string? Name => name;

	/// <summary>
	/// What runs for applying this unit.
	/// </summary>
	[JsonIgnore]
	internal IApplyStrategy ApplyStrategy => applyStrategy;

	/// <summary>
	/// What runs for verifying this unit.
	/// Not all strategies need/can have verification.
	/// </summary>
	[JsonIgnore]
	internal IVerifyStrategy? VerifyStrategy => verifyStrategy;

	/// <summary>
	/// What runs for removing this unit.
	/// Not all strategies need/can have removal.
	/// </summary>
	[JsonIgnore]
	internal IRemoveStrategy? RemoveStrategy => removeStrategy;

	/// <summary>
	/// To store the result whether this protection measure is applied or not.
	/// </summary>
	[JsonInclude]
	[JsonPropertyOrder(2)]
	[JsonPropertyName("IsApplied")]
	internal bool? IsApplied
	{
		get; set
		{
			if (SP(ref field, value))
			{
				// Force immediate UI update on the correct thread
				_ = Dispatcher.TryEnqueue(() =>
				{
					OnPropertyChanged(nameof(StatusState));
				});
			}
		}
	}

	/// <summary>
	/// Optional sub-category this unit belongs to.
	/// </summary>
	[JsonInclude]
	[JsonPropertyOrder(4)]
	[JsonPropertyName("SubCategory")]
	internal SubCategories? SubCategory => subCategory;

	/// <summary>
	/// Used to point the ListView in the UI to a web location for more info or documentation.
	/// </summary>
	[JsonInclude]
	[JsonPropertyOrder(7)]
	[JsonPropertyName("URL")]
	internal string? URL => url;

	/// <summary>
	/// Device Intents this MUnit belongs to.
	/// </summary>
	[JsonInclude]
	[JsonPropertyOrder(6)]
	[JsonPropertyName("DeviceIntents")]
	internal List<Intent> DeviceIntents => deviceIntents;

	/// <summary>
	/// Reference to the user control that contains this MUnit. Set by the user control when the ViewModel is assigned.
	/// </summary>
	[JsonIgnore]
	internal MUnitListViewControl? UserControlReference { get; set; }

	/// <summary>
	/// Gets the unique identifier for this MUnit using Category|Name pattern (for non-JSON MUnits)
	/// </summary>
	[JsonIgnore]
	internal string MUnitId => $"{Category}|{Name}";

	/// <summary>
	/// Gets the registry-based identifier for JSON-based MUnits using KeyName|ValueName pattern
	/// Returns null for non-JSON based MUnits
	/// </summary>
	[JsonIgnore]
	internal string? JsonPolicyId
	{
		get
		{
			// Return the registry-based ID for JSON-based MUnits
			if (ApplyStrategy is IApplyGroupPolicy groupPolicyApply)
			{
				return $"{groupPolicyApply.Policy.KeyName}|{groupPolicyApply.Policy.ValueName}";
			}
			else if (ApplyStrategy is IApplyRegistry registryApply)
			{
				return $"{registryApply.Policy.KeyName}|{registryApply.Policy.ValueName}";
			}

			// Return null for non-JSON based MUnits
			return null;
		}
	}

	/// <summary>
	/// Properties for UI binding
	/// </summary>
	[JsonPropertyOrder(3)]
	[JsonPropertyName("StatusState")]
	public StatusState StatusState => IsApplied switch
	{
		true => StatusState.Applied,
		false => StatusState.NotApplied,
		null => StatusState.Undetermined
	};

	[JsonIgnore]
	internal bool HasSubCategory => SubCategory.HasValue;

	[JsonPropertyOrder(5)]
	[JsonPropertyName("SubCategoryName")]
	public string SubCategoryName => SubCategoryToDisplayString(SubCategory);

	[JsonInclude]
	[JsonPropertyOrder(100)]
	[JsonPropertyName("ID")]
	internal Guid ID => id;

	[JsonIgnore]
	internal bool HasURL => !string.IsNullOrWhiteSpace(URL);

	[JsonIgnore]
	internal Visibility SubCategoryVisibility => HasSubCategory ? Visibility.Visible : Visibility.Collapsed;

	[JsonIgnore]
	internal Visibility URLVisibility => HasURL ? Visibility.Visible : Visibility.Collapsed;

	/// <summary>
	/// Method to handle Apply button click
	/// </summary>
	internal void ApplyMUnit() => UserControlReference?.ApplyMUnit(this);

	/// <summary>
	/// Method to handle Remove button click
	/// </summary>
	internal void RemoveMUnit() => UserControlReference?.RemoveMUnit(this);

	/// <summary>
	/// Method to handle Verify button click
	/// </summary>
	internal void VerifyMUnit() => UserControlReference?.VerifyMUnit(this);

	/// <summary>
	/// Determines if an MUnit uses Group Policy strategies.
	/// </summary>
	/// <param name="mUnit">The MUnit to check</param>
	/// <returns>True if it's a Group Policy MUnit</returns>
	private static bool IsGroupPolicyMUnit(MUnit mUnit)
	{
		return mUnit.ApplyStrategy is IApplyGroupPolicy ||
			   mUnit.VerifyStrategy is IVerifyGroupPolicy ||
			   mUnit.RemoveStrategy is IRemoveGroupPolicy;
	}

	/// <summary>
	/// Determines if an MUnit uses Registry strategies.
	/// </summary>
	/// <param name="mUnit">The MUnit to check</param>
	/// <returns>True if it's a Registry MUnit</returns>
	private static bool IsRegistryMUnit(MUnit mUnit)
	{
		return mUnit.ApplyStrategy is IApplyRegistry ||
			   mUnit.VerifyStrategy is IVerifyRegistry ||
			   mUnit.RemoveStrategy is IRemoveRegistry;
	}

	/// <summary>
	/// Executes specialized strategies for the given policies at the specified timing.
	/// </summary>
	/// <param name="policies">The policies to process</param>
	/// <param name="timing">The execution timing</param>
	/// <param name="operation">The operation type</param>
	/// <param name="cancellationToken">Optional cancellation token</param>
	private static void ExecuteSpecializedStrategies(List<RegistryPolicyEntry> policies, ExecutionTiming timing, MUnitOperation operation, CancellationToken? cancellationToken = null)
	{
		foreach (RegistryPolicyEntry policy in CollectionsMarshal.AsSpan(policies))
		{
			cancellationToken?.ThrowIfCancellationRequested();

			string policyKey = $"{policy.KeyName}|{policy.ValueName}";

			try
			{
				if (operation == MUnitOperation.Apply)
				{
					if (SpecializedStrategiesRegistry._applyStrategies.TryGetValue(policyKey, out List<ISpecializedApplyStrategy>? strategies))
					{
						foreach (ISpecializedApplyStrategy strategy in strategies.Where(s => s.Timing == timing))
						{
							cancellationToken?.ThrowIfCancellationRequested();

							strategy.Apply();
							Logger.Write(string.Format(GlobalVars.GetStr("SpecializedApplySuccess"), timing, policy.KeyName, policy.ValueName));
						}
					}
				}
				else if (operation == MUnitOperation.Remove)
				{
					if (SpecializedStrategiesRegistry._removeStrategies.TryGetValue(policyKey, out List<ISpecializedRemoveStrategy>? strategies))
					{
						foreach (ISpecializedRemoveStrategy strategy in strategies.Where(s => s.Timing == timing))
						{
							cancellationToken?.ThrowIfCancellationRequested();

							strategy.Remove();
							Logger.Write(string.Format(GlobalVars.GetStr("SpecializedRemoveSuccess"), timing, policy.KeyName, policy.ValueName));
						}
					}
				}
			}
			catch (Exception ex)
			{
				if (IsCancellationException(ex)) throw; // Skip writing the custom error message since this is cancellation exception.
				Logger.Write(string.Format(GlobalVars.GetStr("ErrorInSpecializedStrategy"), operation, timing, policy.KeyName, policy.ValueName));
				throw;
			}
		}
	}

	/// <summary>
	/// Processes dependencies for a given timing and operation.
	/// </summary>
	/// <param name="mUnits">The primary MUnits being processed</param>
	/// <param name="allAvailableMUnits">All available MUnits for dependency resolution</param>
	/// <param name="operation">The operation being performed</param>
	/// <param name="timing">When to process dependencies</param>
	/// <param name="cancellationToken">Optional cancellation token</param>
	private static void ProcessDependenciesPhase(
		List<MUnit> mUnits,
		List<MUnit> allAvailableMUnits,
		MUnitOperation operation,
		ExecutionTiming timing,
		CancellationToken? cancellationToken = null)
	{
		cancellationToken?.ThrowIfCancellationRequested();

		// Lists to accumulate dependencies by type
		List<MUnit> groupPolicyDeps = [];
		List<MUnit> registryDeps = [];
		List<MUnit> regularDeps = [];
		int totalDependencies = 0;

		HashSet<Guid> processedIds = [];
		HashSet<Guid> visitedForCycleDetection = [];

		// First, collect all IDs from original MUnits to avoid duplicates
		foreach (MUnit mUnit in CollectionsMarshal.AsSpan(mUnits))
		{
			_ = processedIds.Add(mUnit.ID);
		}

		// Process dependencies
		foreach (MUnit mUnit in CollectionsMarshal.AsSpan(mUnits))
		{
			cancellationToken?.ThrowIfCancellationRequested();

			List<Guid> dependencyIds = MUnitDependencyRegistry.GetDependencies(mUnit.ID, operation, timing);

			foreach (Guid dependencyId in CollectionsMarshal.AsSpan(dependencyIds))
			{
				cancellationToken?.ThrowIfCancellationRequested();

				// Cycle detection
				if (!visitedForCycleDetection.Add(dependencyId))
				{
					Logger.Write(string.Format(GlobalVars.GetStr("DependencyCycleDetected"), dependencyId));
					continue;
				}

				// Skip if already in the original batch
				if (processedIds.Contains(dependencyId))
				{
					Logger.Write(string.Format(GlobalVars.GetStr("DependencySkip"), dependencyId));
					continue;
				}

				// Find the dependent MUnit by its ID.
				MUnit? dependentMUnit = allAvailableMUnits.FirstOrDefault(m => m.ID == dependencyId);

				if (dependentMUnit != null)
				{
					// Categorize
					if (IsGroupPolicyMUnit(dependentMUnit))
					{
						groupPolicyDeps.Add(dependentMUnit);
					}
					else if (IsRegistryMUnit(dependentMUnit))
					{
						registryDeps.Add(dependentMUnit);
					}
					else
					{
						regularDeps.Add(dependentMUnit);
					}

					totalDependencies++;
					_ = processedIds.Add(dependencyId);
					Logger.Write(string.Format(GlobalVars.GetStr("DependencyResolved"), mUnit.ID, dependencyId, operation, timing));
				}
				else
				{
					Logger.Write(string.Format(GlobalVars.GetStr("DependencyNotFound"), dependencyId, mUnit.ID));
				}
			}
		}

		if (totalDependencies == 0)
			return;

		string resourceKey = timing == ExecutionTiming.Before ? "ProcessingBeforeDependencies" : "ProcessingAfterDependencies";
		Logger.Write(string.Format(GlobalVars.GetStr(resourceKey), totalDependencies, operation));

		if (groupPolicyDeps.Count > 0)
		{
			ProcessMUnitsBulkUnified(groupPolicyDeps, operation, allAvailableMUnits, isGroupPolicy: true, cancellationToken);
		}

		if (registryDeps.Count > 0)
		{
			ProcessMUnitsBulkUnified(registryDeps, operation, allAvailableMUnits, isGroupPolicy: false, cancellationToken);
		}

		foreach (MUnit regularDep in regularDeps)
		{
			ProcessRegularMUnit(regularDep, operation, cancellationToken);
		}
	}

	/// <summary>
	/// One unified core method for Group Policy and Registry MUnits.
	/// isGroupPolicy = true  => Group Policy behavior (RegistryPolicyParser + POL verification with fallback)
	/// isGroupPolicy = false => Registry behavior (direct RegistryManager verification with fallback)
	/// </summary>
	private static void ProcessMUnitsBulkUnified(List<MUnit> mUnits, MUnitOperation operation, List<MUnit> allAvailableMUnits, bool isGroupPolicy, CancellationToken? cancellationToken = null)
	{
		cancellationToken?.ThrowIfCancellationRequested();

		List<RegistryPolicyEntry> allPolicies = [];

		// Collect all policies from the MUnits
		foreach (MUnit mUnit in mUnits)
		{
			cancellationToken?.ThrowIfCancellationRequested();

			RegistryPolicyEntry? policy = operation switch
			{
				// Apply
				MUnitOperation.Apply when isGroupPolicy && mUnit.ApplyStrategy is IApplyGroupPolicy applyGp => applyGp.Policy,
				MUnitOperation.Apply when !isGroupPolicy && mUnit.ApplyStrategy is IApplyRegistry applyReg => applyReg.Policy,

				// Remove
				MUnitOperation.Remove when isGroupPolicy && mUnit.RemoveStrategy is IRemoveGroupPolicy removeGp => removeGp.Policy,
				MUnitOperation.Remove when !isGroupPolicy && mUnit.RemoveStrategy is IRemoveRegistry removeReg => removeReg.Policy,

				// Verify
				MUnitOperation.Verify when isGroupPolicy && mUnit.VerifyStrategy is IVerifyGroupPolicy verifyGp => verifyGp.Policy,
				MUnitOperation.Verify when !isGroupPolicy && mUnit.VerifyStrategy is IVerifyRegistry verifyReg => verifyReg.Policy,

				_ => null
			};

			if (policy != null)
			{
				allPolicies.Add(policy);
			}
		}

		if (allPolicies.Count == 0)
		{
			return;
		}

		// Perform bulk operation with specialized strategies and dependencies
		switch (operation)
		{
			case MUnitOperation.Apply:
				{
					// Process Before dependencies
					ProcessDependenciesPhase(mUnits, allAvailableMUnits, operation, ExecutionTiming.Before, cancellationToken);

					// Execute-Before specialized apply strategies
					ExecuteSpecializedStrategies(allPolicies, ExecutionTiming.Before, operation, cancellationToken);

					cancellationToken?.ThrowIfCancellationRequested();

					// Execute main bulk apply operation
					// Split policies based on their Action:
					// Policies with Action=Apply should be Added/Set
					// Policies with Action=Remove should be Removed
					List<RegistryPolicyEntry> toAdd = allPolicies.Where(p => p.policyAction == PolicyAction.Apply).ToList();
					List<RegistryPolicyEntry> toRemove = allPolicies.Where(p => p.policyAction == PolicyAction.Remove).ToList();

					#region extra cleanup

					// For removal, we handle both standard names and "**del." legacy names.
					List<RegistryPolicyEntry> toRemoveProcessed = [];

					foreach (RegistryPolicyEntry entry in CollectionsMarshal.AsSpan(toRemove))
					{
						// Add the original entry
						toRemoveProcessed.Add(entry);

						toRemoveProcessed.Add(new(
							entry.Source,
							entry.KeyName,
							$"**del.{entry.ValueName}",
							entry.Type,
							entry.Size,
							entry.Data,
							entry.Hive,
							entry.ID
						));
					}

					#endregion

					if (isGroupPolicy)
					{
						if (toAdd.Count > 0)
							RegistryPolicyParser.AddPoliciesToSystem(toAdd, GroupPolicyContext.Machine);

						if (toRemoveProcessed.Count > 0)
							RegistryPolicyParser.RemovePoliciesFromSystem(toRemoveProcessed, GroupPolicyContext.Machine);
					}
					else
					{
						if (toAdd.Count > 0)
							CommonCore.RegistryManager.Manager.AddPoliciesToSystem(toAdd);

						if (toRemove.Count > 0)
							CommonCore.RegistryManager.Manager.RemovePoliciesFromSystem(toRemove);
					}

					// Execute-After specialized apply strategies
					ExecuteSpecializedStrategies(allPolicies, ExecutionTiming.After, operation, cancellationToken);

					// Process After dependencies
					ProcessDependenciesPhase(mUnits, allAvailableMUnits, operation, ExecutionTiming.After, cancellationToken);

					// Mark all as applied
					foreach (MUnit mUnit in mUnits)
					{
						mUnit.IsApplied = true;
					}
					break;
				}

			case MUnitOperation.Remove:
				{
					// Process Before dependencies
					ProcessDependenciesPhase(mUnits, allAvailableMUnits, operation, ExecutionTiming.Before, cancellationToken);

					// Execute-Before specialized remove strategies
					ExecuteSpecializedStrategies(allPolicies, ExecutionTiming.Before, operation, cancellationToken);

					cancellationToken?.ThrowIfCancellationRequested();

					// Execute main bulk remove operation
					// For Remove operation:
					// Policies with Action=Apply should be Removed
					// Policies with Action=Remove should be Skipped - Running a removal on a JSON policy with Action=Remove would mean restoring the key that was deleted to secure the system.
					List<RegistryPolicyEntry> toUndo = allPolicies.Where(p => p.policyAction == PolicyAction.Apply).ToList();

					if (toUndo.Count > 0)
					{
						if (isGroupPolicy)
						{
							RegistryPolicyParser.RemovePoliciesFromSystem(toUndo, GroupPolicyContext.Machine);
						}
						else
						{
							CommonCore.RegistryManager.Manager.RemovePoliciesFromSystem(toUndo);
						}
					}

					// Execute-After specialized remove strategies
					ExecuteSpecializedStrategies(allPolicies, ExecutionTiming.After, operation, cancellationToken);

					// Process After dependencies
					ProcessDependenciesPhase(mUnits, allAvailableMUnits, operation, ExecutionTiming.After, cancellationToken);

					// Mark all as not applied
					foreach (MUnit mUnit in CollectionsMarshal.AsSpan(mUnits))
					{
						mUnit.IsApplied = false;
					}
					break;
				}

			case MUnitOperation.Verify:
				{
					if (isGroupPolicy)
					{
						// Primary verification: check via POL file for the selected Group Policy context.
						// If any MUnit fails, fall back to direct registry verification (treat as Source = Registry).
						GroupPolicyContext contextForVerification = GroupPolicyContext.Machine;

						cancellationToken?.ThrowIfCancellationRequested();

						// 1) Verify against the POL file for the chosen context
						Dictionary<RegistryPolicyEntry, (bool IsCompliant, RegistryPolicyEntry? SystemEntry)> verificationResults =
									RegistryPolicyParser.VerifyPoliciesInSystem(allPolicies, contextForVerification);

						// 2) Per‑MUnit evaluation with fallback to direct Registry verification when needed
						foreach (MUnit mUnit in CollectionsMarshal.AsSpan(mUnits))
						{
							cancellationToken?.ThrowIfCancellationRequested();

							if (mUnit.VerifyStrategy is IVerifyGroupPolicy verifyStrategy)
							{
								// Check compliance of the policy
								RegistryPolicyEntry policy = verifyStrategy.Policy;

								if (verificationResults.TryGetValue(policy, out (bool IsCompliant, RegistryPolicyEntry? SystemEntry) resultTuple))
								{
									bool isConsideredCompliant = false;

									if (policy.policyAction == PolicyAction.Apply)
									{
										// Must be present and matching
										isConsideredCompliant = resultTuple.IsCompliant;
									}
									else if (policy.policyAction == PolicyAction.Remove)
									{
										// Must be absent (SystemEntry is null if not found)
										isConsideredCompliant = resultTuple.SystemEntry == null;
									}

									if (isConsideredCompliant)
									{
										mUnit.IsApplied = true;
										continue;
									}
								}

								// 3) Fallback: verify via Registry (treat as Source = Registry)
								// Clone as a Registry entry and set hive + RegValue (compute if missing)
								RegistryPolicyEntry fallbackEntry = new(
									source: Source.Registry,
									keyName: policy.KeyName,
									valueName: policy.ValueName,
									type: policy.Type,
									size: policy.Size,
									data: policy.Data,
									hive: policy.Hive,
									id: policy.ID)
								{
									// Ensure we have the string form expected by Registry verification if it's missing
									RegValue = policy.RegValue ?? CommonCore.RegistryManager.Manager.BuildRegValueFromParsedValue(policy)
								};

								Dictionary<RegistryPolicyEntry, bool> fallbackResults = CommonCore.RegistryManager.Manager.VerifyPoliciesInSystem([fallbackEntry]);

#if DEBUG
								// Log policies that failed POL verification but passed Registry fallback
								bool registryCompliant = false;
								if (fallbackResults.TryGetValue(fallbackEntry, out bool ok) && ok)
								{
									registryCompliant = true;
								}

								if (registryCompliant)
								{
									Logger.Write($"Verified via Registry fallback (GroupPolicy=>Registry): {policy.KeyName}\\{policy.ValueName} (Context: {contextForVerification})");
								}
#endif

								if (fallbackResults.TryGetValue(fallbackEntry, out bool isFallbackCompliant) && isFallbackCompliant)
								{
									Logger.Write($"MUnit '{mUnit.Name}' verified via Registry fallback (Context: {contextForVerification}).");
									mUnit.IsApplied = true;
									continue;
								}

								// 4) Final fallback: specialized verification
								bool specializedFallback = TryFallbackVerification(verifyStrategy.Policy, cancellationToken);
								mUnit.IsApplied = specializedFallback;
							}
						}
					}
					else
					{
						cancellationToken?.ThrowIfCancellationRequested();

						Dictionary<RegistryPolicyEntry, bool> verificationResults = CommonCore.RegistryManager.Manager.VerifyPoliciesInSystem(allPolicies);

						// Update status based on verification results, with fallback support
						foreach (MUnit mUnit in CollectionsMarshal.AsSpan(mUnits))
						{
							cancellationToken?.ThrowIfCancellationRequested();

							if (mUnit.VerifyStrategy is IVerifyRegistry verifyStrategy)
							{
								RegistryPolicyEntry policy = verifyStrategy.Policy;

								if (verificationResults.TryGetValue(policy, out bool isApplied) && isApplied)
								{
									mUnit.IsApplied = true;
								}
								else
								{
									// If primary verification is false, try fallback verification
									bool fallbackResult = TryFallbackVerification(verifyStrategy.Policy, cancellationToken);
									mUnit.IsApplied = fallbackResult;
								}
							}
						}
					}
					break;
				}

			default:
				break;
		}
	}

	/// <summary>
	/// Tries fallback verification for a policy whose Primary verification strategy results in false.
	/// These are used for cases where a security measure is applied via Group Policy or Registry,
	/// But the verification must be able to also detect it if it's applied via COM, Intune and/or other means.
	/// </summary>
	/// <param name="policy">The policy to check for fallback verification</param>
	/// <param name="cancellationToken">Optional cancellation token</param>
	/// <returns>True if the fallback verification succeeds, false otherwise</returns>
	private static bool TryFallbackVerification(RegistryPolicyEntry policy, CancellationToken? cancellationToken = null)
	{
		cancellationToken?.ThrowIfCancellationRequested();

		string policyKey = $"{policy.KeyName}|{policy.ValueName}";

		_ = SpecializedStrategiesRegistry._verificationStrategies.TryGetValue(policyKey, out ISpecializedVerificationStrategy? fallbackStrategy);

		if (fallbackStrategy != null)
		{
			try
			{
				// Pass the specific policy entry so the strategy knows exactly what values to expect
				bool fallbackResult = fallbackStrategy.Verify(policy);
				Logger.Write(string.Format(GlobalVars.GetStr("FallbackVerifyResult"), policy.KeyName, policy.ValueName, fallbackResult ? GlobalVars.GetStr("SUCCESS") : GlobalVars.GetStr("FAILED")));

				return fallbackResult;
			}
			catch (Exception ex)
			{
				if (IsCancellationException(ex)) throw; // Skip writing the custom error message since this is cancellation exception.
				Logger.Write(string.Format(GlobalVars.GetStr("ErrorInFallbackVerification"), policy.KeyName, policy.ValueName, ex.Message));
				throw;
			}
		}

		return false;
	}

	/// <summary>
	/// Processes a regular (non-Group Policy/Registry) MUnit individually.
	/// </summary>
	/// <param name="mUnit">The MUnit to process</param>
	/// <param name="operation">The operation to perform</param>
	/// <param name="cancellationToken">Optional cancellation token</param>
	private static void ProcessRegularMUnit(MUnit mUnit, MUnitOperation operation, CancellationToken? cancellationToken = null)
	{
		try
		{
			cancellationToken?.ThrowIfCancellationRequested();

			switch (operation)
			{
				case MUnitOperation.Apply:
					mUnit.ApplyStrategy.Apply();
					mUnit.IsApplied = true;
					break;

				case MUnitOperation.Remove:
					mUnit.RemoveStrategy?.Remove();
					mUnit.IsApplied = false;
					break;

				case MUnitOperation.Verify:
					if (mUnit.VerifyStrategy != null)
					{
						bool isApplied = mUnit.VerifyStrategy.Verify();
						mUnit.IsApplied = isApplied;
					}
					break;
				default:
					break;
			}
		}
		catch (Exception ex)
		{
			if (IsCancellationException(ex)) throw; // Skip writing the custom error message since this is cancellation exception.
			Logger.Write(string.Format(GlobalVars.GetStr("ErrorProcessingRegularMUnit"), mUnit.Name));
			throw;
		}
	}

	/// <summary>
	/// The core method that each ViewModel must implement to process MUnits with bulk operations.
	/// This will be called by the user control for all operations. Including single Apply/Remove/Verify buttons as well as those that operate on all items or only the selected items.
	/// </summary>
	/// <param name="viewModel"></param>
	/// <param name="mUnits"></param>
	/// <param name="operation"></param>
	/// <param name="cancellationToken">Optional cancellation token for the operation</param>
	internal async static Task ProcessMUnitsWithBulkOperations(IMUnitListViewModel viewModel, List<MUnit> mUnits, MUnitOperation operation, CancellationToken? cancellationToken = null)
	{
		await Task.Run(() =>
		{
			try
			{
				cancellationToken?.ThrowIfCancellationRequested();

				viewModel.ElementsAreEnabled = false;

				viewModel.MainInfoBar.IsClosable = false;

				string operationText = operation switch
				{
					MUnitOperation.Apply => GlobalVars.GetStr("ApplyingSecurityMeasures"),
					MUnitOperation.Remove => GlobalVars.GetStr("RemovingSecurityMeasures"),
					MUnitOperation.Verify => GlobalVars.GetStr("VerifyingSecurityMeasures"),
					_ => GlobalVars.GetStr("ProcessingSecurityMeasures")
				};
				viewModel.MainInfoBar.WriteInfo(string.Format(operationText, mUnits.Count));

				// Use the global catalog to ensure dependencies can be resolved across different categories.
				List<MUnit> allAvailableMUnits = Traverse.MUnitCatalog.All.Values.ToList();

				cancellationToken?.ThrowIfCancellationRequested();

				// Separate different types of MUnits
				List<MUnit> groupPolicyMUnits = [];
				List<MUnit> registryMUnits = [];
				List<MUnit> regularMUnits = [];

				foreach (MUnit mUnit in CollectionsMarshal.AsSpan(mUnits))
				{
					cancellationToken?.ThrowIfCancellationRequested();

					if (IsGroupPolicyMUnit(mUnit))
					{
						groupPolicyMUnits.Add(mUnit);
					}
					else if (IsRegistryMUnit(mUnit))
					{
						registryMUnits.Add(mUnit);
					}
					else
					{
						regularMUnits.Add(mUnit);
					}
				}

				// Process Group Policy MUnits in bulk with dependency support
				if (groupPolicyMUnits.Count > 0)
				{
					ProcessMUnitsBulkUnified(groupPolicyMUnits, operation, allAvailableMUnits, isGroupPolicy: true, cancellationToken);
				}

				// Process Registry MUnits in bulk with dependency support
				if (registryMUnits.Count > 0)
				{
					ProcessMUnitsBulkUnified(registryMUnits, operation, allAvailableMUnits, isGroupPolicy: false, cancellationToken);
				}

				// Process regular MUnits individually with dependency support
				foreach (MUnit mUnit in regularMUnits)
				{
					// Process Before dependencies
					if (operation == MUnitOperation.Apply || operation == MUnitOperation.Remove)
					{
						ProcessDependenciesPhase([mUnit], allAvailableMUnits, operation, ExecutionTiming.Before, cancellationToken);
					}

					ProcessRegularMUnit(mUnit, operation, cancellationToken);

					// Process After dependencies
					if (operation == MUnitOperation.Apply || operation == MUnitOperation.Remove)
					{
						ProcessDependenciesPhase([mUnit], allAvailableMUnits, operation, ExecutionTiming.After, cancellationToken);
					}
				}

				string operationText2 = operation switch
				{
					MUnitOperation.Apply => GlobalVars.GetStr("SuccessfullyAppliedSecurityMeasures"),
					MUnitOperation.Remove => GlobalVars.GetStr("SuccessfullyRemovedSecurityMeasures"),
					MUnitOperation.Verify => GlobalVars.GetStr("SuccessfullyVerifiedSecurityMeasures"),
					_ => GlobalVars.GetStr("SuccessfullyProcessedSecurityMeasures")
				};
				viewModel.MainInfoBar.WriteSuccess(string.Format(operationText2, mUnits.Count));
			}
			finally
			{
				viewModel.ElementsAreEnabled = true;
				viewModel.MainInfoBar.IsClosable = true;
			}
		}, cancellationToken ?? CancellationToken.None);
	}

	/// <summary>
	/// Creates MUnits from RegistryPolicyEntry items for a specific category.
	/// Automatically loads the JSON file based on the category and handles Group Policy and Registry sources.
	/// </summary>
	/// <param name="category">Category to create MUnits for</param>
	/// <returns>List of MUnits</returns>
	internal static List<MUnit> CreateMUnitsFromPolicies(Categories category)
	{
		List<MUnit> temp = [];

		// Build the full path to the JSON file
		string jsonConfigPath = Path.Combine(AppContext.BaseDirectory, "Resources", $"{category}.json");

		// Ensure specialized strategies are registered
		SpecializedStrategiesRegistry.RegisterWmiSpecializedVerificationsOnceFromFile();

		try
		{
			// Load the policies from the JSON file
			List<RegistryPolicyEntry> policies = RegistryPolicyEntry.LoadWithFriendlyNameKeyResolve(jsonConfigPath) ?? throw new InvalidOperationException(string.Format(GlobalVars.GetStr("CouldNotLoadPoliciesFromPath"), jsonConfigPath));

			foreach (RegistryPolicyEntry entry in policies)
			{

				// All security measures in JSON files must have Intents.
				if (entry.DeviceIntents is null)
					throw new InvalidOperationException($"The JSON file '{jsonConfigPath}' doesn't have device intents for all of its policies.");

				MUnit mUnit;

				if (entry.Source == Source.GroupPolicy)
				{
					// Create Group Policy MUnit
					mUnit = new(
						category: category,
						name: entry.FriendlyName,
						applyStrategy: new GroupPolicyApply(entry),
						verifyStrategy: new GroupPolicyVerify(entry),
						removeStrategy: new GroupPolicyRemove(entry),
						subCategory: entry.SubCategory,
						url: entry.URL,
						deviceIntents: entry.DeviceIntents,
						id: entry.ID);
				}
				else if (entry.Source == Source.Registry)
				{
					// Create Registry MUnit
					mUnit = new(
						category: category,
						name: entry.FriendlyName,
						applyStrategy: new RegistryApply(entry),
						verifyStrategy: new RegistryVerify(entry),
						removeStrategy: new RegistryRemove(entry),
						subCategory: entry.SubCategory,
						url: entry.URL,
						deviceIntents: entry.DeviceIntents,
						id: entry.ID);
				}
				else
				{
					throw new InvalidOperationException(string.Format(GlobalVars.GetStr("InvalidSource"), entry.Source));
				}

				temp.Add(mUnit);
			}
		}
		catch (Exception ex)
		{
			if (IsCancellationException(ex)) throw; // Skip writing the custom error message since this is cancellation exception.
			Logger.Write(string.Format(GlobalVars.GetStr("ErrorCreatingMUnitsForCategory"), category, ex.Message));
			throw;
		}

		return temp;
	}

	/// <summary>
	/// Used to normalize the subcategory name for display purposes.
	/// </summary>
	/// <param name="subCategory"></param>
	/// <returns></returns>
	private static string SubCategoryToDisplayString(SubCategories? subCategory)
	{
		if (subCategory is null)
			return string.Empty;

		string? name = subCategory.ToString();

		if (name is null)
			return string.Empty;

		int underscoreIndex = name.IndexOf('_');

		// Get the part after underscore if it exists, otherwise use the full name
		string processedName = underscoreIndex >= 0 ? name[(underscoreIndex + 1)..] : name;

		// Add spaces before capital letters, but keep consecutive capitals together
		StringBuilder result = new();

		for (int i = 0; i < processedName.Length; i++)
		{
			char currentChar = processedName[i];

			if (i > 0 && char.IsUpper(currentChar))
			{
				// Check if the previous character is lowercase
				// OR if current is uppercase and next is lowercase (end of consecutive capitals)
				char prevChar = processedName[i - 1];
				bool nextIsLower = i + 1 < processedName.Length && char.IsLower(processedName[i + 1]);

				if (char.IsLower(prevChar) || (char.IsUpper(prevChar) && nextIsLower))
				{
					_ = result.Append(' ');
				}
			}

			_ = result.Append(currentChar);
		}

		return result.ToString();
	}

	/// <summary>
	/// JSON deserialization constructor.
	/// Only includes parameters that have serializable properties.
	/// Strategies are replaced with safe no-op/null because importer maps by ID to MUnit catalog instances.
	/// </summary>
	[JsonConstructor]
	internal MUnit(
		Categories category,
		string? name,
		List<Intent> deviceIntents,
		Guid id,
		SubCategories? subCategory,
		string? url,
		bool? isApplied)
		: this(
			category: category,
			name: name,
			deviceIntents: deviceIntents,
			id: id,
			applyStrategy: new DefaultApply(() => { }), // no-op
			verifyStrategy: null,
			removeStrategy: null,
			subCategory: subCategory,
			url: url) => IsApplied = isApplied;
}

/// <summary>
/// Source generation context for deserializing strings.
/// </summary>
[JsonSerializable(typeof(string))]
internal sealed partial class StringJsonContext : JsonSerializerContext
{
}
