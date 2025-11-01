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
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AppControlManager.CustomUIElements;
using AppControlManager.ViewModels;
using HardenSystemSecurity.GroupPolicy;
using HardenSystemSecurity.Helpers;
using HardenSystemSecurity.SecurityPolicy;
using Microsoft.UI.Xaml;

namespace HardenSystemSecurity.Protect;

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
internal sealed class MUnitDependency(string dependentMUnitId, DependencyType type, ExecutionTiming timing)
{
	/// <summary>
	/// The unique identifier of the dependent MUnit.
	/// </summary>
	internal string DependentMUnitId => dependentMUnitId;

	/// <summary>
	/// The type of dependency (Apply, Remove, or Both).
	/// </summary>
	internal DependencyType Type => type;

	/// <summary>
	/// When the dependency should be executed relative to the primary operation.
	/// </summary>
	internal ExecutionTiming Timing => timing;
}

/// <summary>
/// Registry for managing MUnit dependencies specifically for JSON-based policies.
/// </summary>
internal static class MUnitDependencyRegistry
{
	/// <summary>
	/// Key: Primary MUnit identifier (KeyName|ValueName pattern)
	/// Value: List of dependent MUnit identifiers with their types
	/// </summary>
	private static readonly Dictionary<string, List<MUnitDependency>> _dependencies = new(StringComparer.OrdinalIgnoreCase);

	/// <summary>
	/// Registers a dependency relationship between two JSON-based MUnits using KeyName|ValueName pattern
	/// </summary>
	/// <param name="primaryMUnitId">The identifier of the primary MUnit (KeyName|ValueName format)</param>
	/// <param name="dependentMUnitId">The identifier of the dependent MUnit (KeyName|ValueName format)</param>
	/// <param name="type">The type of dependency</param>
	/// <param name="timing">When the dependency should be executed</param>
	internal static void RegisterDependency(string primaryMUnitId, string dependentMUnitId, DependencyType type, ExecutionTiming timing)
	{
		if (!_dependencies.TryGetValue(primaryMUnitId, out List<MUnitDependency>? value))
		{
			value = [];
			_dependencies[primaryMUnitId] = value;
		}

		value.Add(new MUnitDependency(dependentMUnitId, type, timing));
		Logger.Write(string.Format(GlobalVars.GetStr("JSONDependencyRegistered"), primaryMUnitId, dependentMUnitId, type, timing));
	}

	/// <summary>
	/// Gets dependencies for a specific JSON-based MUnit and operation
	/// </summary>
	/// <param name="mUnitId">The MUnit identifier (KeyName|ValueName format)</param>
	/// <param name="operation">The operation being performed</param>
	/// <param name="timing">The execution timing</param>
	/// <returns>List of dependent MUnit identifiers</returns>
	internal static List<string> GetDependencies(string mUnitId, MUnitOperation operation, ExecutionTiming timing)
	{
		if (!_dependencies.TryGetValue(mUnitId, out List<MUnitDependency>? dependencies))
		{
			return [];
		}

		return dependencies
			.Where(dep => dep.Timing == timing &&
						 (dep.Type == DependencyType.Both ||
						  (operation == MUnitOperation.Apply && dep.Type == DependencyType.Apply) ||
						  (operation == MUnitOperation.Remove && dep.Type == DependencyType.Remove)))
			.Select(dep => dep.DependentMUnitId)
			.ToList();
	}

	/// <summary>
	/// Clears all registered dependencies
	/// </summary>
	internal static void Clear()
	{
		_dependencies.Clear();
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
/// A marker + payload strategy for bulk security policy registry application.
/// Used for specific policies that we use SecurityPolicyWriter to apply.
/// </summary>
internal interface IApplySecurityPolicyRegistry : IApplyStrategy
{
	/// <summary>
	/// One or more Security Policy Registry entries that need to be applied for one specific protection measure.
	/// </summary>
	List<RegistryPolicyEntry> Policies { get; }
}

/// <summary>
/// Implementation of the <see cref="IApplySecurityPolicyRegistry"/> strategy.
/// </summary>
internal sealed class SecurityPolicyRegistryApply(List<RegistryPolicyEntry> policies) : IApplySecurityPolicyRegistry
{
	public List<RegistryPolicyEntry> Policies => policies;

	// This will never be called on its own: we bulk-invoke via SecurityPolicyManager instead.
	public void Apply() =>
		throw new InvalidOperationException(GlobalVars.GetStr("SecurityPolicyRegistryApplyBulkInvokeError"));
}

/// <summary>
/// A marker + payload strategy for bulk Group Policy application.
/// </summary>
internal interface IApplyGroupPolicy : IApplyStrategy
{
	/// <summary>
	/// One or more Group Policies that need to be applied for one specific protection measure.
	/// </summary>
	List<RegistryPolicyEntry> Policies { get; }
}

/// <summary>
/// Implementation of the <see cref="IApplyGroupPolicy"/> strategy.
/// </summary>
/// <param name="policies"></param>
internal sealed class GroupPolicyApply(List<RegistryPolicyEntry> policies) : IApplyGroupPolicy
{
	public List<RegistryPolicyEntry> Policies => policies;

	// This will never be called on its own: we bulk-invoke ApplyPolicies instead.
	public void Apply() => throw new InvalidOperationException(GlobalVars.GetStr("GroupPolicyApplyBulkInvokeError"));
}

/// <summary>
/// A marker + payload strategy for bulk Registry application.
/// </summary>
internal interface IApplyRegistry : IApplyStrategy
{
	/// <summary>
	/// One or more Registry policies that need to be applied for one specific protection measure.
	/// </summary>
	List<RegistryPolicyEntry> Policies { get; }
}

/// <summary>
/// Implementation of the <see cref="IApplyRegistry"/> strategy.
/// </summary>
/// <param name="policies"></param>
internal sealed class RegistryApply(List<RegistryPolicyEntry> policies) : IApplyRegistry
{
	public List<RegistryPolicyEntry> Policies => policies;

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
	bool Verify();
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
/// A marker + payload strategy for bulk Group Policy verification.
/// </summary>
internal interface IVerifyGroupPolicy : IVerifyStrategy
{
	/// <summary>
	/// One or more Group Policies that need to be verified for one specific protection measure.
	/// </summary>
	List<RegistryPolicyEntry> Policies { get; }
}

/// <summary>
/// Implementation of the <see cref="IVerifyGroupPolicy"/> strategy.
/// </summary>
/// <param name="policies"></param>
internal sealed class GroupPolicyVerify(List<RegistryPolicyEntry> policies) : IVerifyGroupPolicy
{
	public List<RegistryPolicyEntry> Policies => policies;

	// This will never be called on its own.
	public bool Verify() =>
		throw new InvalidOperationException(GlobalVars.GetStr("SecurityPolicyRegistryVerifyBulkInvokeError"));

}

/// <summary>
/// A marker + payload strategy for bulk Registry verification.
/// </summary>
internal interface IVerifyRegistry : IVerifyStrategy
{
	/// <summary>
	/// One or more Registry policies that need to be verified for one specific protection measure.
	/// </summary>
	List<RegistryPolicyEntry> Policies { get; }
}

/// <summary>
/// Implementation of the <see cref="IVerifyRegistry"/> strategy.
/// </summary>
/// <param name="policies"></param>
internal sealed class RegistryVerify(List<RegistryPolicyEntry> policies) : IVerifyRegistry
{
	public List<RegistryPolicyEntry> Policies => policies;

	// This will never be called on its own.
	public bool Verify() =>
		throw new InvalidOperationException(GlobalVars.GetStr("SecurityPolicyRegistryVerifyBulkInvokeError"));

}

/// <summary>
/// A marker + payload strategy for bulk Security Policy Registry verification.
/// </summary>
internal interface IVerifySecurityPolicyRegistry : IVerifyStrategy
{
	/// <summary>
	/// One or more Security Policy Registry entries that need to be verified for one specific protection measure.
	/// </summary>
	List<RegistryPolicyEntry> Policies { get; }
}

/// <summary>
/// Implementation of the <see cref="IVerifySecurityPolicyRegistry"/> strategy.
/// </summary>
/// <param name="policies"></param>
internal sealed class SecurityPolicyRegistryVerify(List<RegistryPolicyEntry> policies) : IVerifySecurityPolicyRegistry
{
	public List<RegistryPolicyEntry> Policies => policies;

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
/// A marker + payload strategy for bulk Group Policy removal.
/// </summary>
internal interface IRemoveGroupPolicy : IRemoveStrategy
{
	/// <summary>
	/// One or more Group Policies that need to be removed for one specific protection measure.
	/// </summary>
	List<RegistryPolicyEntry> Policies { get; }
}

/// <summary>
/// Implementation of the <see cref="IRemoveGroupPolicy"/> strategy.
/// </summary>
/// <param name="policies"></param>
internal sealed class GroupPolicyRemove(List<RegistryPolicyEntry> policies) : IRemoveGroupPolicy
{
	public List<RegistryPolicyEntry> Policies => policies;

	// This will never be called on its own.
	public void Remove() =>
		throw new InvalidOperationException(GlobalVars.GetStr("SecurityPolicyRegistryVerifyBulkInvokeError"));
}

/// <summary>
/// A marker + payload strategy for bulk Registry removal.
/// </summary>
internal interface IRemoveRegistry : IRemoveStrategy
{
	/// <summary>
	/// One or more Registry policies that need to be removed for one specific protection measure.
	/// </summary>
	List<RegistryPolicyEntry> Policies { get; }
}

/// <summary>
/// Implementation of the <see cref="IRemoveRegistry"/> strategy.
/// </summary>
/// <param name="policies"></param>
internal sealed class RegistryRemove(List<RegistryPolicyEntry> policies) : IRemoveRegistry
{
	public List<RegistryPolicyEntry> Policies => policies;

	// This will never be called on its own.
	public void Remove() =>
		throw new InvalidOperationException(GlobalVars.GetStr("SecurityPolicyRegistryVerifyBulkInvokeError"));
}

/// <summary>
/// A marker + payload strategy for bulk Security Policy Registry removal.
/// </summary>
internal interface IRemoveSecurityPolicyRegistry : IRemoveStrategy
{
	/// <summary>
	/// One or more Security Policy Registry entries that need to be removed for one specific protection measure.
	/// </summary>
	List<RegistryPolicyEntry> Policies { get; }
}

/// <summary>
/// Implementation of the <see cref="IRemoveSecurityPolicyRegistry"/> strategy.
/// </summary>
/// <param name="policies"></param>
internal sealed class SecurityPolicyRegistryRemove(List<RegistryPolicyEntry> policies) : IRemoveSecurityPolicyRegistry
{
	public List<RegistryPolicyEntry> Policies => policies;

	// This will never be called on its own.
	public void Remove() =>
		throw new InvalidOperationException(GlobalVars.GetStr("SecurityPolicyRegistryVerifyBulkInvokeError"));
}

/// <summary>
/// Repository for managing specialized strategies for verification, apply and remove operations.
/// </summary>
internal static class SpecializedStrategiesRegistry
{
	private static readonly Dictionary<string, ISpecializedVerificationStrategy> _verificationStrategies = new(StringComparer.OrdinalIgnoreCase);
	private static readonly Dictionary<string, List<ISpecializedApplyStrategy>> _applyStrategies = new(StringComparer.OrdinalIgnoreCase);
	private static readonly Dictionary<string, List<ISpecializedRemoveStrategy>> _removeStrategies = new(StringComparer.OrdinalIgnoreCase);

	/// <summary>
	/// Registers a specialized verification strategy for a specific policy.
	/// </summary>
	/// <param name="policyKey">The policy key in format "KeyName|ValueName"</param>
	/// <param name="strategy">The specialized verification strategy</param>
	internal static void RegisterSpecializedVerification(string policyKey, ISpecializedVerificationStrategy strategy)
	{
		_verificationStrategies[policyKey] = strategy;
	}

	/// <summary>
	/// Registers a specialized apply strategy for a specific policy.
	/// </summary>
	/// <param name="policyKey">The policy key in format "KeyName|ValueName"</param>
	/// <param name="strategy">The specialized apply strategy</param>
	internal static void RegisterSpecializedApply(string policyKey, ISpecializedApplyStrategy strategy)
	{
		if (!_applyStrategies.TryGetValue(policyKey, out List<ISpecializedApplyStrategy>? value))
		{
			value = [];
			_applyStrategies[policyKey] = value;
		}

		value.Add(strategy);
	}

	/// <summary>
	/// Registers a specialized remove strategy for a specific policy.
	/// </summary>
	/// <param name="policyKey">The policy key in format "KeyName|ValueName"</param>
	/// <param name="strategy">The specialized remove strategy</param>
	internal static void RegisterSpecializedRemove(string policyKey, ISpecializedRemoveStrategy strategy)
	{
		if (!_removeStrategies.TryGetValue(policyKey, out List<ISpecializedRemoveStrategy>? value))
		{
			value = [];
			_removeStrategies[policyKey] = value;
		}

		value.Add(strategy);
	}

	/// <summary>
	/// Gets a specialized verification strategy for a specific policy.
	/// </summary>
	/// <param name="policyKey">The policy key in format "KeyName|ValueName"</param>
	/// <returns>The specialized verification strategy or null if not found</returns>
	internal static ISpecializedVerificationStrategy? GetSpecializedVerification(string policyKey)
	{
		return _verificationStrategies.TryGetValue(policyKey, out ISpecializedVerificationStrategy? strategy) ? strategy : null;
	}

	/// <summary>
	/// Gets specialized apply strategies for a specific policy filtered by timing.
	/// </summary>
	/// <param name="policyKey">The policy key in format "KeyName|ValueName"</param>
	/// <param name="timing">The timing filter</param>
	/// <returns>List of specialized apply strategies with the specified timing</returns>
	internal static List<ISpecializedApplyStrategy> GetSpecializedApply(string policyKey, ExecutionTiming timing)
	{
		if (_applyStrategies.TryGetValue(policyKey, out List<ISpecializedApplyStrategy>? strategies))
		{
			return strategies.Where(s => s.Timing == timing).ToList();
		}
		return [];
	}

	/// <summary>
	/// Gets specialized remove strategies for a specific policy filtered by timing.
	/// </summary>
	/// <param name="policyKey">The policy key in format "KeyName|ValueName"</param>
	/// <param name="timing">The timing filter</param>
	/// <returns>List of specialized remove strategies with the specified timing</returns>
	internal static List<ISpecializedRemoveStrategy> GetSpecializedRemove(string policyKey, ExecutionTiming timing)
	{
		if (_removeStrategies.TryGetValue(policyKey, out List<ISpecializedRemoveStrategy>? strategies))
		{
			return strategies.Where(s => s.Timing == timing).ToList();
		}
		return [];
	}

	/// <summary>
	/// Clears all registered specialized strategies in the repository.
	/// </summary>
	internal static void Clear()
	{
		_verificationStrategies.Clear();
		_applyStrategies.Clear();
		_removeStrategies.Clear();
	}
}

/// <summary>
/// Represents a unit that can contain any security measure.
/// It defines how to apply, remove and verify it.
/// </summary>
internal sealed partial class MUnit(
	Categories category,
	string? name,
	List<DeviceIntents.Intent> deviceIntents,
	IApplyStrategy applyStrategy,
	IVerifyStrategy? verifyStrategy = null,
	IRemoveStrategy? removeStrategy = null,
	SubCategories? subCategory = null,
	string? url = null) : ViewModelBase
{
	/// <summary>
	/// The category this unit belongs to.
	/// </summary>
	internal Categories Category => category;

	/// <summary>
	/// The name of this unit.
	/// </summary>
	internal string? Name => name;

	/// <summary>
	/// What runs for applying this unit.
	/// </summary>
	internal IApplyStrategy ApplyStrategy => applyStrategy;

	/// <summary>
	/// What runs for verifying this unit.
	/// Not all strategies need/can have verification.
	/// </summary>
	internal IVerifyStrategy? VerifyStrategy => verifyStrategy;

	/// <summary>
	/// What runs for removing this unit.
	/// Not all strategies need/can have removal.
	/// </summary>
	internal IRemoveStrategy? RemoveStrategy => removeStrategy;

	/// <summary>
	/// To store the result whether this protection measure is applied or not.
	/// </summary>
	internal bool? IsApplied
	{
		get;
		set
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
	internal SubCategories? SubCategory => subCategory;

	/// <summary>
	/// Used to point the ListView in the UI to a web location for more info or documentation.
	/// </summary>
	internal string? URL => url;

	/// <summary>
	/// Device Intents this MUnit belongs to.
	/// </summary>
	internal List<DeviceIntents.Intent> DeviceIntents => deviceIntents;

	/// <summary>
	/// Reference to the user control that contains this MUnit. Set by the user control when the ViewModel is assigned.
	/// </summary>
	internal MUnitListViewControl? UserControlReference { get; set; }

	/// <summary>
	/// Gets the unique identifier for this MUnit using Category|Name pattern (for non-JSON MUnits)
	/// </summary>
	internal string MUnitId => $"{Category}|{Name}";

	/// <summary>
	/// Gets the registry-based identifier for JSON-based MUnits using KeyName|ValueName pattern
	/// Returns null for non-JSON based MUnits
	/// </summary>
	internal string? JsonPolicyId
	{
		get
		{
			// Return the registry-based ID for JSON-based MUnits
			if (ApplyStrategy is IApplyGroupPolicy groupPolicyApply && groupPolicyApply.Policies.Count > 0)
			{
				RegistryPolicyEntry policy = groupPolicyApply.Policies[0];
				return $"{policy.KeyName}|{policy.ValueName}";
			}
			else if (ApplyStrategy is IApplyRegistry registryApply && registryApply.Policies.Count > 0)
			{
				RegistryPolicyEntry policy = registryApply.Policies[0];
				return $"{policy.KeyName}|{policy.ValueName}";
			}
			else if (ApplyStrategy is IApplySecurityPolicyRegistry securityPolicyApply && securityPolicyApply.Policies.Count > 0)
			{
				RegistryPolicyEntry policy = securityPolicyApply.Policies[0];
				return $"{policy.KeyName}|{policy.ValueName}";
			}

			// Return null for non-JSON based MUnits
			return null;
		}
	}

	// Properties for UI binding
	internal StatusState StatusState => IsApplied switch
	{
		true => StatusState.Applied,
		false => StatusState.NotApplied,
		null => StatusState.Undetermined
	};

	internal bool HasSubCategory => SubCategory.HasValue;

	internal string SubCategoryName => SubCategoryToDisplayString(SubCategory);

	internal bool HasURL => !string.IsNullOrWhiteSpace(URL);

	internal Visibility SubCategoryVisibility => HasSubCategory ? Visibility.Visible : Visibility.Collapsed;

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
	/// Determines if an MUnit uses Security Policy Registry strategies.
	/// </summary>
	/// <param name="mUnit">The MUnit to check</param>
	/// <returns>True if it's a Security Policy Registry MUnit</returns>
	private static bool IsSecurityPolicyRegistryMUnit(MUnit mUnit)
	{
		return mUnit.ApplyStrategy is IApplySecurityPolicyRegistry ||
			   mUnit.VerifyStrategy is IVerifySecurityPolicyRegistry ||
			   mUnit.RemoveStrategy is IRemoveSecurityPolicyRegistry;
	}

	/// <summary>
	/// Determines if an MUnit is JSON-based.
	/// </summary>
	/// <param name="mUnit">The MUnit to check</param>
	/// <returns>True if it's a JSON-based MUnit</returns>
	private static bool IsJsonBasedMUnit(MUnit mUnit)
	{
		return mUnit.JsonPolicyId != null;
	}

	/// <summary>
	/// Resolves dependencies for JSON-based MUnits and returns additional MUnits (aka dependencies) to process.
	/// </summary>
	/// <param name="originalMUnits">The original MUnits requested by the user</param>
	/// <param name="allAvailableMUnits">All available MUnits in the category</param>
	/// <param name="operation">The operation being performed</param>
	/// <param name="timing">The execution timing</param>
	/// <param name="cancellationToken">Optional cancellation token</param>
	/// <returns>Additional MUnits to process due to dependencies</returns>
	private static List<MUnit> ResolveDependencies(List<MUnit> originalMUnits, List<MUnit> allAvailableMUnits, MUnitOperation operation, ExecutionTiming timing, CancellationToken? cancellationToken = null)
	{
		cancellationToken?.ThrowIfCancellationRequested();

		List<MUnit> dependentMUnits = [];
		HashSet<string> processedJsonIds = new(StringComparer.OrdinalIgnoreCase);
		HashSet<string> visitedForCycleDetection = new(StringComparer.OrdinalIgnoreCase);

		// First, collect all JSON-based policy IDs from original MUnits to avoid duplicates
		foreach (MUnit mUnit in originalMUnits)
		{
			if (mUnit.JsonPolicyId != null)
			{
				_ = processedJsonIds.Add(mUnit.JsonPolicyId);
			}
		}

		// Process dependencies only for JSON-based MUnits
		foreach (MUnit mUnit in originalMUnits.Where(IsJsonBasedMUnit))
		{
			cancellationToken?.ThrowIfCancellationRequested();

			if (mUnit.JsonPolicyId == null) continue;

			List<string> dependencyIds = MUnitDependencyRegistry.GetDependencies(mUnit.JsonPolicyId, operation, timing);

			foreach (string dependencyId in dependencyIds)
			{
				cancellationToken?.ThrowIfCancellationRequested();

				// Cycle detection
				if (visitedForCycleDetection.Contains(dependencyId))
				{
					Logger.Write(string.Format(GlobalVars.GetStr("DependencyCycleDetected"), dependencyId));
					continue;
				}

				_ = visitedForCycleDetection.Add(dependencyId);

				// Skip if already in the original batch
				if (processedJsonIds.Contains(dependencyId))
				{
					Logger.Write(string.Format(GlobalVars.GetStr("DependencySkip"), dependencyId));
					continue;
				}

				// Find the dependent MUnit by its JsonPolicyId in the same category
				MUnit? dependentMUnit = allAvailableMUnits.FirstOrDefault(m =>
					m.Category == mUnit.Category &&
					IsJsonBasedMUnit(m) &&
					string.Equals(m.JsonPolicyId, dependencyId, StringComparison.OrdinalIgnoreCase));

				if (dependentMUnit != null)
				{
					dependentMUnits.Add(dependentMUnit);
					_ = processedJsonIds.Add(dependencyId);
					Logger.Write(string.Format(GlobalVars.GetStr("DependencyResolved"), mUnit.JsonPolicyId, dependencyId, operation, timing));
				}
				else
				{
					Logger.Write(string.Format(GlobalVars.GetStr("DependencyNotFound"), dependencyId, mUnit.JsonPolicyId));
				}
			}
		}

		return dependentMUnits;
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
		foreach (RegistryPolicyEntry policy in policies)
		{
			cancellationToken?.ThrowIfCancellationRequested();

			string policyKey = $"{policy.KeyName}|{policy.ValueName}";

			try
			{
				if (operation == MUnitOperation.Apply)
				{
					List<ISpecializedApplyStrategy> applyStrategies = SpecializedStrategiesRegistry.GetSpecializedApply(policyKey, timing);
					foreach (ISpecializedApplyStrategy strategy in applyStrategies)
					{
						cancellationToken?.ThrowIfCancellationRequested();

						strategy.Apply();
						Logger.Write(string.Format(GlobalVars.GetStr("SpecializedApplySuccess"), timing, policy.KeyName, policy.ValueName));
					}
				}
				else if (operation == MUnitOperation.Remove)
				{
					List<ISpecializedRemoveStrategy> removeStrategies = SpecializedStrategiesRegistry.GetSpecializedRemove(policyKey, timing);
					foreach (ISpecializedRemoveStrategy strategy in removeStrategies)
					{
						cancellationToken?.ThrowIfCancellationRequested();

						strategy.Remove();
						Logger.Write(string.Format(GlobalVars.GetStr("SpecializedRemoveSuccess"), timing, policy.KeyName, policy.ValueName));
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
	/// Processes Group Policy MUnits in bulk.
	/// </summary>
	/// <param name="groupPolicyMUnits">The Group Policy MUnits to process</param>
	/// <param name="operation">The operation to perform</param>
	/// <param name="allAvailableMUnits">All available MUnits for dependency resolution</param>
	/// <param name="cancellationToken">Optional cancellation token</param>
	private static void ProcessGroupPolicyMUnitsBulk(List<MUnit> groupPolicyMUnits, MUnitOperation operation, List<MUnit> allAvailableMUnits, CancellationToken? cancellationToken = null)
	{
		try
		{
			cancellationToken?.ThrowIfCancellationRequested();

			List<RegistryPolicyEntry> allPolicies = [];

			// Collect all policies from the MUnits
			foreach (MUnit mUnit in groupPolicyMUnits)
			{
				cancellationToken?.ThrowIfCancellationRequested();

				List<RegistryPolicyEntry>? policies = operation switch
				{
					MUnitOperation.Apply when mUnit.ApplyStrategy is IApplyGroupPolicy applyStrategy => applyStrategy.Policies,
					MUnitOperation.Remove when mUnit.RemoveStrategy is IRemoveGroupPolicy removeStrategy => removeStrategy.Policies,
					MUnitOperation.Verify when mUnit.VerifyStrategy is IVerifyGroupPolicy verifyStrategy => verifyStrategy.Policies,
					_ => null
				};

				if (policies != null)
				{
					allPolicies.AddRange(policies);
				}
			}

			if (allPolicies.Count > 0)
			{
				// Perform bulk operation with specialized strategies and dependencies
				switch (operation)
				{
					case MUnitOperation.Apply:
						// Process Before dependencies for JSON-based MUnits
						List<MUnit> beforeDependencies = ResolveDependencies(groupPolicyMUnits, allAvailableMUnits, operation, ExecutionTiming.Before, cancellationToken);
						if (beforeDependencies.Count > 0)
						{
							Logger.Write(string.Format(GlobalVars.GetStr("ProcessingBeforeDependencies"), beforeDependencies.Count, operation));
							ProcessGroupPolicyMUnitsBulk(beforeDependencies.Where(IsGroupPolicyMUnit).ToList(), operation, allAvailableMUnits, cancellationToken);
							ProcessRegistryMUnitsBulk(beforeDependencies.Where(IsRegistryMUnit).ToList(), operation, allAvailableMUnits, cancellationToken);
							ProcessSecurityPolicyRegistryMUnitsBulk(beforeDependencies.Where(IsSecurityPolicyRegistryMUnit).ToList(), operation, allAvailableMUnits, cancellationToken);
							foreach (MUnit regularDep in beforeDependencies.Where(m => !IsGroupPolicyMUnit(m) && !IsRegistryMUnit(m) && !IsSecurityPolicyRegistryMUnit(m)))
							{
								ProcessRegularMUnit(regularDep, operation, cancellationToken);
							}
						}

						// Execute-Before specialized apply strategies
						ExecuteSpecializedStrategies(allPolicies, ExecutionTiming.Before, operation, cancellationToken);

						cancellationToken?.ThrowIfCancellationRequested();

						// Execute main bulk apply operation
						RegistryPolicyParser.AddPoliciesToSystem(allPolicies, GroupPolicyContext.Machine);

						// Execute-After specialized apply strategies
						ExecuteSpecializedStrategies(allPolicies, ExecutionTiming.After, operation, cancellationToken);

						// Process After dependencies for JSON-based MUnits
						List<MUnit> afterDependencies = ResolveDependencies(groupPolicyMUnits, allAvailableMUnits, operation, ExecutionTiming.After, cancellationToken);
						if (afterDependencies.Count > 0)
						{
							Logger.Write(string.Format(GlobalVars.GetStr("ProcessingAfterDependencies"), afterDependencies.Count, operation));
							ProcessGroupPolicyMUnitsBulk(afterDependencies.Where(IsGroupPolicyMUnit).ToList(), operation, allAvailableMUnits, cancellationToken);
							ProcessRegistryMUnitsBulk(afterDependencies.Where(IsRegistryMUnit).ToList(), operation, allAvailableMUnits, cancellationToken);
							ProcessSecurityPolicyRegistryMUnitsBulk(afterDependencies.Where(IsSecurityPolicyRegistryMUnit).ToList(), operation, allAvailableMUnits, cancellationToken);
							foreach (MUnit regularDep in afterDependencies.Where(m => !IsGroupPolicyMUnit(m) && !IsRegistryMUnit(m) && !IsSecurityPolicyRegistryMUnit(m)))
							{
								ProcessRegularMUnit(regularDep, operation, cancellationToken);
							}
						}

						// Mark all as applied
						foreach (MUnit mUnit in groupPolicyMUnits)
						{
							mUnit.IsApplied = true;
						}
						break;

					case MUnitOperation.Remove:
						// Process Before dependencies for JSON-based MUnits
						List<MUnit> beforeRemoveDependencies = ResolveDependencies(groupPolicyMUnits, allAvailableMUnits, operation, ExecutionTiming.Before, cancellationToken);
						if (beforeRemoveDependencies.Count > 0)
						{
							Logger.Write(string.Format(GlobalVars.GetStr("ProcessingBeforeDependencies"), beforeRemoveDependencies.Count, operation));
							ProcessGroupPolicyMUnitsBulk(beforeRemoveDependencies.Where(IsGroupPolicyMUnit).ToList(), operation, allAvailableMUnits, cancellationToken);
							ProcessRegistryMUnitsBulk(beforeRemoveDependencies.Where(IsRegistryMUnit).ToList(), operation, allAvailableMUnits, cancellationToken);
							ProcessSecurityPolicyRegistryMUnitsBulk(beforeRemoveDependencies.Where(IsSecurityPolicyRegistryMUnit).ToList(), operation, allAvailableMUnits, cancellationToken);
							foreach (MUnit regularDep in beforeRemoveDependencies.Where(m => !IsGroupPolicyMUnit(m) && !IsRegistryMUnit(m) && !IsSecurityPolicyRegistryMUnit(m)))
							{
								ProcessRegularMUnit(regularDep, operation, cancellationToken);
							}
						}

						// Execute-Before specialized remove strategies
						ExecuteSpecializedStrategies(allPolicies, ExecutionTiming.Before, operation, cancellationToken);

						cancellationToken?.ThrowIfCancellationRequested();

						// Execute main bulk remove operation
						RegistryPolicyParser.RemovePoliciesFromSystem(allPolicies, GroupPolicyContext.Machine);

						// Execute-After specialized remove strategies
						ExecuteSpecializedStrategies(allPolicies, ExecutionTiming.After, operation, cancellationToken);

						// Process After dependencies for JSON-based MUnits
						List<MUnit> afterRemoveDependencies = ResolveDependencies(groupPolicyMUnits, allAvailableMUnits, operation, ExecutionTiming.After, cancellationToken);
						if (afterRemoveDependencies.Count > 0)
						{
							Logger.Write(string.Format(GlobalVars.GetStr("ProcessingAfterDependencies"), afterRemoveDependencies.Count, operation));
							ProcessGroupPolicyMUnitsBulk(afterRemoveDependencies.Where(IsGroupPolicyMUnit).ToList(), operation, allAvailableMUnits, cancellationToken);
							ProcessRegistryMUnitsBulk(afterRemoveDependencies.Where(IsRegistryMUnit).ToList(), operation, allAvailableMUnits, cancellationToken);
							ProcessSecurityPolicyRegistryMUnitsBulk(afterRemoveDependencies.Where(IsSecurityPolicyRegistryMUnit).ToList(), operation, allAvailableMUnits, cancellationToken);
							foreach (MUnit regularDep in afterRemoveDependencies.Where(m => !IsGroupPolicyMUnit(m) && !IsRegistryMUnit(m) && !IsSecurityPolicyRegistryMUnit(m)))
							{
								ProcessRegularMUnit(regularDep, operation, cancellationToken);
							}
						}

						// Mark all as not applied
						foreach (MUnit mUnit in groupPolicyMUnits)
						{
							mUnit.IsApplied = false;
						}
						break;

					case MUnitOperation.Verify:
						// Primary verification: check via POL file for the selected Group Policy context.
						// If any MUnit fails, fall back to direct registry verification (treat as Source = Registry).
						GroupPolicyContext contextForVerification = GroupPolicyContext.Machine;

						cancellationToken?.ThrowIfCancellationRequested();

						// 1) Verify against the POL file for the chosen context
						Dictionary<RegistryPolicyEntry, (bool IsCompliant, RegistryPolicyEntry? SystemEntry)> verificationResults =
									RegistryPolicyParser.VerifyPoliciesInSystem(allPolicies, contextForVerification);

						// 2) Per‑MUnit evaluation with fallback to direct Registry verification when needed
						foreach (MUnit mUnit in groupPolicyMUnits)
						{
							cancellationToken?.ThrowIfCancellationRequested();

							if (mUnit.VerifyStrategy is IVerifyGroupPolicy verifyStrategy)
							{
								// Determine if all of this MUnit's policies are compliant via POL
								bool allPoliciesAppliedViaPol = true;
								foreach (RegistryPolicyEntry policy in verifyStrategy.Policies)
								{
									if (!verificationResults.TryGetValue(policy, out (bool IsCompliant, RegistryPolicyEntry? SystemEntry) resultTuple) || !resultTuple.IsCompliant)
									{
										allPoliciesAppliedViaPol = false;
										break;
									}
								}

								if (allPoliciesAppliedViaPol)
								{
									mUnit.IsApplied = true;
									continue;
								}

								// 3) Fallback: verify via Registry (treat as Source = Registry)
								List<RegistryPolicyEntry> fallbackRegistryPolicies = new(verifyStrategy.Policies.Count);
								foreach (RegistryPolicyEntry policy in verifyStrategy.Policies)
								{
									cancellationToken?.ThrowIfCancellationRequested();

									// Clone as a Registry entry and set hive + RegValue (compute if missing)
									RegistryPolicyEntry fallbackEntry = new(
										source: Source.Registry,
										keyName: policy.KeyName,
										valueName: policy.ValueName,
										type: policy.Type,
										size: policy.Size,
										data: policy.Data,
										hive: policy.Hive)
									{
										// Ensure we have the string form expected by Registry verification if it's missing
										RegValue = policy.RegValue ?? RegistryManager.Manager.BuildRegValueFromParsedValue(policy)
									};

									fallbackRegistryPolicies.Add(fallbackEntry);
								}

								Dictionary<RegistryPolicyEntry, bool> fallbackResults = RegistryManager.Manager.VerifyPoliciesInSystem(fallbackRegistryPolicies);

#if DEBUG
								// Log policies that failed POL verification but passed Registry fallback
								for (int i = 0; i < verifyStrategy.Policies.Count && i < fallbackRegistryPolicies.Count; i++)
								{
									RegistryPolicyEntry originalPolicy = verifyStrategy.Policies[i];
									RegistryPolicyEntry fallbackEntry = fallbackRegistryPolicies[i];

									bool polCompliant = false;
									if (verificationResults.TryGetValue(originalPolicy, out (bool IsCompliant, RegistryPolicyEntry? SystemEntry) polTuple) && polTuple.IsCompliant)
									{
										polCompliant = true;
									}

									bool registryCompliant = false;
									if (fallbackResults.TryGetValue(fallbackEntry, out bool ok) && ok)
									{
										registryCompliant = true;
									}

									if (!polCompliant && registryCompliant)
									{
										Logger.Write($"Verified via Registry fallback (GroupPolicy=>Registry): {originalPolicy.KeyName}\\{originalPolicy.ValueName} (Context: {contextForVerification})");
									}
								}
#endif

								bool allPoliciesAppliedViaRegistry = true;
								foreach (KeyValuePair<RegistryPolicyEntry, bool> kvp in fallbackResults)
								{
									if (!kvp.Value)
									{
										allPoliciesAppliedViaRegistry = false;
										break;
									}
								}

								if (allPoliciesAppliedViaRegistry)
								{
									Logger.Write($"MUnit '{mUnit.Name}' verified via Registry fallback for all policies (Context: {contextForVerification}).");
									mUnit.IsApplied = true;
									continue;
								}

								// 4) Final fallback: specialized verification
								bool specializedFallback = TryFallbackVerification(verifyStrategy.Policies, cancellationToken);
								mUnit.IsApplied = specializedFallback;
							}
						}
						break;
					default:
						break;
				}
			}
		}
		catch (Exception ex)
		{
			if (IsCancellationException(ex)) throw; // Skip writing the custom error message since this is cancellation exception.
			Logger.Write(GlobalVars.GetStr("ErrorProcessingGroupPolicyMUnits"));
			throw;
		}
	}

	/// <summary>
	/// Processes Registry MUnits in bulk.
	/// </summary>
	/// <param name="registryMUnits">The Registry MUnits to process</param>
	/// <param name="operation">The operation to perform</param>
	/// <param name="allAvailableMUnits">All available MUnits for dependency resolution</param>
	/// <param name="cancellationToken">Optional cancellation token</param>
	private static void ProcessRegistryMUnitsBulk(List<MUnit> registryMUnits, MUnitOperation operation, List<MUnit> allAvailableMUnits, CancellationToken? cancellationToken = null)
	{
		try
		{
			cancellationToken?.ThrowIfCancellationRequested();

			List<RegistryPolicyEntry> allPolicies = [];

			// Collect all policies from the MUnits
			foreach (MUnit mUnit in registryMUnits)
			{
				cancellationToken?.ThrowIfCancellationRequested();

				List<RegistryPolicyEntry>? policies = operation switch
				{
					MUnitOperation.Apply when mUnit.ApplyStrategy is IApplyRegistry applyStrategy => applyStrategy.Policies,
					MUnitOperation.Remove when mUnit.RemoveStrategy is IRemoveRegistry removeStrategy => removeStrategy.Policies,
					MUnitOperation.Verify when mUnit.VerifyStrategy is IVerifyRegistry verifyStrategy => verifyStrategy.Policies,
					_ => null
				};

				if (policies != null)
				{
					allPolicies.AddRange(policies);
				}
			}

			if (allPolicies.Count > 0)
			{
				// Perform bulk operation with specialized strategies and dependencies
				switch (operation)
				{
					case MUnitOperation.Apply:
						// Process Before dependencies for JSON-based MUnits
						List<MUnit> beforeDependencies = ResolveDependencies(registryMUnits, allAvailableMUnits, operation, ExecutionTiming.Before, cancellationToken);
						if (beforeDependencies.Count > 0)
						{
							Logger.Write(string.Format(GlobalVars.GetStr("ProcessingBeforeDependencies"), beforeDependencies.Count, operation));
							ProcessGroupPolicyMUnitsBulk(beforeDependencies.Where(IsGroupPolicyMUnit).ToList(), operation, allAvailableMUnits, cancellationToken);
							ProcessRegistryMUnitsBulk(beforeDependencies.Where(IsRegistryMUnit).ToList(), operation, allAvailableMUnits, cancellationToken);
							ProcessSecurityPolicyRegistryMUnitsBulk(beforeDependencies.Where(IsSecurityPolicyRegistryMUnit).ToList(), operation, allAvailableMUnits, cancellationToken);
							foreach (MUnit regularDep in beforeDependencies.Where(m => !IsGroupPolicyMUnit(m) && !IsRegistryMUnit(m) && !IsSecurityPolicyRegistryMUnit(m)))
							{
								ProcessRegularMUnit(regularDep, operation, cancellationToken);
							}
						}

						// Execute-Before specialized apply strategies
						ExecuteSpecializedStrategies(allPolicies, ExecutionTiming.Before, operation, cancellationToken);

						cancellationToken?.ThrowIfCancellationRequested();

						// Execute main bulk apply operation
						RegistryManager.Manager.AddPoliciesToSystem(allPolicies);

						// Execute-After specialized apply strategies
						ExecuteSpecializedStrategies(allPolicies, ExecutionTiming.After, operation, cancellationToken);

						// Process After dependencies for JSON-based MUnits
						List<MUnit> afterDependencies = ResolveDependencies(registryMUnits, allAvailableMUnits, operation, ExecutionTiming.After, cancellationToken);
						if (afterDependencies.Count > 0)
						{
							Logger.Write(string.Format(GlobalVars.GetStr("ProcessingAfterDependencies"), afterDependencies.Count, operation));
							ProcessGroupPolicyMUnitsBulk(afterDependencies.Where(IsGroupPolicyMUnit).ToList(), operation, allAvailableMUnits, cancellationToken);
							ProcessRegistryMUnitsBulk(afterDependencies.Where(IsRegistryMUnit).ToList(), operation, allAvailableMUnits, cancellationToken);
							ProcessSecurityPolicyRegistryMUnitsBulk(afterDependencies.Where(IsSecurityPolicyRegistryMUnit).ToList(), operation, allAvailableMUnits, cancellationToken);
							foreach (MUnit regularDep in afterDependencies.Where(m => !IsGroupPolicyMUnit(m) && !IsRegistryMUnit(m) && !IsSecurityPolicyRegistryMUnit(m)))
							{
								ProcessRegularMUnit(regularDep, operation, cancellationToken);
							}
						}

						// Mark all as applied
						foreach (MUnit mUnit in registryMUnits)
						{
							mUnit.IsApplied = true;
						}
						break;

					case MUnitOperation.Remove:
						// Process Before dependencies for JSON-based MUnits
						List<MUnit> beforeRemoveDependencies = ResolveDependencies(registryMUnits, allAvailableMUnits, operation, ExecutionTiming.Before, cancellationToken);
						if (beforeRemoveDependencies.Count > 0)
						{
							Logger.Write(string.Format(GlobalVars.GetStr("ProcessingBeforeDependencies"), beforeRemoveDependencies.Count, operation));
							ProcessGroupPolicyMUnitsBulk(beforeRemoveDependencies.Where(IsGroupPolicyMUnit).ToList(), operation, allAvailableMUnits, cancellationToken);
							ProcessRegistryMUnitsBulk(beforeRemoveDependencies.Where(IsRegistryMUnit).ToList(), operation, allAvailableMUnits, cancellationToken);
							ProcessSecurityPolicyRegistryMUnitsBulk(beforeRemoveDependencies.Where(IsSecurityPolicyRegistryMUnit).ToList(), operation, allAvailableMUnits, cancellationToken);
							foreach (MUnit regularDep in beforeRemoveDependencies.Where(m => !IsGroupPolicyMUnit(m) && !IsRegistryMUnit(m) && !IsSecurityPolicyRegistryMUnit(m)))
							{
								ProcessRegularMUnit(regularDep, operation, cancellationToken);
							}
						}

						// Execute-Before specialized remove strategies
						ExecuteSpecializedStrategies(allPolicies, ExecutionTiming.Before, operation, cancellationToken);

						cancellationToken?.ThrowIfCancellationRequested();

						// Execute main bulk remove operation
						RegistryManager.Manager.RemovePoliciesFromSystem(allPolicies);

						// Execute-After specialized remove strategies
						ExecuteSpecializedStrategies(allPolicies, ExecutionTiming.After, operation, cancellationToken);

						// Process After dependencies for JSON-based MUnits
						List<MUnit> afterRemoveDependencies = ResolveDependencies(registryMUnits, allAvailableMUnits, operation, ExecutionTiming.After, cancellationToken);
						if (afterRemoveDependencies.Count > 0)
						{
							Logger.Write(string.Format(GlobalVars.GetStr("ProcessingAfterDependencies"), afterRemoveDependencies.Count, operation));
							ProcessGroupPolicyMUnitsBulk(afterRemoveDependencies.Where(IsGroupPolicyMUnit).ToList(), operation, allAvailableMUnits, cancellationToken);
							ProcessRegistryMUnitsBulk(afterRemoveDependencies.Where(IsRegistryMUnit).ToList(), operation, allAvailableMUnits, cancellationToken);
							ProcessSecurityPolicyRegistryMUnitsBulk(afterRemoveDependencies.Where(IsSecurityPolicyRegistryMUnit).ToList(), operation, allAvailableMUnits, cancellationToken);
							foreach (MUnit regularDep in afterRemoveDependencies.Where(m => !IsGroupPolicyMUnit(m) && !IsRegistryMUnit(m) && !IsSecurityPolicyRegistryMUnit(m)))
							{
								ProcessRegularMUnit(regularDep, operation, cancellationToken);
							}
						}

						// Mark all as not applied
						foreach (MUnit mUnit in registryMUnits)
						{
							mUnit.IsApplied = false;
						}
						break;

					case MUnitOperation.Verify:
						cancellationToken?.ThrowIfCancellationRequested();

						Dictionary<RegistryPolicyEntry, bool> verificationResults = RegistryManager.Manager.VerifyPoliciesInSystem(allPolicies);

						// Update status based on verification results, with fallback support
						foreach (MUnit mUnit in registryMUnits)
						{
							cancellationToken?.ThrowIfCancellationRequested();

							if (mUnit.VerifyStrategy is IVerifyRegistry verifyStrategy)
							{
								bool allPoliciesApplied = true;
								foreach (RegistryPolicyEntry policy in verifyStrategy.Policies)
								{
									if (!verificationResults.TryGetValue(policy, out bool isApplied) || !isApplied)
									{
										allPoliciesApplied = false;
										break;
									}
								}

								// If primary verification is false, try fallback verification
								if (!allPoliciesApplied)
								{
									bool fallbackResult = TryFallbackVerification(verifyStrategy.Policies, cancellationToken);
									mUnit.IsApplied = fallbackResult;
								}
								else
								{
									mUnit.IsApplied = true;
								}
							}
						}
						break;
					default:
						break;
				}
			}
		}
		catch (Exception ex)
		{
			if (IsCancellationException(ex)) throw; // Skip writing the custom error message since this is cancellation exception.
			Logger.Write(GlobalVars.GetStr("ErrorProcessingRegistryMUnits"));
			throw;
		}
	}

	/// <summary>
	/// Processes Security Policy Registry MUnits in bulk.
	/// </summary>
	/// <param name="securityPolicyRegistryMUnits">The Security Policy Registry MUnits to process</param>
	/// <param name="operation">The operation to perform</param>
	/// <param name="allAvailableMUnits">All available MUnits for dependency resolution</param>
	/// <param name="cancellationToken">Optional cancellation token</param>
	private static void ProcessSecurityPolicyRegistryMUnitsBulk(List<MUnit> securityPolicyRegistryMUnits, MUnitOperation operation, List<MUnit> allAvailableMUnits, CancellationToken? cancellationToken = null)
	{
		try
		{
			cancellationToken?.ThrowIfCancellationRequested();

			List<RegistryPolicyEntry> allPolicies = [];

			// Collect all policies from the MUnits
			foreach (MUnit mUnit in securityPolicyRegistryMUnits)
			{
				cancellationToken?.ThrowIfCancellationRequested();

				List<RegistryPolicyEntry>? policies = operation switch
				{
					MUnitOperation.Apply when mUnit.ApplyStrategy is IApplySecurityPolicyRegistry applyStrategy => applyStrategy.Policies,
					MUnitOperation.Remove when mUnit.RemoveStrategy is IRemoveSecurityPolicyRegistry removeStrategy => removeStrategy.Policies,
					MUnitOperation.Verify when mUnit.VerifyStrategy is IVerifySecurityPolicyRegistry verifyStrategy => verifyStrategy.Policies,
					_ => null
				};

				if (policies != null)
				{
					allPolicies.AddRange(policies);
				}
			}

			if (allPolicies.Count > 0)
			{
				// Perform bulk operation with specialized strategies and dependencies
				switch (operation)
				{
					case MUnitOperation.Apply:
						// Process Before dependencies for JSON-based MUnits
						List<MUnit> beforeDependencies = ResolveDependencies(securityPolicyRegistryMUnits, allAvailableMUnits, operation, ExecutionTiming.Before, cancellationToken);
						if (beforeDependencies.Count > 0)
						{
							Logger.Write(string.Format(GlobalVars.GetStr("ProcessingBeforeDependencies"), beforeDependencies.Count, operation));
							ProcessGroupPolicyMUnitsBulk(beforeDependencies.Where(IsGroupPolicyMUnit).ToList(), operation, allAvailableMUnits, cancellationToken);
							ProcessRegistryMUnitsBulk(beforeDependencies.Where(IsRegistryMUnit).ToList(), operation, allAvailableMUnits, cancellationToken);
							ProcessSecurityPolicyRegistryMUnitsBulk(beforeDependencies.Where(IsSecurityPolicyRegistryMUnit).ToList(), operation, allAvailableMUnits, cancellationToken);
							foreach (MUnit regularDep in beforeDependencies.Where(m => !IsGroupPolicyMUnit(m) && !IsRegistryMUnit(m) && !IsSecurityPolicyRegistryMUnit(m)))
							{
								ProcessRegularMUnit(regularDep, operation, cancellationToken);
							}
						}

						// Execute-Before specialized apply strategies
						ExecuteSpecializedStrategies(allPolicies, ExecutionTiming.Before, operation, cancellationToken);

						cancellationToken?.ThrowIfCancellationRequested();

						// Execute main bulk apply operation for Security Policy Registry
						SecurityPolicyRegistryManager.AddPoliciesToSystem(allPolicies);

						// Execute-After specialized apply strategies
						ExecuteSpecializedStrategies(allPolicies, ExecutionTiming.After, operation, cancellationToken);

						// Process After dependencies for JSON-based MUnits
						List<MUnit> afterDependencies = ResolveDependencies(securityPolicyRegistryMUnits, allAvailableMUnits, operation, ExecutionTiming.After, cancellationToken);
						if (afterDependencies.Count > 0)
						{
							Logger.Write(string.Format(GlobalVars.GetStr("ProcessingAfterDependencies"), afterDependencies.Count, operation));
							ProcessGroupPolicyMUnitsBulk(afterDependencies.Where(IsGroupPolicyMUnit).ToList(), operation, allAvailableMUnits, cancellationToken);
							ProcessRegistryMUnitsBulk(afterDependencies.Where(IsRegistryMUnit).ToList(), operation, allAvailableMUnits, cancellationToken);
							ProcessSecurityPolicyRegistryMUnitsBulk(afterDependencies.Where(IsSecurityPolicyRegistryMUnit).ToList(), operation, allAvailableMUnits, cancellationToken);
							foreach (MUnit regularDep in afterDependencies.Where(m => !IsGroupPolicyMUnit(m) && !IsRegistryMUnit(m) && !IsSecurityPolicyRegistryMUnit(m)))
							{
								ProcessRegularMUnit(regularDep, operation, cancellationToken);
							}
						}

						// Mark all as applied
						foreach (MUnit mUnit in securityPolicyRegistryMUnits)
						{
							mUnit.IsApplied = true;
						}
						break;

					case MUnitOperation.Remove:
						// Process Before dependencies for JSON-based MUnits
						List<MUnit> beforeRemoveDependencies = ResolveDependencies(securityPolicyRegistryMUnits, allAvailableMUnits, operation, ExecutionTiming.Before, cancellationToken);
						if (beforeRemoveDependencies.Count > 0)
						{
							Logger.Write(string.Format(GlobalVars.GetStr("ProcessingBeforeDependencies"), beforeRemoveDependencies.Count, operation));
							ProcessGroupPolicyMUnitsBulk(beforeRemoveDependencies.Where(IsGroupPolicyMUnit).ToList(), operation, allAvailableMUnits, cancellationToken);
							ProcessRegistryMUnitsBulk(beforeRemoveDependencies.Where(IsRegistryMUnit).ToList(), operation, allAvailableMUnits, cancellationToken);
							ProcessSecurityPolicyRegistryMUnitsBulk(beforeRemoveDependencies.Where(IsSecurityPolicyRegistryMUnit).ToList(), operation, allAvailableMUnits, cancellationToken);
							foreach (MUnit regularDep in beforeRemoveDependencies.Where(m => !IsGroupPolicyMUnit(m) && !IsRegistryMUnit(m) && !IsSecurityPolicyRegistryMUnit(m)))
							{
								ProcessRegularMUnit(regularDep, operation, cancellationToken);
							}
						}

						// Execute-Before specialized remove strategies
						ExecuteSpecializedStrategies(allPolicies, ExecutionTiming.Before, operation, cancellationToken);

						cancellationToken?.ThrowIfCancellationRequested();

						// Execute main bulk remove operation for Security Policy Registry
						SecurityPolicyRegistryManager.RemovePoliciesFromSystem(allPolicies);

						// Execute-After specialized remove strategies
						ExecuteSpecializedStrategies(allPolicies, ExecutionTiming.After, operation, cancellationToken);

						// Process After dependencies for JSON-based MUnits
						List<MUnit> afterRemoveDependencies = ResolveDependencies(securityPolicyRegistryMUnits, allAvailableMUnits, operation, ExecutionTiming.After, cancellationToken);
						if (afterRemoveDependencies.Count > 0)
						{
							Logger.Write(string.Format(GlobalVars.GetStr("ProcessingAfterDependencies"), afterRemoveDependencies.Count, operation));
							ProcessGroupPolicyMUnitsBulk(afterRemoveDependencies.Where(IsGroupPolicyMUnit).ToList(), operation, allAvailableMUnits, cancellationToken);
							ProcessRegistryMUnitsBulk(afterRemoveDependencies.Where(IsRegistryMUnit).ToList(), operation, allAvailableMUnits, cancellationToken);
							ProcessSecurityPolicyRegistryMUnitsBulk(afterRemoveDependencies.Where(IsSecurityPolicyRegistryMUnit).ToList(), operation, allAvailableMUnits, cancellationToken);
							foreach (MUnit regularDep in afterRemoveDependencies.Where(m => !IsGroupPolicyMUnit(m) && !IsRegistryMUnit(m) && !IsSecurityPolicyRegistryMUnit(m)))
							{
								ProcessRegularMUnit(regularDep, operation, cancellationToken);
							}
						}

						// Mark all as not applied
						foreach (MUnit mUnit in securityPolicyRegistryMUnits)
						{
							mUnit.IsApplied = false;
						}
						break;

					case MUnitOperation.Verify:
						cancellationToken?.ThrowIfCancellationRequested();

						Dictionary<RegistryPolicyEntry, bool> verificationResults = SecurityPolicyRegistryManager.VerifyPoliciesInSystem(allPolicies);

						// Update status based on verification results, with fallback support
						foreach (MUnit mUnit in securityPolicyRegistryMUnits)
						{
							cancellationToken?.ThrowIfCancellationRequested();

							if (mUnit.VerifyStrategy is IVerifySecurityPolicyRegistry verifyStrategy)
							{
								bool allPoliciesApplied = true;
								foreach (RegistryPolicyEntry policy in verifyStrategy.Policies)
								{
									if (!verificationResults.TryGetValue(policy, out bool isApplied) || !isApplied)
									{
										allPoliciesApplied = false;
										break;
									}
								}

								// If primary verification is false, try fallback verification
								if (!allPoliciesApplied)
								{
									bool fallbackResult = TryFallbackVerification(verifyStrategy.Policies, cancellationToken);
									mUnit.IsApplied = fallbackResult;
								}
								else
								{
									mUnit.IsApplied = true;
								}
							}
						}
						break;
					default:
						break;
				}
			}
		}
		catch (Exception ex)
		{
			if (IsCancellationException(ex)) throw; // Skip writing the custom error message since this is cancellation exception.
			Logger.Write(GlobalVars.GetStr("ErrorProcessingSecurityPolicyRegistryMUnits"));
			throw;
		}
	}

	/// <summary>
	/// Tries fallback verification for policies whose Primary verification strategy results in false.
	/// These are used for cases where a security measure is applied via Group Policy or Registry,
	/// But the verification must be able to also detect it if it's applied via COM, Intune and/or other means.
	/// </summary>
	/// <param name="policies">The policies to check for fallback verification</param>
	/// <param name="cancellationToken">Optional cancellation token</param>
	/// <returns>True if any fallback verification succeeds, false otherwise</returns>
	private static bool TryFallbackVerification(List<RegistryPolicyEntry> policies, CancellationToken? cancellationToken = null)
	{
		foreach (RegistryPolicyEntry policy in policies)
		{
			cancellationToken?.ThrowIfCancellationRequested();

			string policyKey = $"{policy.KeyName}|{policy.ValueName}";
			ISpecializedVerificationStrategy? fallbackStrategy = SpecializedStrategiesRegistry.GetSpecializedVerification(policyKey);

			if (fallbackStrategy != null)
			{
				try
				{
					bool fallbackResult = fallbackStrategy.Verify();
					Logger.Write(string.Format(GlobalVars.GetStr("FallbackVerifyResult"), policy.KeyName, policy.ValueName, fallbackResult ? GlobalVars.GetStr("SUCCESS") : GlobalVars.GetStr("FAILED")));

					if (fallbackResult)
					{
						return true; // At least one fallback succeeded
					}
				}
				catch (Exception ex)
				{
					if (IsCancellationException(ex)) throw; // Skip writing the custom error message since this is cancellation exception.
					Logger.Write(string.Format(GlobalVars.GetStr("ErrorInFallbackVerification"), policy.KeyName, policy.ValueName, ex.Message));
					throw;
				}
			}
		}

		return false; // No fallbacks succeeded
	}

	/// <summary>
	/// Processes a regular (non-Group Policy/Registry/Security Policy Registry) MUnit individually
	/// Note: Regular MUnits (DefaultApply/DefaultRemove) do not support dependency resolution (yet) as they are not JSON-based.
	/// That can be implemented later if needed.
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

				// Get all available MUnits for dependency resolution (same category as the first MUnit)
				// Mixed category inputs are not applicable, processors run per category, and this code builds the catalog for mUnits[0].Category, so it's safe.
				List<MUnit> allAvailableMUnits = [];

				// JSON dependency resolution needs the full list of MUnits for the category to look up dependent JsonPolicyId values.
				if (mUnits.Count > 0)
				{
					allAvailableMUnits = viewModel.AllMUnits
						.Where(m => m.Category == mUnits[0].Category)
						.ToList();
				}

				cancellationToken?.ThrowIfCancellationRequested();

				// Separate different types of MUnits
				List<MUnit> groupPolicyMUnits = [];
				List<MUnit> registryMUnits = [];
				List<MUnit> securityPolicyRegistryMUnits = [];
				List<MUnit> regularMUnits = [];

				foreach (MUnit mUnit in mUnits)
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
					else if (IsSecurityPolicyRegistryMUnit(mUnit))
					{
						securityPolicyRegistryMUnits.Add(mUnit);
					}
					else
					{
						regularMUnits.Add(mUnit);
					}
				}

				// Process Group Policy MUnits in bulk with dependency support
				if (groupPolicyMUnits.Count > 0)
				{
					ProcessGroupPolicyMUnitsBulk(groupPolicyMUnits, operation, allAvailableMUnits, cancellationToken);
				}

				// Process Registry MUnits in bulk with dependency support
				if (registryMUnits.Count > 0)
				{
					ProcessRegistryMUnitsBulk(registryMUnits, operation, allAvailableMUnits, cancellationToken);
				}

				// Process Security Policy Registry MUnits in bulk with dependency support
				if (securityPolicyRegistryMUnits.Count > 0)
				{
					ProcessSecurityPolicyRegistryMUnitsBulk(securityPolicyRegistryMUnits, operation, allAvailableMUnits, cancellationToken);
				}

				// Process regular MUnits individually (no dependency support for these as they are not JSON-based)
				foreach (MUnit mUnit in regularMUnits)
				{
					ProcessRegularMUnit(mUnit, operation, cancellationToken);
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
	/// Automatically loads the JSON file based on the category and handles Group Policy, Registry, and Security Policy Registry sources.
	/// </summary>
	/// <param name="category">Category to create MUnits for</param>
	/// <returns>List of MUnits</returns>
	internal static List<MUnit> CreateMUnitsFromPolicies(Categories category)
	{
		List<MUnit> temp = [];

		// Build the full path to the JSON file
		string jsonConfigPath = Path.Combine(AppContext.BaseDirectory, "Resources", $"{category}.json");

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
						applyStrategy: new GroupPolicyApply([entry]),
						verifyStrategy: new GroupPolicyVerify([entry]),
						removeStrategy: new GroupPolicyRemove([entry]),
						subCategory: entry.SubCategory,
						url: entry.URL,
						deviceIntents: entry.DeviceIntents);
				}
				else if (entry.Source == Source.Registry)
				{
					// Create Registry MUnit
					mUnit = new(
						category: category,
						name: entry.FriendlyName,
						applyStrategy: new RegistryApply([entry]),
						verifyStrategy: new RegistryVerify([entry]),
						removeStrategy: new RegistryRemove([entry]),
						subCategory: entry.SubCategory,
						url: entry.URL,
						deviceIntents: entry.DeviceIntents);
				}
				else if (entry.Source == Source.SecurityPolicyRegistry)
				{
					// Validate that DefaultRegValue is not null for SecurityPolicyRegistry entries
					if (entry.DefaultRegValue is null)
					{
						throw new InvalidOperationException(string.Format(GlobalVars.GetStr("SecurityPolicyRegistryEntryMustHaveDefaultRegValue"), entry.KeyName, entry.ValueName));
					}

					// Create Security Policy Registry MUnit
					mUnit = new(
						category: category,
						name: entry.FriendlyName,
						applyStrategy: new SecurityPolicyRegistryApply([entry]),
						verifyStrategy: new SecurityPolicyRegistryVerify([entry]),
						removeStrategy: new SecurityPolicyRegistryRemove([entry]),
						subCategory: entry.SubCategory,
						url: entry.URL,
						deviceIntents: entry.DeviceIntents);
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
}
