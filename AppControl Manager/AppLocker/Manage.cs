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
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;
using System.Xml.Schema;
using AppControlManager.Others;
using CommonCore.Interop;

namespace AppControlManager.AppLocker;

internal enum ManagedInstallerRuleType
{
	Path,
	Hash,
	Publisher
}

internal sealed class ManagedInstallerPolicyDocument(string xmlContent, IReadOnlyList<ManagedInstallerRuleInfo> rules)
{
	internal string XmlContent => xmlContent;
	internal IReadOnlyList<ManagedInstallerRuleInfo> Rules => rules;
}

internal sealed class ManagedInstallerFileAnalysis(
	string filePath,
	bool pathAvailable,
	bool hashAvailable,
	bool publisherAvailable,
	string hash,
	string publisherName,
	string productName,
	string binaryName)
{
	internal string FilePath => filePath;
	internal bool PathAvailable => pathAvailable;
	internal bool HashAvailable => hashAvailable;
	internal bool PublisherAvailable => publisherAvailable;
	internal string Hash => hash;
	internal string PublisherName => publisherName;
	internal string ProductName => productName;
	internal string BinaryName => binaryName;
	internal bool IsRuleTypeAvailable(ManagedInstallerRuleType ruleType) => ruleType switch
	{
		ManagedInstallerRuleType.Path => PathAvailable,
		ManagedInstallerRuleType.Hash => HashAvailable,
		ManagedInstallerRuleType.Publisher => PublisherAvailable,
		_ => false
	};
}

internal sealed class ManagedInstallerRuleInfo(
	string ruleId,
	string name,
	ManagedInstallerRuleType ruleType,
	string path,
	string hashData,
	string sourceFileName,
	string publisherName,
	string productName,
	string binaryName,
	string versionRange)
{
	internal string RuleId => ruleId;
	internal string Name => name;
	internal string RuleTypeText => ruleType.ToString();
	internal string Path => path;
	internal string HashData => hashData;
	internal string SourceFileName => sourceFileName;
	internal string PublisherName => publisherName;
	internal string ProductName => productName;
	internal string BinaryName => binaryName;
	internal string VersionRange => versionRange;
	internal double PathSectionHeight => ruleType is ManagedInstallerRuleType.Path ? double.NaN : 0D;
	internal double HashSectionHeight => ruleType is ManagedInstallerRuleType.Hash ? double.NaN : 0D;
	internal double PublisherSectionHeight => ruleType is ManagedInstallerRuleType.Publisher ? double.NaN : 0D;
}

internal static partial class Manage
{
	internal const string EmptyAppLockerPolicyXMLContent = "<AppLockerPolicy Version=\"1\" />";
	private const int SharingViolationHResult = unchecked((int)0x80070020);
	private const int PolicyWriteAttemptCount = 5;
	private static readonly SemaphoreSlim PolicyWriteSemaphore = new(1, 1);

	// https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/applocker/delete-an-applocker-rule#to-clear-applocker-policies-on-a-single-system-or-remote-systems
	internal static async Task ClearAsync()
	{
		_ = await UpdateLocalPolicyAsync(
			static _ => EmptyAppLockerPolicyXMLContent,
			"cleared local policy");

		using (Process process = Process.Start(new ProcessStartInfo(Path.Join(Environment.SystemDirectory, "appidtel.exe"), "stop -mionly")
		{
			UseShellExecute = false,
			CreateNoWindow = true
		}) ?? throw new InvalidOperationException("Failed to stop AppLocker Managed Installer tracking."))
		{
			await process.WaitForExitAsync();
			if (process.ExitCode is not (0 or 1)) // Exit code 1 is when we try to stop this while it is already stopped.
			{
				throw new InvalidOperationException(string.Concat("Failed to stop AppLocker Managed Installer tracking with exit code ", process.ExitCode.ToString(CultureInfo.InvariantCulture), "."));
			}
		}

		ConfigureISGServices.SetServiceStartType("appid", ConfigureISGServices.ServiceStartType.Manual);
		ConfigureISGServices.SetServiceStartType("applockerfltr", ConfigureISGServices.ServiceStartType.Manual);
		ConfigureISGServices.StopService("applockerfltr");
		ConfigureISGServices.StopService("appidsvc");
		ConfigureISGServices.StopService("appid");
		// Even after we stop all of the services, Set an empty AppLocker policy, run gpupdate /force, give enough time to the system to process things and restart the system
		// AppLocker Managed Installer would continue to work if we don't delete this file manually.
		// This has nothing to do with the implementation in this file or using other methods to interact with AppLocker, they all have the same unexpected behavior.
		File.Delete(Path.Join(Environment.SystemDirectory, "AppLocker", "ManagedInstaller.AppLocker"));
		Logger.Write("Local AppLocker policy cleared.");
	}

	internal static void Validate(ManagedInstallerPolicyDocument policy) => ValidatePolicyXml(policy.XmlContent, "Managed Installer policy");

	internal static ManagedInstallerPolicyDocument List() => ParsePolicy(GetLocalPolicy());

	internal static async Task<ManagedInstallerPolicyDocument> DeleteAsync(string ruleId)
	{
		if (string.IsNullOrWhiteSpace(ruleId))
		{
			throw new ArgumentException("A Managed Installer rule ID is required.", nameof(ruleId));
		}

		int attempt = 0;
		string updatedXml = await UpdateLocalPolicyAsync(
			currentXml => RemoveManagedInstallerRule(currentXml, ruleId, attempt++),
			"updated local policy");
		Logger.Write(string.Concat("Removed Managed Installer rule ", ruleId, "."));
		return ParsePolicy(updatedXml);
	}

	// Configuration when Deploying/Setting a new Managed Installer policy while an existing policy already exists.
	//
	// AppLockerPolicy
	// ├─ Dll
	// │  ├─ Newly generated benign tracking rule
	// │  └─ Required service-tracking extensions
	// ├─ Exe
	// │  ├─ Newly generated benign tracking rule
	// │  └─ Required service-tracking extensions
	// └─ ManagedInstaller
	//    ├─ Newly supplied Managed Installer rule
	//    └─ Previously deployed Managed Installer rule(s)
	internal static async Task SetAsync(ManagedInstallerPolicyDocument policy)
	{
		Validate(policy);
		_ = await UpdateLocalPolicyAsync(
			existingXml => PreserveManagedInstallerRules(existingXml, policy.XmlContent),
			"resulting policy");

		// Initialize AppLocker Managed Installer tracking after the policy is successfully set.
		using (Process process = Process.Start(new ProcessStartInfo(Path.Join(Environment.SystemDirectory, "appidtel.exe"), "start -mionly")
		{
			UseShellExecute = false,
			CreateNoWindow = true
		}) ?? throw new InvalidOperationException("Failed to start AppLocker Managed Installer tracking."))
		{
			await process.WaitForExitAsync();
			if (process.ExitCode is not 0)
			{
				throw new InvalidOperationException(string.Concat("Failed to start AppLocker Managed Installer tracking with exit code ", process.ExitCode.ToString(CultureInfo.InvariantCulture), "."));
			}
		}

		Logger.Write("Local Managed Installer policy replaced while preserving existing Managed Installer rules.");
	}

	private static async Task<string> UpdateLocalPolicyAsync(Func<string, string> updatePolicy, string validationSource)
	{
		await PolicyWriteSemaphore.WaitAsync();
		try
		{
			for (int attempt = 0; attempt < PolicyWriteAttemptCount; attempt++)
			{
				string currentXml = GetLocalPolicy();
				ValidatePolicyXml(currentXml, "current local policy");
				string updatedXml = updatePolicy(currentXml);
				ValidatePolicyXml(updatedXml, validationSource);

				try
				{
					SetLocalPolicy(updatedXml);
					return updatedXml;
				}
				catch (Exception ex) when (ex.HResult == SharingViolationHResult && attempt < PolicyWriteAttemptCount - 1)
				{
					int retryDelayMilliseconds = 75 << attempt;
					Logger.Write(string.Concat(
						"The AppLocker policy store is busy. Retrying policy update after ",
						retryDelayMilliseconds.ToString(CultureInfo.InvariantCulture),
						" milliseconds."));
					await Task.Delay(retryDelayMilliseconds);
				}
			}

			throw new InvalidOperationException("The AppLocker policy update did not complete.");
		}
		finally
		{
			_ = PolicyWriteSemaphore.Release();
		}
	}

	private static string RemoveManagedInstallerRule(string currentXml, string ruleId, int attempt)
	{
		XDocument document = XDocument.Parse(currentXml, LoadOptions.PreserveWhitespace);
		XElement root = document.Root ?? throw new InvalidDataException("The local AppLocker policy has no root element.");
		XElement managedInstaller = GetManagedInstallerCollection(root) ??
			throw new InvalidOperationException("The local AppLocker policy does not contain a ManagedInstaller rule collection.");
		List<XElement> matches = [.. managedInstaller.Elements()
				.Where(IsRuleElement)
				.Where(rule => string.Equals((string?)rule.Attribute("Id"), ruleId, StringComparison.OrdinalIgnoreCase))
				.Take(2)];

		if (matches.Count is 0 && attempt > 0)
		{
			return currentXml;
		}
		if (matches.Count is not 1)
		{
			throw new InvalidOperationException(matches.Count is 0
				? "The selected Managed Installer rule no longer exists. Refresh the policy and try again."
				: "The local policy contains duplicate Managed Installer rule IDs, so no rule was removed.");
		}

		matches[0].Remove();
		return document.ToString(SaveOptions.DisableFormatting);
	}

	internal static ManagedInstallerPolicyDocument Create(string installerPath, string ruleName, ManagedInstallerRuleType ruleType)
	{
		string fullInstallerPath = Path.GetFullPath(installerPath);
		if (!File.Exists(fullInstallerPath) || !fullInstallerPath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
		{
			throw new FileNotFoundException("An existing EXE is required to create a Managed Installer rule.", fullInstallerPath);
		}

		if (string.IsNullOrWhiteSpace(ruleName))
		{
			throw new ArgumentException("Rule name is required.", nameof(ruleName));
		}

		ManagedInstallerFileAnalysis analysis = AnalyzeInstaller(fullInstallerPath);
		if (!analysis.IsRuleTypeAvailable(ruleType))
		{
			throw new InvalidOperationException(string.Concat(ruleType.ToString(), " rule creation is not available for the selected executable."));
		}

		XDocument policy = BuildManagedInstallerPolicy(fullInstallerPath, ruleName, ruleType);
		ManagedInstallerPolicyDocument result = ParsePolicy(policy.ToString(SaveOptions.DisableFormatting));
		Validate(result);
		return result;
	}

	internal static ManagedInstallerFileAnalysis AnalyzeInstaller(string installerPath)
	{
		string fullInstallerPath = Path.GetFullPath(installerPath);
		if (!File.Exists(fullInstallerPath) || !fullInstallerPath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
		{
			return new ManagedInstallerFileAnalysis(
				filePath: fullInstallerPath,
				pathAvailable: false,
				hashAvailable: false,
				publisherAvailable: false,
				hash: string.Empty,
				publisherName: string.Empty,
				productName: string.Empty,
				binaryName: string.Empty);
		}

		bool hashAvailable = false;
		string hash = string.Empty;
		string publisherName = string.Empty;
		string productName = string.Empty;
		string binaryName = string.Empty;

		using NativePolicyHelper helper = new();
		try
		{
			byte[] calculatedHash = helper.CalculateFileHash(fullInstallerPath);
			hashAvailable = calculatedHash.Length > 0;
			if (hashAvailable)
			{
				hash = string.Concat("0x", Convert.ToHexString(calculatedHash));
			}
		}
		catch (Exception ex)
		{
			Logger.Write(string.Concat("AppLocker could not calculate an Authenticode hash for '", fullInstallerPath, "': ", ex.Message));
		}

		try
		{
			helper.CalculateFilePublisher(fullInstallerPath, out publisherName, out productName, out binaryName, out _);
		}
		catch (Exception ex)
		{
			Logger.Write(string.Concat("AppLocker publisher details are unavailable for '", fullInstallerPath, "': ", ex.Message));
		}

		bool publisherAvailable =
			!string.IsNullOrWhiteSpace(publisherName) &&
			!string.IsNullOrWhiteSpace(productName) &&
			!string.IsNullOrWhiteSpace(binaryName);

		return new ManagedInstallerFileAnalysis(
			fullInstallerPath,
			true,
			hashAvailable,
			publisherAvailable,
			hash,
			publisherName,
			productName,
			binaryName);
	}

	private static string GetLocalPolicy()
	{
		using NativePolicyHandler handler = new();
		string xml = handler.GetPolicy();
		return string.IsNullOrWhiteSpace(xml) ? EmptyAppLockerPolicyXMLContent : xml;
	}

	private static void SetLocalPolicy(string xml)
	{
		using NativePolicyHandler handler = new();
		handler.SetPolicy(xml);
	}

	private static void ValidatePolicyXml(string xml, string sourceName)
	{
		List<string> errors = [with(4)];
		string schemaPath = Path.Join(AppContext.BaseDirectory, "XSDSchemas", "AppIdPolicy.xsd"); ;

		XmlReaderSettings settings = new()
		{
			DtdProcessing = DtdProcessing.Prohibit,
			XmlResolver = null,
			ValidationType = ValidationType.Schema,
			ValidationFlags = XmlSchemaValidationFlags.ReportValidationWarnings
		};
		_ = settings.Schemas.Add(null, schemaPath);
		settings.ValidationEventHandler += (_, eventArgs) => errors.Add(eventArgs.Message);

		using StringReader textReader = new(xml);
		using XmlReader reader = XmlReader.Create(textReader, settings);
		XDocument document = XDocument.Load(reader);
		XElement? root = document.Root;

		XAttribute? version = root?.Attribute("Version");
		if (version is null || !string.Equals(version.Value, "1", StringComparison.OrdinalIgnoreCase))
		{
			errors.Add("AppLockerPolicy must specify Version=\"1\".");
		}

		if (errors.Count > 0)
		{
			throw new InvalidDataException(string.Concat("AppLocker policy validation failed for ", sourceName, Environment.NewLine, string.Join(Environment.NewLine, errors)));
		}
	}

	private static string PreserveManagedInstallerRules(string existingXml, string incomingXml)
	{
		XDocument existing = XDocument.Parse(existingXml, LoadOptions.PreserveWhitespace);
		XDocument incoming = XDocument.Parse(incomingXml, LoadOptions.PreserveWhitespace);
		XElement existingRoot = existing.Root ?? throw new InvalidDataException("The existing policy has no root element.");
		XElement incomingRoot = incoming.Root ?? throw new InvalidDataException("The incoming policy has no root element.");
		XElement incomingManagedInstaller = GetManagedInstallerCollection(incomingRoot) ??
			throw new InvalidDataException("The policy being deployed does not contain a ManagedInstaller rule collection.");
		XElement? existingManagedInstaller = GetManagedInstallerCollection(existingRoot);

		if (existingManagedInstaller is null)
		{
			return incoming.ToString(SaveOptions.DisableFormatting);
		}

		HashSet<string> incomingRuleIds = new(
			incomingManagedInstaller.Elements()
				.Where(IsRuleElement)
				.Select(rule => (string?)rule.Attribute("Id"))
				.OfType<string>()
				.Where(id => !string.IsNullOrWhiteSpace(id)),
			StringComparer.OrdinalIgnoreCase);

		HashSet<string> incomingRuleConditions = new(
			incomingManagedInstaller.Elements().Where(IsRuleElement).Select(GetRuleConditionIdentity),
			StringComparer.OrdinalIgnoreCase);

		foreach (XElement existingRule in existingManagedInstaller.Elements().Where(IsRuleElement))
		{
			string id = GetRequiredAttribute(existingRule, "Id");
			string conditionIdentity = GetRuleConditionIdentity(existingRule);
			if (incomingRuleIds.Add(id) && incomingRuleConditions.Add(conditionIdentity))
			{
				incomingManagedInstaller.Add(new XElement(existingRule));
			}
		}

		return incoming.ToString(SaveOptions.DisableFormatting);
	}

	private static ManagedInstallerPolicyDocument ParsePolicy(string xml)
	{
		XDocument document = XDocument.Parse(xml, LoadOptions.PreserveWhitespace);
		XElement root = document.Root ?? throw new InvalidDataException("The AppLocker policy has no root element.");
		XElement? collection = GetManagedInstallerCollection(root);
		List<ManagedInstallerRuleInfo> rules = collection is null ? [] : new(collection.Elements().Where(IsRuleElement).Select(ParseRule));
		return new ManagedInstallerPolicyDocument(document.ToString(SaveOptions.DisableFormatting), rules);
	}

	private static ManagedInstallerRuleInfo ParseRule(XElement rule)
	{
		string ruleId = GetRequiredAttribute(rule, "Id");
		string name = (string?)rule.Attribute("Name") ?? "Managed Installer";
		XElement? conditions = rule.Elements().FirstOrDefault(element => string.Equals(element.Name.LocalName, "Conditions", StringComparison.OrdinalIgnoreCase));
		XElement? condition = conditions?.Elements().FirstOrDefault();

		if (string.Equals(rule.Name.LocalName, "FilePathRule", StringComparison.OrdinalIgnoreCase))
		{
			return new ManagedInstallerRuleInfo(
				ruleId: ruleId,
				name: name,
				ruleType: ManagedInstallerRuleType.Path,
				path: (string?)condition?.Attribute("Path") ?? string.Empty,
				hashData: string.Empty,
				sourceFileName: string.Empty,
				publisherName: string.Empty,
				productName: string.Empty,
				binaryName: string.Empty,
				versionRange: string.Empty);
		}

		if (string.Equals(rule.Name.LocalName, "FileHashRule", StringComparison.OrdinalIgnoreCase))
		{
			XElement? hash = condition?.Elements().FirstOrDefault(element => string.Equals(element.Name.LocalName, "FileHash", StringComparison.OrdinalIgnoreCase));
			return new ManagedInstallerRuleInfo(
				ruleId,
				name,
				ManagedInstallerRuleType.Hash,
				string.Empty,
				(string?)hash?.Attribute("Data") ?? string.Empty,
				(string?)hash?.Attribute("SourceFileName") ?? string.Empty,
				string.Empty,
				string.Empty,
				string.Empty,
				string.Empty);
		}

		XElement? versionRange = condition?.Elements().FirstOrDefault(element => string.Equals(element.Name.LocalName, "BinaryVersionRange", StringComparison.OrdinalIgnoreCase));
		return new ManagedInstallerRuleInfo(
			ruleId,
			name,
			ManagedInstallerRuleType.Publisher,
			string.Empty,
			string.Empty,
			string.Empty,
			(string?)condition?.Attribute("PublisherName") ?? string.Empty,
			(string?)condition?.Attribute("ProductName") ?? string.Empty,
			(string?)condition?.Attribute("BinaryName") ?? string.Empty,
			string.Concat((string?)versionRange?.Attribute("LowSection") ?? string.Empty, " to ", (string?)versionRange?.Attribute("HighSection") ?? string.Empty));
	}

	private static XElement? GetManagedInstallerCollection(XElement policyRoot) =>
		policyRoot.Elements().FirstOrDefault(element =>
			string.Equals(element.Name.LocalName, "RuleCollection", StringComparison.OrdinalIgnoreCase) &&
			string.Equals((string?)element.Attribute("Type"), "ManagedInstaller", StringComparison.OrdinalIgnoreCase));

	private static string GetRuleConditionIdentity(XElement rule)
	{
		XElement? conditions = rule.Elements().FirstOrDefault(element =>
			string.Equals(element.Name.LocalName, "Conditions", StringComparison.OrdinalIgnoreCase));
		return string.Concat(
			rule.Name.LocalName,
			"|",
			(string?)rule.Attribute("UserOrGroupSid") ?? string.Empty,
			"|",
			(string?)rule.Attribute("Action") ?? string.Empty,
			"|",
			conditions?.ToString(SaveOptions.DisableFormatting) ?? string.Empty);
	}

	// https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/design/configure-authorized-apps-deployed-with-a-managed-installer
	private static XDocument BuildManagedInstallerPolicy(string installerPath, string ruleName, ManagedInstallerRuleType ruleType)
	{
		XElement root = new("AppLockerPolicy", new XAttribute("Version", "1"),
			BuildTrackingCollection("Dll", "%OSDRIVE%\\ThisWillBeBlocked.dll", "Benign DENY Rule for DLL service tracking", "Enables DLL service tracking without affecting legitimate files."),
			BuildTrackingCollection("Exe", "%OSDRIVE%\\ThisWillBeBlocked.exe", "Benign DENY Rule for EXE service tracking", "Enables EXE service tracking without affecting legitimate files."),
			new XElement("RuleCollection",
				new XAttribute("Type", "ManagedInstaller"),
				new XAttribute("EnforcementMode", "AuditOnly"),
				BuildManagedInstallerRule(installerPath, ruleName, ruleType)));
		return new XDocument(new XDeclaration("1.0", "utf-8", null), root);
	}

	private static XElement BuildManagedInstallerRule(string installerPath, string ruleName, ManagedInstallerRuleType ruleType)
	{
		if (ruleType is ManagedInstallerRuleType.Path)
		{
			return new XElement("FilePathRule",
				BuildRuleAttributes(ruleName),
				new XElement("Conditions", new XElement("FilePathCondition", new XAttribute("Path", installerPath))));
		}

		string fullInstallerPath = Path.GetFullPath(installerPath);
		using NativePolicyHelper helper = new();
		if (ruleType is ManagedInstallerRuleType.Hash)
		{
			byte[] hash = helper.CalculateFileHash(fullInstallerPath);
			return new XElement("FileHashRule",
				BuildRuleAttributes(ruleName),
				new XElement("Conditions",
					new XElement("FileHashCondition",
						new XElement("FileHash",
							new XAttribute("Type", "SHA256"),
							new XAttribute("Data", string.Concat("0x", Convert.ToHexString(hash))),
							new XAttribute("SourceFileName", Path.GetFileName(fullInstallerPath)),
							new XAttribute("SourceFileLength", new FileInfo(fullInstallerPath).Length.ToString(CultureInfo.InvariantCulture))))));
		}

		helper.CalculateFilePublisher(fullInstallerPath, out string publisherName, out string productName, out string binaryName, out ulong binaryVersion);
		return new XElement("FilePublisherRule",
			BuildRuleAttributes(ruleName),
			new XElement("Conditions",
				new XElement("FilePublisherCondition",
					new XAttribute("PublisherName", publisherName),
					new XAttribute("ProductName", productName),
					new XAttribute("BinaryName", binaryName),
					// LowSection uses the detected version, or * when version metadata is unavailable.
					// HighSection uses * so the publisher rule matches that version and every higher version.
					new XElement("BinaryVersionRange",
						new XAttribute("LowSection", FormatFileVersion(binaryVersion)),
						new XAttribute("HighSection", "*")))));
	}

	private static object[] BuildRuleAttributes(string ruleName) =>
	[
		new XAttribute("Id", Guid.NewGuid().ToString("D", CultureInfo.InvariantCulture)),
		new XAttribute("Name", ruleName),
		new XAttribute("Description", "Designates the specified executable as a Managed Installer."),
		new XAttribute("UserOrGroupSid", "S-1-1-0"),
		new XAttribute("Action", "Allow")
	];

	private static string FormatFileVersion(ulong version) => version is 0 ? "*" : string.Format(
		CultureInfo.InvariantCulture,
		"{0}.{1}.{2}.{3}",
		version >> 48,
		version >> 32 & 0xFFFF,
		version >> 16 & 0xFFFF,
		version & 0xFFFF);

	private static XElement BuildTrackingCollection(string type, string path, string name, string description) =>
		new("RuleCollection",
			new XAttribute("Type", type),
			new XAttribute("EnforcementMode", "AuditOnly"),
			new XElement("FilePathRule",
				new XAttribute("Id", Guid.NewGuid().ToString("D", CultureInfo.InvariantCulture)),
				new XAttribute("Name", name),
				new XAttribute("Description", description),
				new XAttribute("UserOrGroupSid", "S-1-1-0"),
				new XAttribute("Action", "Deny"),
				new XElement("Conditions", new XElement("FilePathCondition", new XAttribute("Path", path)))),
			new XElement("RuleCollectionExtensions",
				new XElement("ThresholdExtensions", new XElement("Services", new XAttribute("EnforcementMode", "Enabled"))),
				new XElement("RedstoneExtensions", new XElement("SystemApps", new XAttribute("Allow", "Enabled")))));

	private static bool IsRuleElement(XElement element) => element.Name.LocalName.EndsWith("Rule", StringComparison.OrdinalIgnoreCase);

	private static string GetRequiredAttribute(XElement element, string name) =>
		(string?)element.Attribute(name) ?? throw new InvalidDataException(string.Concat(element.Name.LocalName, " is missing required attribute ", name, "."));

	private sealed unsafe partial class NativePolicyHandler : IDisposable
	{
		private static readonly Guid ClassId = new("F1ED7D4C-F863-4DE6-A1CA-7253EFDEE1F3");
		private static readonly Guid InterfaceId = new("B6FEA19E-32DD-4367-B5B7-2F5DA140E87D");
		private nint instance;
		private bool uninitializeCom;
		private bool disposed;

		internal NativePolicyHandler()
		{
			uninitializeCom = InitializeComForCurrentThread();
			try
			{
				instance = CreateComInstance(ClassId, InterfaceId);
			}
			catch
			{
				UninitializeComForCurrentThread(uninitializeCom);
				uninitializeCom = false;
				throw;
			}
		}

		internal string GetPolicy()
		{
			ObjectDisposedException.ThrowIf(disposed, this);
			nint ldap = AllocateBstr(string.Empty);
			nint result = 0;
			try
			{
				void** vtable = *(void***)instance;
				int hresult = ((delegate* unmanaged[Stdcall]<nint, nint, nint*, int>)vtable[8])(instance, ldap, &result);
				Marshal.ThrowExceptionForHR(hresult);
				return BstrToString(result);
			}
			finally
			{
				FreeBstr(result);
				FreeBstr(ldap);
			}
		}

		internal void SetPolicy(string xmlPolicy)
		{
			ObjectDisposedException.ThrowIf(disposed, this);
			nint ldap = AllocateBstr(string.Empty);
			nint xml = AllocateBstr(xmlPolicy);
			try
			{
				void** vtable = *(void***)instance;
				int hresult = ((delegate* unmanaged[Stdcall]<nint, nint, nint, int>)vtable[7])(instance, ldap, xml);
				Marshal.ThrowExceptionForHR(hresult);
			}
			finally
			{
				FreeBstr(xml);
				FreeBstr(ldap);
			}
		}

		public void Dispose()
		{
			if (!disposed)
			{
				ReleaseComInstance(instance);
				instance = 0;
				UninitializeComForCurrentThread(uninitializeCom);
				uninitializeCom = false;
				disposed = true;
			}
		}
	}

	private sealed unsafe partial class NativePolicyHelper : IDisposable
	{
		private static readonly Guid ClassId = new("0AEA3667-1039-43FF-8D21-B1A162090671");
		private static readonly Guid InterfaceId = new("D500522D-465B-4C83-8008-00C4EC90A859");
		private nint instance;
		private bool uninitializeCom;
		private bool disposed;

		internal NativePolicyHelper()
		{
			uninitializeCom = InitializeComForCurrentThread();
			try
			{
				instance = CreateComInstance(ClassId, InterfaceId);
			}
			catch
			{
				UninitializeComForCurrentThread(uninitializeCom);
				uninitializeCom = false;
				throw;
			}
		}

		internal byte[] CalculateFileHash(string filePath)
		{
			ObjectDisposedException.ThrowIf(disposed, this);
			nint path = AllocateBstr(filePath);
			nint safeArray = 0;
			try
			{
				void** vtable = *(void***)instance;
				int hresult = ((delegate* unmanaged[Stdcall]<nint, nint, nint*, int>)vtable[10])(instance, path, &safeArray);
				Marshal.ThrowExceptionForHR(hresult);
				return CopyByteSafeArray(safeArray);
			}
			finally
			{
				DestroySafeArrayIfAllocated(safeArray);
				FreeBstr(path);
			}
		}

		internal void CalculateFilePublisher(
			string filePath,
			out string publisherName,
			out string productName,
			out string binaryName,
			out ulong binaryVersion)
		{
			ObjectDisposedException.ThrowIf(disposed, this);
			nint path = AllocateBstr(filePath);
			nint publisher = 0;
			nint product = 0;
			nint binary = 0;
			ulong version = 0;
			try
			{
				void** vtable = *(void***)instance;
				int hresult = ((delegate* unmanaged[Stdcall]<nint, nint, nint*, nint*, nint*, ulong*, int>)vtable[11])(
					instance, path, &publisher, &product, &binary, &version);
				Marshal.ThrowExceptionForHR(hresult);
				publisherName = BstrToString(publisher);
				productName = BstrToString(product);
				binaryName = BstrToString(binary);
				binaryVersion = version;
			}
			finally
			{
				FreeBstr(binary);
				FreeBstr(product);
				FreeBstr(publisher);
				FreeBstr(path);
			}
		}

		public void Dispose()
		{
			if (!disposed)
			{
				ReleaseComInstance(instance);
				instance = 0;
				UninitializeComForCurrentThread(uninitializeCom);
				uninitializeCom = false;
				disposed = true;
			}
		}
	}

	private static bool InitializeComForCurrentThread()
	{
		const int RpcEChangedMode = unchecked((int)0x80010106);
		const uint CoInitApartmentThreaded = 0x2;
		int hresult = NativeMethods.CoInitializeEx(0, CoInitApartmentThreaded);
		if (hresult == RpcEChangedMode)
		{
			return false;
		}
		Marshal.ThrowExceptionForHR(hresult);
		return true;
	}

	private static void UninitializeComForCurrentThread(bool required)
	{
		if (required)
		{
			NativeMethods.CoUninitialize();
		}
	}

	private static nint CreateComInstance(Guid classId, Guid interfaceId)
	{
		int hresult = NativeMethods.CoCreateInstance(in classId, IntPtr.Zero, 1, in interfaceId, out IntPtr instance);
		Marshal.ThrowExceptionForHR(hresult);
		return instance;
	}

	private unsafe static void ReleaseComInstance(nint instance)
	{
		if (instance != 0)
		{
			void** vtable = *(void***)instance;
			_ = ((delegate* unmanaged[Stdcall]<nint, uint>)vtable[2])(instance);
		}
	}

	private unsafe static nint AllocateBstr(string value)
	{
		fixed (char* valuePointer = value)
		{
			nint result = NativeMethods.SysAllocStringLen(valuePointer, (uint)value.Length);
			if (result == 0 && value.Length != 0)
			{
				throw new InvalidOperationException("Failed to allocate the BSTR.");
			}
			return result;
		}
	}

	private unsafe static string BstrToString(nint value)
	{
		if (value == 0)
		{
			return string.Empty;
		}

		uint length = NativeMethods.SysStringLen(value);
		return new string((char*)value, 0, checked((int)length));
	}

	private static void FreeBstr(nint value)
	{
		if (value != 0)
		{
			NativeMethods.SysFreeString(value);
		}
	}

	private static void DestroySafeArrayIfAllocated(nint safeArray)
	{
		if (safeArray != 0)
		{
			_ = NativeMethods.SafeArrayDestroy(safeArray);
		}
	}

	private unsafe static byte[] CopyByteSafeArray(nint safeArray)
	{
		if (safeArray == 0)
		{
			return [];
		}
		int lowerBound = 0;
		int upperBound = -1;
		Marshal.ThrowExceptionForHR(NativeMethods.SafeArrayGetLBound(safeArray, 1, &lowerBound));
		Marshal.ThrowExceptionForHR(NativeMethods.SafeArrayGetUBound(safeArray, 1, &upperBound));
		int length = checked(upperBound - lowerBound + 1);
		byte[] result = new byte[length];
		nint data = 0;
		Marshal.ThrowExceptionForHR(NativeMethods.SafeArrayAccessData(safeArray, &data));
		try
		{
			new ReadOnlySpan<byte>((void*)data, length).CopyTo(result);
		}
		finally
		{
			Marshal.ThrowExceptionForHR(NativeMethods.SafeArrayUnaccessData(safeArray));
		}
		return result;
	}
}
