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
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Microsoft.UI.Xaml;

namespace CommonCore.Signing;

/// <summary>
/// Native SIP removal with packaging COM validation.
/// The original is preserved and the completed unsigned copy is published only
/// after signature absence, retained-stream equality and block-map validation.
/// </summary>
internal static partial class PackageSignatureRemover
{
	internal static bool CreateUnsignedCopy(string sourcePath, string destinationPath, bool removeInnerSignatures = false)
	{
		string extension = Path.GetExtension(sourcePath);
		bool bundle = string.Equals(extension, ".msixbundle", StringComparison.OrdinalIgnoreCase);
		if (!bundle && !string.Equals(extension, ".msix", StringComparison.OrdinalIgnoreCase))
		{
			throw new ArgumentException("Select an unencrypted .msix or .msixbundle file.");
		}
		if (File.Exists(destinationPath))
		{
			throw new IOException("The destination already exists. Choose a new filename.");
		}
		int initialization = NativeMethods.CoInitializeEx(IntPtr.Zero, 0);
		if (initialization < 0 && initialization != unchecked((int)0x80010106))
		{
			Marshal.ThrowExceptionForHR(initialization);
		}
		string temporary = Path.Join(Path.GetDirectoryName(destinationPath), $".unsigned-{Guid.CreateVersion7():N}{extension}");
		bool created = false;
		try
		{
			using FileStream input = new(sourcePath, FileMode.Open, FileAccess.Read, FileShare.Read);
			using NativePackage original = new(sourcePath, bundle);
			bool outerSigned = original.HasSignature();
			bool rebuild = bundle && removeInnerSignatures && original.HasSignedInnerPackages();
			if (!outerSigned && !rebuild)
			{
				return false;
			}
			original.ValidateBlockMap();
			using (FileStream output = new(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
			{
				created = true;
				if (!rebuild)
				{
					input.CopyTo(output);
					output.Flush(flushToDisk: true);
				}
			}
			if (rebuild)
			{
				bool innerChanged = original.RebuildWithoutInnerSignatures(temporary);
				if (!outerSigned && !innerChanged)
				{
					return false;
				}
				using FileStream completed = new(temporary, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
				completed.Flush(flushToDisk: true);
			}
			else
			{
				RemoveUsingSip(temporary);
			}
			using (NativePackage unsigned = new(temporary, bundle))
			{
				if (unsigned.HasSignature())
				{
					throw new InvalidDataException("The output still has a package signature. No output was published.");
				}
				unsigned.ValidateBlockMap();
				if (rebuild)
				{
					original.CompareRebuiltBundle(unsigned);
				}
				else
				{
					original.CompareRetainedFiles(unsigned);
				}
			}

			File.Move(temporary, destinationPath, overwrite: false);
			return true;
		}
		finally
		{
			if (created && File.Exists(temporary))
			{
				try
				{
					File.Delete(temporary);
				}
				catch (Exception ex)
				{
					Logger.Write($"Could not delete temporary package '{temporary}': {ex.Message}");
				}
			}
			if (initialization >= 0)
			{
				NativeMethods.CoUninitialize();
			}
		}
	}

	/// <summary>
	/// Strict four-component package version.
	/// </summary>
	internal static ulong ParsePackageVersion(string text)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(text);
		ReadOnlySpan<char> value = text.AsSpan().Trim();
		Span<Range> parts = stackalloc Range[5];
		if (value.Split(parts, '.') != 4)
		{
			throw new ArgumentException("Use Major.Minor.Build.Revision, with each component between 0 and 65535.");
		}
		ulong result = 0;
		for (int index = 0; index < 4; index++)
		{
			ReadOnlySpan<char> part = value[parts[index]];
			if (part.IndexOfAnyExceptInRange('0', '9') >= 0 || !ushort.TryParse(part, NumberStyles.None, CultureInfo.InvariantCulture, out ushort component) || (index is 0 && component is 0))
			{
				throw new ArgumentException("Use four decimal components from 0 to 65535. The major component must be greater than zero.");
			}
			result = (result << 16) | component;
		}
		return result;
	}

	internal static string FormatPackageVersion(ulong version) =>
		string.Create(CultureInfo.InvariantCulture, $"{version >> 48}.{(version >> 32) & 65535}.{(version >> 16) & 65535}.{version & 65535}");

	/// <summary>
	/// Read identities through the native manifest readers.
	/// </summary>
	internal static List<PackageVersionRecord> ReadPackageVersions(string packagePath)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(packagePath);
		string path = Path.GetFullPath(packagePath);
		bool bundle = IsVersionBundle(path);
		int initialization = NativeMethods.CoInitializeEx(IntPtr.Zero, 0);
		if (initialization < 0 && initialization != unchecked((int)0x80010106))
		{
			Marshal.ThrowExceptionForHR(initialization);
		}
		try
		{
			using FileStream guard = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
			using NativePackage package = new(path, bundle);
			return package.ReadVersionRecords(Path.GetFileName(path));
		}
		finally
		{
			if (initialization >= 0)
			{
				NativeMethods.CoUninitialize();
			}
		}
	}

	private static bool IsVersionBundle(string path)
	{
		string extension = Path.GetExtension(path);
		bool bundle = string.Equals(extension, ".msixbundle", StringComparison.OrdinalIgnoreCase);
		if (!bundle && !string.Equals(extension, ".msix", StringComparison.OrdinalIgnoreCase))
		{
			throw new ArgumentException("Select an unencrypted MSIX or MSIXBundle.");
		}
		return bundle;
	}

	/// <summary>
	/// Publish a validated unsigned copy. Null innerName changes only the selected
	/// outer identity; a non-null name changes exactly that embedded package.
	/// The source and all unselected inner-package streams remain unchanged.
	/// </summary>
	internal static void WritePackageVersionCopy(string sourcePath, string destinationPath, string? innerName, ulong expectedVersion, ulong newVersion)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(sourcePath);
		ArgumentException.ThrowIfNullOrWhiteSpace(destinationPath);
		if ((newVersion >> 48) is 0)
		{
			throw new ArgumentException("The major version must be greater than zero.");
		}

		string source = Path.GetFullPath(sourcePath);
		string destination = Path.GetFullPath(destinationPath);
		bool bundle = IsVersionBundle(source);

		if (string.Equals(source, destination, StringComparison.OrdinalIgnoreCase) ||
			!string.Equals(Path.GetExtension(source), Path.GetExtension(destination), StringComparison.OrdinalIgnoreCase))
		{
			throw new ArgumentException("Choose a different output filename with the same package extension.");
		}

		if (File.Exists(destination))
		{
			throw new IOException("The destination already exists. Choose a new filename.");
		}

		int initialization = NativeMethods.CoInitializeEx(IntPtr.Zero, 0);

		if (initialization < 0 && initialization != unchecked((int)0x80010106))
		{
			Marshal.ThrowExceptionForHR(initialization);
		}

		string temporary = Path.Join(Path.GetDirectoryName(destination), $".version-{Guid.CreateVersion7():N}{Path.GetExtension(source)}");
		bool created = false;
		try
		{
			using FileStream guard = new(source, FileMode.Open, FileAccess.Read, FileShare.Read);
			using NativePackage original = new(source, bundle);
			if (original.VersionFor(innerName) != expectedVersion)
			{
				throw new IOException("The selected package version changed on disk. Browse for the package again before saving.");
			}
			original.ValidateBlockMap();
			using (FileStream output = new(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
			{
				created = true;
			}
			if (bundle)
			{
				original.WriteVersionBundle(temporary, innerName, newVersion);
			}
			else
			{
				if (innerName is not null)
				{
					throw new ArgumentException("A standalone MSIX has no embedded-package version row.");
				}
				original.WriteVersionPackage(temporary, newVersion);
			}
			using (NativePackage rebuilt = new(temporary, bundle))
			{
				if (rebuilt.HasSignature())
				{
					throw new InvalidDataException("The version-edited output unexpectedly contains an outer signature.");
				}
				rebuilt.ValidateBlockMap();
				original.CompareVersionOutput(rebuilt, innerName, newVersion);
			}
			using (FileStream completed = new(temporary, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
			{
				completed.Flush(flushToDisk: true);
			}
			File.Move(temporary, destination, overwrite: false);
		}
		finally
		{
			if (created && File.Exists(temporary))
			{
				try
				{
					File.Delete(temporary);
				}
				catch (Exception ex)
				{
					Logger.Write($"Could not delete version-edit temporary file '{temporary}': {ex.Message}");
				}
			}
			if (initialization >= 0)
			{
				NativeMethods.CoUninitialize();
			}
		}
	}

	/// <summary>
	/// Rebuild and validate one selected version on disk before writing the selected
	/// file through one exclusive handle. No rename/delete access to the source is
	/// required. The temporary backup is restored automatically if writing fails,
	/// and its DeleteOnClose handle never escapes this operation.
	/// </summary>
	internal static void WritePackageVersionInPlace(string sourcePath, string? innerName, ulong expectedVersion, ulong newVersion)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(sourcePath);
		string source = Path.GetFullPath(sourcePath);
		_ = IsVersionBundle(source);
		string replacement = Path.Join(Path.GetDirectoryName(source), $".version-replacement-{Guid.CreateVersion7():N}{Path.GetExtension(source)}");
		bool replacementCreated = false;
		Exception? failure = null;
		List<Exception> cleanupErrors = new(2);
		try
		{
			string temporaryPath;
			using (Microsoft.Windows.Storage.ApplicationData applicationData = Microsoft.Windows.Storage.ApplicationData.GetDefault())
			{
				temporaryPath = applicationData.TemporaryPath;
			}
			ArgumentException.ThrowIfNullOrWhiteSpace(temporaryPath);
			_ = Directory.CreateDirectory(temporaryPath);

			string backupPath = Path.Join(temporaryPath, $".version-backup-{Guid.CreateVersion7():N}.bak");

			byte[] originalHash;
			byte[] validatedHash;

			// Native package readers require read-only sharing. Complete and dispose
			// every reader before acquiring the source's exclusive read/write handle.
			using (FileStream guard = new(source, FileMode.Open, FileAccess.Read, FileShare.Read))
			{
				originalHash = System.Security.Cryptography.SHA256.HashData(guard);
				WritePackageVersionCopy(source, replacement, innerName, expectedVersion, newVersion);
				replacementCreated = true;
				using FileStream completed = new(replacement, FileMode.Open, FileAccess.Read, FileShare.Read);
				validatedHash = System.Security.Cryptography.SHA256.HashData(completed);
			}

			// Keep the validated replacement locked from hashing through the final
			// write. DeleteOnClose removes it on success and all exception paths.
			using FileStream validated = OpenVersionFile(replacement, FileAccess.Read, FileOptions.DeleteOnClose);
			using FileStream target = OpenVersionFile(source, FileAccess.ReadWrite, FileOptions.None);
			byte[] currentReplacementHash = System.Security.Cryptography.SHA256.HashData(validated);
			if (!validatedHash.AsSpan().SequenceEqual(currentReplacementHash))
			{
				throw new IOException("The validated replacement changed while saving. No write was performed.");
			}
			byte[] currentHash = System.Security.Cryptography.SHA256.HashData(target);
			if (!originalHash.AsSpan().SequenceEqual(currentHash))
			{
				throw new IOException("The source package changed while saving. No write was performed. Browse for the package again.");
			}

			// No other process can open this backup. It is automatically deleted
			// when this scope closes, including after rollback or a failed save.
			using FileStream backup = new(backupPath, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 65536, FileOptions.DeleteOnClose);
			target.Position = 0;
			target.CopyTo(backup);
			backup.Flush(flushToDisk: true);
			backup.Position = 0;
			byte[] backupHash = System.Security.Cryptography.SHA256.HashData(backup);
			if (!originalHash.AsSpan().SequenceEqual(backupHash))
			{
				throw new IOException("The temporary backup does not match the original package. No write was performed.");
			}

			try
			{
				// All existing native validation and preservation checks already
				// succeeded in WritePackageVersionCopy. Verify the exact saved
				// bytes against that validated file using the same locked handle.
				WriteAndVerifyVersionFile(validated, target, validatedHash);
			}
			catch (Exception saveError)
			{
				try
				{
					WriteAndVerifyVersionFile(backup, target, originalHash);
				}
				catch (Exception restoreError)
				{
					throw new AggregateException("The version save failed and automatic restoration also failed. The selected package may be incomplete.", saveError, restoreError);
				}
				throw new IOException("The version save failed. The original package was automatically restored and verified; no version change was committed.", saveError);
			}
		}
		catch (Exception ex)
		{
			failure = ex;
		}
		finally
		{
			// Covers failure to acquire the DeleteOnClose replacement handle too.
			// All stream scopes have exited before this fallback deletion runs.
			if (replacementCreated)
			{
				DeleteVersionWorkFile(replacement, cleanupErrors);
			}
		}
		if (cleanupErrors.Count > 0)
		{
			if (failure is not null)
			{
				cleanupErrors.Insert(0, failure);
			}
			throw new AggregateException("Version-edit temporary-file cleanup failed. The operation did not complete cleanly.", cleanupErrors);
		}
		if (failure is not null)
		{
			System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failure).Throw();
		}
	}

	/// <summary>
	/// Retry only transient sharing/lock violations for at most three seconds.
	/// Do not retry access-denied, missing-file, disk or other unrelated failures.
	/// The same helper acquires exclusive handles for the source and work file.
	/// </summary>
	private static FileStream OpenVersionFile(string path, FileAccess access, FileOptions options)
	{
		for (int attempt = 0; ; attempt++)
		{
			try
			{
				return new FileStream(path, FileMode.Open, access, FileShare.None, 65536, options);
			}
			catch (IOException ex) when (((ex.HResult & 65535) is 32 or 33) && attempt < 12)
			{
				System.Threading.Thread.Sleep(250);
			}
		}
	}

	/// <summary>
	/// Copy and verify through the existing exclusive target handle, including EOF.
	/// Used for both committing the validated version and automatic restoration.
	/// </summary>
	private static void WriteAndVerifyVersionFile(FileStream input, FileStream target, byte[] expectedHash)
	{
		input.Position = 0;
		target.Position = 0;

		// Set the final length after copying so a shorter output leaves no suffix.
		input.CopyTo(target);
		target.SetLength(input.Length);
		target.Flush(flushToDisk: true);
		target.Position = 0;
		byte[] actualHash = System.Security.Cryptography.SHA256.HashData(target);
		if (!expectedHash.AsSpan().SequenceEqual(actualHash))
		{
			throw new InvalidDataException("The written package does not match the verified input file.");
		}
	}

	/// <summary>
	/// Delete only an owned version-edit work file; retry transient sharing failures.
	/// </summary>
	private static void DeleteVersionWorkFile(string path, List<Exception> errors)
	{
		try
		{
			for (int attempt = 0; ; attempt++)
			{
				try
				{
					File.Delete(path);
					break;
				}
				catch (IOException ex) when (((ex.HResult & 65535) is 32 or 33) && attempt < 12)
				{
					System.Threading.Thread.Sleep(250);
				}
			}
			if (File.Exists(path))
			{
				throw new IOException("The temporary file still exists after deletion.");
			}
		}
		catch (Exception ex)
		{
			errors.Add(new IOException("Could not remove a version-edit temporary file.", ex));
		}
	}

	/// <summary>
	/// Plain managed tree data; no COM pointers cross the worker boundary.
	/// </summary>
	internal sealed class PackageTreeEntry(string name, bool directory, ulong? size = null)
	{
		internal string Name { get; } = name;
		internal bool IsDirectory { get; } = directory;
		internal ulong? Size { get; } = size;
		internal List<PackageTreeEntry> Children { get; } = [];
	}

	/// <summary>
	/// Read-only native enumeration, including nested package streams.
	/// </summary>
	internal static PackageTreeEntry ReadPackageTree(string packagePath)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(packagePath);
		string path = Path.GetFullPath(packagePath);
		string extension = Path.GetExtension(path);
		bool bundle = string.Equals(extension, ".msixbundle", StringComparison.OrdinalIgnoreCase);
		if (!bundle && !string.Equals(extension, ".msix", StringComparison.OrdinalIgnoreCase))
		{
			throw new ArgumentException("Select an unencrypted MSIX or MSIXBundle.");
		}

		int initialization = NativeMethods.CoInitializeEx(IntPtr.Zero, 0);
		if (initialization < 0 && initialization != unchecked((int)0x80010106))
		{
			Marshal.ThrowExceptionForHR(initialization);
		}
		try
		{
			using FileStream guard = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
			using NativePackage package = new(path, bundle);
			int remaining = 100000;
			return package.ReadTree(Path.GetFileName(path), 0, ref remaining);
		}
		finally
		{
			if (initialization >= 0)
			{
				NativeMethods.CoUninitialize();
			}
		}
	}

	/// <summary>
	/// Raw packaging COM ABI, following appxpackaging.h method order. Owned pointers
	/// are released deterministically; strings use CoTaskMemFree. BOOL is Int32.
	/// </summary>
	private sealed unsafe partial class NativePackage : IDisposable
	{
		private const int FileNotFound = unchecked((int)0x80070002);
		private IntPtr reader;
		private IntPtr blockMap;
		private readonly bool bundle;

		internal NativePackage(string path, bool isBundle)
		{
			bundle = isBundle;
			IntPtr stream = OpenFileStream(path, 0x20);
			try
			{
				InitializeReader(stream);
			}
			finally
			{
				Release(stream);
			}
		}

		internal NativePackage(IntPtr stream, bool isBundle)
		{
			bundle = isBundle;
			SeekStart(stream);
			InitializeReader(stream);
		}

		private void InitializeReader(IntPtr stream)
		{
			IntPtr factory = IntPtr.Zero;
			try
			{
				Guid clsid = bundle ? new("378E0446-5384-43B7-8877-E7DBDD883446") : new("5842a140-ff9f-4166-8f5c-62f5b7b0c781");
				Guid iid = bundle ? new("BBA65864-965F-4A5F-855F-F074BDBF3A7B") : new("BEB94909-E451-438B-B5A7-D79E767B75D8");
				Marshal.ThrowExceptionForHR(NativeMethods.CoCreateInstance(in clsid, IntPtr.Zero, 1, in iid, out factory));
				IntPtr result = IntPtr.Zero;
				int hr = ((delegate* unmanaged[Stdcall]<IntPtr, IntPtr, IntPtr*, int>)Slot(factory, 4))(factory, stream, &result);
				reader = result;
				Marshal.ThrowExceptionForHR(hr);
				blockMap = GetPointer(reader, bundle ? 4 : 3);
			}
			catch
			{
				Dispose();
				throw;
			}
			finally
			{
				Release(factory);
			}
		}

		private static IntPtr OpenFileStream(string path, uint mode)
		{
			IntPtr stream = IntPtr.Zero;
			fixed (char* filename = path)
			{
				int hr = NativeMethods.SHCreateStreamOnFileEx((ushort*)filename, mode, 0, 0, IntPtr.Zero, &stream);
				if (hr < 0)
				{
					Release(stream);
					Marshal.ThrowExceptionForHR(hr);
				}
			}
			return stream != IntPtr.Zero ? stream : throw new InvalidDataException("The native file stream is null.");
		}

		internal bool HasSignature()
		{
			IntPtr file = IntPtr.Zero;
			try
			{
				int hr = GetFootprint(2, &file);
				if (hr == FileNotFound)
				{
					return false;
				}
				Marshal.ThrowExceptionForHR(hr);
				if (file == IntPtr.Zero)
				{
					throw new InvalidDataException("The native reader returned a null signature file.");
				}
				return true;
			}
			finally
			{
				Release(file);
			}
		}

		internal void ValidateBlockMap()
		{
			IntPtr enumerator = GetPointer(blockMap, 4);
			try
			{
				while (HasCurrent(enumerator))
				{
					IntPtr mappedFile = GetPointer(enumerator, 3);
					IntPtr file = IntPtr.Zero;
					IntPtr stream = IntPtr.Zero;
					try
					{
						string name = GetString(mappedFile, 5);
						file = GetFile(name);
						stream = GetPointer(file, 7);
						SeekStart(stream);
						int nativeValid = 0;
						Marshal.ThrowExceptionForHR(((delegate* unmanaged[Stdcall]<IntPtr, IntPtr, int*, int>)Slot(mappedFile, 7))(mappedFile, stream, &nativeValid));
						int valid = Unsafe.Read<int>(&nativeValid);
						if (valid is 0)
						{
							throw new InvalidDataException($"Native block-map validation failed: {name}");
						}
					}
					finally
					{
						Release(stream);
						Release(file);
						Release(mappedFile);
					}
					MoveNext(enumerator);
				}
			}
			finally
			{
				Release(enumerator);
			}
		}

		internal void CompareRetainedFiles(NativePackage other)
		{
			// Content-type metadata is interpreted by the native reader. It is not
			// parsed or required to remain byte-identical after signature removal.
			CompareFootprint(other, 0, required: true);
			CompareFootprint(other, 1, required: true);
			if (!bundle)
			{
				CompareFootprint(other, 3, required: false);
				CompareFootprint(other, 4, required: false);
			}
			HashSet<string> expected = PayloadNames();
			HashSet<string> actual = other.PayloadNames();
			if (!expected.SetEquals(actual))
			{
				throw new InvalidDataException("The package payload set changed during signature removal.");
			}
			foreach (string name in expected)
			{
				IntPtr left = GetFile(name);
				IntPtr right = IntPtr.Zero;
				try
				{
					right = other.GetFile(name);
					CompareFiles(left, right, name);
				}
				finally
				{
					Release(right);
					Release(left);
				}
			}
		}

		/// <summary>
		/// Avoid rebuilding when no embedded payload signature needs removal.
		/// </summary>
		internal bool HasSignedInnerPackages()
		{
			foreach (string name in PayloadNames())
			{
				IntPtr file = GetFile(name);
				IntPtr stream = IntPtr.Zero;
				try
				{
					stream = GetPointer(file, 7);
					using NativePackage inner = new(stream, false);
					if (inner.HasSignature())
					{
						return true;
					}
				}
				finally
				{
					Release(stream);
					Release(file);
				}
			}
			return false;
		}

		/// <summary>
		/// Preserve version and default applicability; reject optional/external bundles and unsupported hashes.
		/// </summary>
		internal bool RebuildWithoutInnerSignatures(string outputPath)
		{
			Dictionary<string, bool> flags = BundleApplicability();
			ulong version = BundleVersion();
			if (version is 0 || !string.Equals(HashMethod(), "http://www.w3.org/2001/04/xmlenc#sha256", StringComparison.OrdinalIgnoreCase))
			{
				throw new NotSupportedException("Inner removal supports self-contained SHA-256 bundles with a nonzero version. Use outer-only removal for other bundles.");
			}

			string staging = Directory.CreateDirectory(Path.Join(Path.GetDirectoryName(outputPath), $".inner-{Guid.CreateVersion7():N}")).FullName;
			IntPtr output = IntPtr.Zero;
			IntPtr factory = IntPtr.Zero;
			IntPtr writer = IntPtr.Zero;
			IntPtr writer4 = IntPtr.Zero;
			List<IntPtr> streams = new(flags.Count);
			bool changed = false;
			try
			{
				output = OpenFileStream(outputPath, 0x12);
				Guid clsid = new("378E0446-5384-43B7-8877-E7DBDD883446");
				Guid iid = new("BBA65864-965F-4A5F-855F-F074BDBF3A7B");
				Marshal.ThrowExceptionForHR(NativeMethods.CoCreateInstance(in clsid, IntPtr.Zero, 1, in iid, out factory));
				IntPtr result = IntPtr.Zero;
				int hr = ((delegate* unmanaged[Stdcall]<IntPtr, IntPtr, ulong, IntPtr*, int>)Slot(factory, 3))(factory, output, version, &result);
				writer = result;
				Marshal.ThrowExceptionForHR(hr);
				writer4 = Query(writer, new("9CD9D523-5009-4C01-9882-DC029FBD47A3"));

				foreach (KeyValuePair<string, bool> item in flags)
				{
					IntPtr file = GetFile(item.Key);
					IntPtr stream = IntPtr.Zero;
					try
					{
						stream = GetPointer(file, 7);
						bool signed;
						using (NativePackage inner = new(stream, false))
						{
							inner.ValidateBlockMap();
							signed = inner.HasSignature();
						}
						if (signed)
						{
							// Never use an untrusted payload name as a disk extraction path.
							string innerPath = Path.Join(staging, $"{Guid.CreateVersion7():N}.msix");
							CopyToFile(stream, innerPath);
							RemoveUsingSip(innerPath);
							using (NativePackage before = new(stream, false))
							using (NativePackage after = new(innerPath, false))
							{
								if (after.HasSignature())
								{
									throw new InvalidDataException($"Inner signature remains: {item.Key}");
								}
								after.ValidateBlockMap();
								before.CompareRetainedFiles(after);
							}
							Release(stream); stream = IntPtr.Zero;
							stream = OpenFileStream(innerPath, 0x20);
							changed = true;
						}
						SeekStart(stream);
						fixed (char* filename = item.Key)
						{
							Marshal.ThrowExceptionForHR(((delegate* unmanaged[Stdcall]<IntPtr, char*, IntPtr, int, int>)Slot(writer4, 3))(writer4, filename, stream, item.Value ? 1 : 0));
						}
						streams.Add(stream); stream = IntPtr.Zero;
					}
					finally
					{
						Release(stream);
						Release(file);
					}
				}
				// Close writes fresh native bundle manifest, content types and block map.
				Marshal.ThrowExceptionForHR(((delegate* unmanaged[Stdcall]<IntPtr, int>)Slot(writer, 4))(writer));
				return changed;
			}
			finally
			{
				Release(writer4);
				Release(writer);
				Release(factory);
				Release(output);
				foreach (IntPtr stream in streams)
				{
					Release(stream);
				}
				try
				{
					Directory.Delete(staging, recursive: true);
				}
				catch (Exception ex)
				{
					Logger.Write($"Could not delete staging directory '{staging}': {ex.Message}");
				}
			}
		}

		/// <summary>
		/// Outer metadata must change; retained inner contents must not.
		/// </summary>
		internal void CompareRebuiltBundle(NativePackage other)
		{
			if (BundleVersion() != other.BundleVersion() ||
				!string.Equals(BundleFullName(), other.BundleFullName(), StringComparison.OrdinalIgnoreCase) ||
				!string.Equals(HashMethod(), other.HashMethod(), StringComparison.OrdinalIgnoreCase))
			{
				throw new InvalidDataException("The rebuilt bundle identity, version or hash method changed.");
			}

			Dictionary<string, string> expectedMetadata = BundleManifestMetadata();
			Dictionary<string, string> actualMetadata = other.BundleManifestMetadata();

			if (expectedMetadata.Count != actualMetadata.Count)
			{
				throw new InvalidDataException("Bundle manifest membership changed.");
			}

			foreach (KeyValuePair<string, string> item in expectedMetadata)
			{
				if (!actualMetadata.TryGetValue(item.Key, out string? metadata) || !string.Equals(item.Value, metadata, StringComparison.OrdinalIgnoreCase))
				{
					throw new InvalidDataException($"Bundle manifest identity, type or resource qualifiers changed: {item.Key}");
				}
			}
			Dictionary<string, bool> expected = BundleApplicability();
			Dictionary<string, bool> actual = other.BundleApplicability();

			if (expected.Count != actual.Count)
			{
				throw new InvalidDataException("The rebuilt bundle payload set changed.");
			}

			foreach (KeyValuePair<string, bool> item in expected)
			{
				if (!actual.TryGetValue(item.Key, out bool flag) || flag != item.Value)
				{
					throw new InvalidDataException($"Bundle applicability changed: {item.Key}");
				}
				IntPtr left = GetFile(item.Key);
				IntPtr right = IntPtr.Zero;
				IntPtr leftStream = IntPtr.Zero;
				IntPtr rightStream = IntPtr.Zero;
				try
				{
					right = other.GetFile(item.Key);
					leftStream = GetPointer(left, 7);
					rightStream = GetPointer(right, 7);
					using NativePackage before = new(leftStream, false);
					using NativePackage after = new(rightStream, false);
					if (after.HasSignature())
					{
						throw new InvalidDataException($"Signed inner package remains: {item.Key}");
					}
					after.ValidateBlockMap();
					before.CompareRetainedFiles(after);
					if (!before.HasSignature())
					{
						CompareFiles(left, right, item.Key);
					}
				}
				finally
				{
					Release(rightStream);
					Release(leftStream);
					Release(right);
					Release(left);
				}
			}
		}

		/// <summary>
		/// Compare the native manifest object model.
		/// </summary>
		private Dictionary<string, string> BundleManifestMetadata()
		{
			IntPtr manifest = GetPointer(reader, 5);
			IntPtr enumerator = IntPtr.Zero;
			try
			{
				enumerator = GetPointer(manifest, 4);
				Dictionary<string, string> metadata = new(StringComparer.OrdinalIgnoreCase);
				while (HasCurrent(enumerator))
				{
					IntPtr info = GetPointer(enumerator, 3);
					IntPtr id = IntPtr.Zero;
					IntPtr resources = IntPtr.Zero;
					try
					{
						string name = GetString(info, 5);
						id = GetPointer(info, 4);
						uint type = GetUInt32(info, 3);
						resources = GetPointer(info, 8);
						List<string> qualifiers = [];
						while (HasCurrent(resources))
						{
							IntPtr resource = GetPointer(resources, 3);
							IntPtr language = IntPtr.Zero;
							try
							{
								Marshal.ThrowExceptionForHR(((delegate* unmanaged[Stdcall]<IntPtr, IntPtr*, int>)Slot(resource, 3))(resource, &language));
								string text = Marshal.PtrToStringUni(language) ?? string.Empty;
								qualifiers.Add($"{text}|{GetUInt32(resource, 4)}|{GetUInt32(resource, 5)}");
							}
							finally
							{
								NativeMethods.CoTaskMemFree(language);
								Release(resource);
							}
							MoveNext(resources);
						}
						qualifiers.Sort(StringComparer.OrdinalIgnoreCase);

						if (!metadata.TryAdd(name, $"{GetString(id, 9)}|{type}|{string.Join(';', qualifiers)}"))
						{
							throw new InvalidDataException($"Duplicate bundle manifest entry: {name}");
						}
					}
					finally
					{
						Release(resources);
						Release(id);
						Release(info);
					}
					MoveNext(enumerator);
				}
				return metadata;
			}
			finally
			{
				Release(enumerator);
				Release(manifest);
			}
		}

		private static uint GetUInt32(IntPtr instance, int slot)
		{
			uint nativeValue = 0;
			Marshal.ThrowExceptionForHR(((delegate* unmanaged[Stdcall]<IntPtr, uint*, int>)Slot(instance, slot))(instance, &nativeValue));
			return Unsafe.Read<uint>(&nativeValue);
		}

		private Dictionary<string, bool> BundleApplicability()
		{
			IntPtr manifest = GetPointer(reader, 5);
			IntPtr manifest2 = IntPtr.Zero;
			IntPtr optional = IntPtr.Zero;
			IntPtr enumerator = IntPtr.Zero;
			try
			{
				// Versioned interfaces are independent IUnknown vtables, not slot offsets
				// in the base interface. QueryInterface is required before invoking them.
				manifest2 = Query(manifest, new("5517DF70-033F-4AF2-8213-87D766805C02"));
				optional = GetPointer(manifest2, 3);
				if (HasCurrent(optional))
				{
					throw new NotSupportedException("Optional-reference bundles are not rebuilt. Use outer-only removal.");
				}
				enumerator = GetPointer(manifest, 4);
				Dictionary<string, bool> flags = new(StringComparer.OrdinalIgnoreCase);

				while (HasCurrent(enumerator))
				{
					IntPtr info = GetPointer(enumerator, 3);
					IntPtr info2 = IntPtr.Zero;
					try
					{
						string name = GetString(info, 5);
						// IAppxBundleManifestPackageInfo2 has its own IUnknown vtable.
						// Slot 3 is GetIsPackageReference;
						// slot 5 is GetIsDefaultApplicablePackage.
						// Use the published package-info2 IID.
						info2 = Query(info, new("44C2ACBC-B2CF-4CCB-BBDB-9C6DA8C3BC9E"));
						if (GetUInt32(info2, 3) is not 0)
						{
							throw new NotSupportedException($"External package references cannot be rebuilt: {name}");
						}
						bool defaultApplicable = GetUInt32(info2, 5) is not 0;
						if (!flags.TryAdd(name, defaultApplicable))
						{
							throw new InvalidDataException($"Duplicate bundle package: {name}");
						}
					}
					finally
					{
						Release(info2);
						Release(info);
					}
					MoveNext(enumerator);
				}
				if (!PayloadNames().SetEquals(flags.Keys))
				{
					throw new NotSupportedException("Flat/external-reference bundles are not rebuilt. Use outer-only removal.");
				}
				return flags;
			}
			finally
			{
				Release(enumerator);
				Release(optional);
				Release(manifest2);
				Release(manifest);
			}
		}

		private ulong BundleVersion()
		{
			IntPtr manifest = GetPointer(reader, 5);
			IntPtr id = IntPtr.Zero;
			try
			{
				id = GetPointer(manifest, 3);
				return GetUInt64(id, 6);
			}
			finally
			{
				Release(id);
				Release(manifest);
			}
		}

		private string BundleFullName()
		{
			IntPtr manifest = GetPointer(reader, 5);
			IntPtr id = IntPtr.Zero;
			try
			{
				id = GetPointer(manifest, 3);
				return GetString(id, 9);
			}
			finally
			{
				Release(id);
				Release(manifest);
			}
		}

		private string HashMethod()
		{
			IntPtr uri = GetPointer(blockMap, 5);
			IntPtr text = IntPtr.Zero;
			try
			{
				Marshal.ThrowExceptionForHR(((delegate* unmanaged[Stdcall]<IntPtr, IntPtr*, int>)Slot(uri, 7))(uri, &text));
				return Marshal.PtrToStringBSTR(text);
			}
			finally
			{
				NativeMethods.SysFreeString(text);
				Release(uri);
			}
		}

		private static IntPtr Query(IntPtr instance, Guid iid)
		{
			IntPtr result = IntPtr.Zero;
			int hr = ((delegate* unmanaged[Stdcall]<IntPtr, Guid*, IntPtr*, int>)Slot(instance, 0))(instance, &iid, &result);
			if (hr < 0)
			{
				Release(result);
				// Preserve the native HRESULT and requested IID instead of a generic cast error.
				throw new InvalidOperationException($"QueryInterface failed for IID {iid:D} (HRESULT 0x{unchecked((uint)hr):X8}).");
			}
			return result != IntPtr.Zero ? result : throw new InvalidDataException($"QueryInterface returned null for IID {iid:D}.");
		}

		private static ulong GetUInt64(IntPtr instance, int slot)
		{
			ulong nativeValue = 0;
			Marshal.ThrowExceptionForHR(((delegate* unmanaged[Stdcall]<IntPtr, ulong*, int>)Slot(instance, slot))(instance, &nativeValue));
			return Unsafe.Read<ulong>(&nativeValue);
		}

		private static void CopyToFile(IntPtr stream, string path)
		{
			SeekStart(stream);
			using FileStream output = new(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
			byte[] buffer = new byte[65536];
			int count;
			while ((count = Fill(stream, buffer)) > 0)
			{
				output.Write(buffer, 0, count);
			}
			output.Flush(flushToDisk: true);
		}

		/// <summary>
		/// Enumerate native file objects; nested readers use IStream directly.
		/// </summary>
		internal PackageTreeEntry ReadTree(string name, int depth, ref int remaining, PackageTreeEntry? existingRoot = null)
		{
			if (depth > 16)
			{
				throw new InvalidDataException("Package nesting exceeds 16 levels.");
			}
			PackageTreeEntry root;
			if (existingRoot is null)
			{
				ConsumeEntry(ref remaining);
				// The selected package is a file, even though its contents are expandable.
				root = new(name, false);
			}
			else
			{
				// Reuse the embedded package node without adding or counting a wrapper.
				root = existingRoot;
			}
			List<string> names = new(PayloadNames());
			names.Sort(StringComparer.OrdinalIgnoreCase);
			foreach (string fileName in names)
			{
				IntPtr file = GetFile(fileName);
				IntPtr stream = IntPtr.Zero;
				try
				{
					PackageTreeEntry leaf = AddTreePath(root, fileName, GetUInt64(file, 6), ref remaining);
					string extension = Path.GetExtension(fileName);
					bool nestedBundle = string.Equals(extension, ".msixbundle", StringComparison.OrdinalIgnoreCase) || string.Equals(extension, ".appxbundle", StringComparison.OrdinalIgnoreCase);
					bool nestedPackage = bundle || string.Equals(extension, ".msix", StringComparison.OrdinalIgnoreCase) || string.Equals(extension, ".appx", StringComparison.OrdinalIgnoreCase);
					if (nestedBundle || nestedPackage)
					{
						stream = GetPointer(file, 7);
						using NativePackage nested = new(stream, nestedBundle);
						// Put native contents directly beneath the embedded package file.
						_ = nested.ReadTree(leaf.Name, depth + 1, ref remaining, leaf);
					}
				}
				finally
				{
					Release(stream);
					Release(file);
				}
			}
			for (int type = 0; type <= (bundle ? 2 : 4); type++)
			{
				IntPtr file = IntPtr.Zero;
				try
				{
					int hr = GetFootprint(type, &file);
					if (hr == FileNotFound)
					{
						continue;
					}
					Marshal.ThrowExceptionForHR(hr);
					_ = AddTreePath(root, GetString(file, 5), GetUInt64(file, 6), ref remaining);
				}
				finally
				{
					Release(file);
				}
			}
			// Native readers expose MIME types, not a raw content-types footprint stream.
			_ = AddTreePath(root, "[Content_Types].xml (native-managed metadata)", null, ref remaining);
			return root;
		}

		private static PackageTreeEntry AddTreePath(PackageTreeEntry root, string path, ulong? size, ref int remaining)
		{
			string[] parts = path.Replace('\\', '/').Split('/');
			if (parts.Length > 64)
			{
				throw new InvalidDataException("Package folder depth exceeds 64 levels.");
			}
			PackageTreeEntry parent = root;
			for (int index = 0; index < parts.Length; index++)
			{
				string part = parts[index];
				if (string.IsNullOrWhiteSpace(part) || string.Equals(part, ".", StringComparison.OrdinalIgnoreCase) || string.Equals(part, "..", StringComparison.OrdinalIgnoreCase))
				{
					throw new InvalidDataException($"Invalid native entry path: {path}");
				}
				PackageTreeEntry? existing = null;
				foreach (PackageTreeEntry child in parent.Children)
				{
					if (string.Equals(child.Name, part, StringComparison.OrdinalIgnoreCase))
					{
						existing = child;
						break;
					}
				}
				bool directory = index < parts.Length - 1;
				if (existing is null)
				{
					ConsumeEntry(ref remaining);
					existing = new(part, directory, directory ? null : size);
					parent.Children.Add(existing);
				}
				else if (existing.IsDirectory != directory)
				{
					throw new InvalidDataException($"Conflicting native entry path: {path}");
				}
				parent = existing;
			}
			return parent;
		}

		private static void ConsumeEntry(ref int remaining) =>
			_ = --remaining >= 0 ? remaining : throw new InvalidDataException("Package exploration exceeds 100,000 nodes.");

		private HashSet<string> PayloadNames()
		{
			HashSet<string> names = new(StringComparer.OrdinalIgnoreCase);
			IntPtr enumerator = GetPointer(reader, 6);
			try
			{
				while (HasCurrent(enumerator))
				{
					IntPtr file = GetPointer(enumerator, 3);
					try
					{
						string name = GetString(file, 5);
						if (!names.Add(name))
						{
							throw new InvalidDataException($"Duplicate native payload name: {name}");
						}
					}
					finally
					{
						Release(file);
					}
					MoveNext(enumerator);
				}
			}
			finally
			{
				Release(enumerator);
			}
			return names;
		}

		private IntPtr GetFile(string name)
		{
			string normalizedName = name.Replace('/', '\\');

			int footprint = string.Equals(normalizedName, bundle ? "AppxMetadata\\AppxBundleManifest.xml" : "AppxManifest.xml", StringComparison.OrdinalIgnoreCase) ? 0 :
				string.Equals(normalizedName, "AppxBlockMap.xml", StringComparison.OrdinalIgnoreCase) ? 1 :
				!bundle && string.Equals(normalizedName, "AppxMetadata\\CodeIntegrity.cat", StringComparison.OrdinalIgnoreCase) ? 3 :
				!bundle && string.Equals(normalizedName, "AppxContentGroupMap.xml", StringComparison.OrdinalIgnoreCase) ? 4 : -1;

			IntPtr file = IntPtr.Zero;
			int hr;
			if (footprint >= 0)
			{
				hr = GetFootprint(footprint, &file);
			}
			else
			{
				fixed (char* filename = name)
				{
					hr = ((delegate* unmanaged[Stdcall]<IntPtr, char*, IntPtr*, int>)Slot(reader, bundle ? 7 : 5))(reader, filename, &file);
				}
			}
			if (hr < 0)
			{
				Release(file);
				Marshal.ThrowExceptionForHR(hr);
			}
			return file != IntPtr.Zero ? file : throw new InvalidDataException($"The native reader returned a null file: {name}");
		}

		private void CompareFootprint(NativePackage other, int type, bool required)
		{
			IntPtr left = IntPtr.Zero;
			IntPtr right = IntPtr.Zero;
			try
			{
				int leftResult = GetFootprint(type, &left);
				int rightResult = other.GetFootprint(type, &right);
				string footprintName = type switch
				{
					0 => bundle ? "AppxMetadata\\AppxBundleManifest.xml" : "AppxManifest.xml",
					1 => "AppxBlockMap.xml",
					3 => "AppxMetadata\\CodeIntegrity.cat",
					4 => "AppxContentGroupMap.xml",
					_ => $"footprint type {type}"
				};

				if (!required && leftResult == FileNotFound && rightResult == FileNotFound)
				{
					return;
				}

				// The code-integrity catalog is signing metadata, not a retained payload.
				// Accept only its disappearance across a confirmed signed-to-unsigned
				// transition. Other missing/added footprints remain validation failures.
				if (!required && type is 3 && leftResult >= 0 && rightResult == FileNotFound &&
					HasSignature() && !other.HasSignature())
				{
					Logger.Write($"Native signature removal also removed '{footprintName}'.");
					return;
				}
				if (leftResult < 0 || rightResult < 0)
				{
					throw new InvalidDataException(
						$"Footprint comparison failed for '{footprintName}'. Original HRESULT: 0x{unchecked((uint)leftResult):X8}; unsigned-copy HRESULT: 0x{unchecked((uint)rightResult):X8}.",
						Marshal.GetExceptionForHR(leftResult < 0 ? leftResult : rightResult));
				}
				CompareFiles(left, right, footprintName);
			}
			finally
			{
				Release(right);
				Release(left);
			}
		}

		private static void CompareFiles(IntPtr left, IntPtr right, string name)
		{
			if (!string.Equals(GetString(left, 4), GetString(right, 4), StringComparison.OrdinalIgnoreCase))
			{
				throw new InvalidDataException($"Native content type changed: {name}");
			}
			IntPtr first = GetPointer(left, 7);
			IntPtr second = IntPtr.Zero;
			try
			{
				second = GetPointer(right, 7);
				SeekStart(first);
				SeekStart(second);
				byte[] firstBuffer = new byte[65536];
				byte[] secondBuffer = new byte[65536];
				while (true)
				{
					int firstCount = Fill(first, firstBuffer);
					int secondCount = Fill(second, secondBuffer);
					if (firstCount != secondCount || !firstBuffer.AsSpan(0, firstCount).SequenceEqual(secondBuffer.AsSpan(0, secondCount)))
					{
						throw new InvalidDataException($"Native package stream changed: {name}");
					}
					if (firstCount is 0)
					{
						break;
					}
				}
			}
			finally
			{
				Release(second);
				Release(first);
			}
		}

		private static void SeekStart(IntPtr stream) =>
			Marshal.ThrowExceptionForHR(((delegate* unmanaged[Stdcall]<IntPtr, long, uint, ulong*, int>)Slot(stream, 5))(stream, 0, 0, null));

		private static int Fill(IntPtr stream, byte[] buffer)
		{
			int total = 0;
			fixed (byte* data = buffer)
			{
				while (total < buffer.Length)
				{
					uint nativeRead = 0;
					uint requested = (uint)(buffer.Length - total);
					Marshal.ThrowExceptionForHR(((delegate* unmanaged[Stdcall]<IntPtr, byte*, uint, uint*, int>)Slot(stream, 3))(stream, data + total, requested, &nativeRead));
					uint read = Unsafe.Read<uint>(&nativeRead);
					if (read > requested)
					{
						throw new InvalidDataException("Invalid native stream read length.");
					}
					if (read is 0)
					{
						break;
					}
					total += (int)read;
				}
			}
			return total;
		}

		private int GetFootprint(int type, IntPtr* file) =>
			((delegate* unmanaged[Stdcall]<IntPtr, int, IntPtr*, int>)Slot(reader, bundle ? 3 : 4))(reader, type, file);

		private static IntPtr GetPointer(IntPtr instance, int slot)
		{
			IntPtr result = IntPtr.Zero;
			int hr = ((delegate* unmanaged[Stdcall]<IntPtr, IntPtr*, int>)Slot(instance, slot))(instance, &result);
			if (hr < 0)
			{
				Release(result);
				Marshal.ThrowExceptionForHR(hr);
			}
			return result != IntPtr.Zero ? result : throw new InvalidDataException("A native COM method returned a null interface.");
		}

		private static string GetString(IntPtr instance, int slot)
		{
			IntPtr text = IntPtr.Zero;
			try
			{
				Marshal.ThrowExceptionForHR(((delegate* unmanaged[Stdcall]<IntPtr, IntPtr*, int>)Slot(instance, slot))(instance, &text));
				return Marshal.PtrToStringUni(text) ?? throw new InvalidDataException("A native COM method returned a null string.");
			}
			finally
			{
				NativeMethods.CoTaskMemFree(text);
			}
		}

		private static bool HasCurrent(IntPtr enumerator)
		{
			int nativeCurrent = 0;
			Marshal.ThrowExceptionForHR(((delegate* unmanaged[Stdcall]<IntPtr, int*, int>)Slot(enumerator, 4))(enumerator, &nativeCurrent));
			int current = Unsafe.Read<int>(&nativeCurrent);
			return current is not 0;
		}

		private static void MoveNext(IntPtr enumerator)
		{
			int current = 0;
			Marshal.ThrowExceptionForHR(((delegate* unmanaged[Stdcall]<IntPtr, int*, int>)Slot(enumerator, 5))(enumerator, &current));
		}

		private static void* Slot(IntPtr instance, int slot) => instance != IntPtr.Zero
			? (*(void***)instance)[slot] : throw new InvalidDataException("A native COM interface is null.");

		private static void Release(IntPtr instance) => NativeMethods.ReleaseComObject(instance);

		public void Dispose()
		{
			Release(blockMap); blockMap = IntPtr.Zero;
			Release(reader); reader = IntPtr.Zero;
		}
	}

	/// <summary>
	/// Version editing shares the existing native readers and deterministic COM ownership.
	/// </summary>
	private sealed unsafe partial class NativePackage
	{
		internal readonly record struct VersionIdentity(string Name, string Publisher, string ResourceId, uint Architecture, ulong Version);

		private VersionIdentity ReadVersionIdentity()
		{
			IntPtr manifest = GetPointer(reader, bundle ? 5 : 7);
			IntPtr id = IntPtr.Zero;
			try
			{
				id = GetPointer(manifest, 3);
				return ReadVersionIdentityFromId(id);
			}
			finally
			{
				Release(id);
				Release(manifest);
			}
		}

		private static VersionIdentity ReadVersionIdentityFromId(IntPtr id) =>
			new(GetString(id, 3), GetString(id, 5), ReadOptionalIdentityString(id, 7), GetUInt32(id, 4), GetUInt64(id, 6));

		/// <summary>
		/// Validate the selected bundle manifest identity independently of its payload.
		/// </summary>
		private VersionIdentity ReadBundleVersionIdentity(string name)
		{
			IntPtr manifest = GetPointer(reader, 5);
			IntPtr enumerator = IntPtr.Zero;
			try
			{
				enumerator = GetPointer(manifest, 4);
				while (HasCurrent(enumerator))
				{
					IntPtr info = GetPointer(enumerator, 3);
					IntPtr id = IntPtr.Zero;
					try
					{
						if (string.Equals(GetString(info, 5), name, StringComparison.OrdinalIgnoreCase))
						{
							id = GetPointer(info, 4);
							return ReadVersionIdentityFromId(id);
						}
					}
					finally
					{
						Release(id);
						Release(info);
					}
					MoveNext(enumerator);
				}
				throw new InvalidDataException($"The selected package has no bundle manifest identity: {name}");
			}
			finally
			{
				Release(enumerator);
				Release(manifest);
			}
		}

		/// <summary>
		/// GetResourceId is documented to return null when the attribute is absent.
		/// </summary>
		private static string ReadOptionalIdentityString(IntPtr instance, int slot)
		{
			IntPtr text = IntPtr.Zero;
			try
			{
				Marshal.ThrowExceptionForHR(((delegate* unmanaged[Stdcall]<IntPtr, IntPtr*, int>)Slot(instance, slot))(instance, &text));
				return Marshal.PtrToStringUni(text) ?? string.Empty;
			}
			finally
			{
				NativeMethods.CoTaskMemFree(text);
			}
		}

		internal List<PackageVersionRecord> ReadVersionRecords(string rootName)
		{
			HashSet<string> names = bundle ? PayloadNames() : new(StringComparer.OrdinalIgnoreCase);
			if (names.Count > 10000)
			{
				throw new InvalidDataException("Version inspection exceeds 10,000 embedded packages.");
			}
			List<PackageVersionRecord> result = new(names.Count + 1)
			{
				new(rootName, null, ReadVersionIdentity().Version, bundle)
			};

			List<string> ordered = new(names);
			ordered.Sort(StringComparer.OrdinalIgnoreCase);

			foreach (string name in ordered)
			{
				IntPtr file = GetFile(name);
				IntPtr stream = IntPtr.Zero;
				try
				{
					stream = GetPointer(file, 7);
					using NativePackage inner = new(stream, false);
					result.Add(new(name, name, inner.ReadVersionIdentity().Version, false));
				}
				finally
				{
					Release(stream);
					Release(file);
				}
			}
			return result;
		}

		internal ulong VersionFor(string? innerName)
		{
			if (innerName is null)
			{
				return ReadVersionIdentity().Version;
			}
			if (!bundle || !PayloadNames().Contains(innerName))
			{
				throw new ArgumentException("The selected inner package is not a payload of this bundle.");
			}

			IntPtr file = GetFile(innerName);
			IntPtr stream = IntPtr.Zero;
			try
			{
				stream = GetPointer(file, 7);
				using NativePackage inner = new(stream, false);
				return inner.ReadVersionIdentity().Version;
			}
			finally
			{
				Release(stream);
				Release(file);
			}
		}

		/// <summary>
		/// Native writer regenerates footprints; payload bytes and MIME types are retained.
		/// </summary>
		internal void WriteVersionPackage(string outputPath, ulong version)
		{
			if (bundle)
			{
				throw new InvalidOperationException("Use the bundle writer for an MSIXBundle.");
			}
			IntPtr output = IntPtr.Zero;
			IntPtr factory = IntPtr.Zero;
			IntPtr writer = IntPtr.Zero;
			IntPtr writer2 = IntPtr.Zero;
			IntPtr groupMapFile = IntPtr.Zero;
			IntPtr groupMapStream = IntPtr.Zero;
			IntPtr hashUri = IntPtr.Zero;
			IntPtr manifestFile = IntPtr.Zero;
			IntPtr manifestStream = IntPtr.Zero;
			IntPtr editedManifest = IntPtr.Zero;
			HashSet<string> names = PayloadNames();
			List<IntPtr> streams = new(names.Count);
			try
			{
				output = OpenFileStream(outputPath, 0x12);
				Guid clsid = new("5842a140-ff9f-4166-8f5c-62f5b7b0c781");
				Guid iid = new("BEB94909-E451-438B-B5A7-D79E767B75D8");

				Marshal.ThrowExceptionForHR(NativeMethods.CoCreateInstance(in clsid, IntPtr.Zero, 1, in iid, out factory));
				hashUri = GetPointer(blockMap, 5);
				APPX_PACKAGE_SETTINGS settings = new() { forceZip32 = 0, hashMethod = hashUri };
				IntPtr nativeWriter = IntPtr.Zero;
				int hr = ((delegate* unmanaged[Stdcall]<IntPtr, IntPtr, APPX_PACKAGE_SETTINGS*, IntPtr*, int>)Slot(factory, 3))(factory, output, &settings, &nativeWriter);
				writer = nativeWriter;
				Marshal.ThrowExceptionForHR(hr);

				foreach (string name in names)
				{
					AddVersionPayload(writer, GetFile(name), streams);
				}
				// Content-group metadata is retained. The old signing catalog is deliberately
				// omitted because it cannot authenticate a manifest with a changed version.
				hr = GetFootprint(4, &groupMapFile);
				if (hr == FileNotFound)
				{
					Release(groupMapFile); groupMapFile = IntPtr.Zero;
				}
				else
				{
					Marshal.ThrowExceptionForHR(hr);
					groupMapStream = GetPointer(groupMapFile, 7);
					SeekStart(groupMapStream);
					// IAppxPackageWriter2 is an independent IUnknown interface. Its
					// Close method writes the content-group map as a native footprint.
					writer2 = Query(writer, new("2CF5C4FD-E54C-4EA5-BA4E-F8C4B105A8C8"));
				}
				manifestFile = GetFile("AppxManifest.xml");
				manifestStream = GetPointer(manifestFile, 7);
				using NativeManifestDocument document = new(manifestStream);
				document.SetVersion(FormatPackageVersion(version));
				editedManifest = NativeMethods.SHCreateMemStream(null, 0);
				if (editedManifest == IntPtr.Zero)
				{
					throw new InvalidOperationException("Could not allocate the native manifest stream.");
				}
				document.Save(editedManifest);
				SeekStart(editedManifest);

				// Close performs the native manifest validation and writes fresh footprints.
				if (writer2 == IntPtr.Zero)
				{
					Marshal.ThrowExceptionForHR(((delegate* unmanaged[Stdcall]<IntPtr, IntPtr, int>)Slot(writer, 4))(writer, editedManifest));
				}
				else
				{
					Marshal.ThrowExceptionForHR(((delegate* unmanaged[Stdcall]<IntPtr, IntPtr, IntPtr, int>)Slot(writer2, 3))(writer2, editedManifest, groupMapStream));
				}
			}
			finally
			{
				Release(writer2);
				Release(writer);
				Release(factory);
				Release(output);
				Release(hashUri);
				Release(groupMapStream);
				Release(groupMapFile);
				Release(editedManifest);
				Release(manifestStream);
				Release(manifestFile);
				foreach (IntPtr stream in streams)
				{
					Release(stream);
				}
			}
		}

		/// <summary>
		/// Takes ownership of file; input streams stay alive through writer.Close.
		/// </summary>
		private static void AddVersionPayload(IntPtr writer, IntPtr file, List<IntPtr> streams)
		{
			IntPtr stream = IntPtr.Zero;
			try
			{
				string name = GetString(file, 5);
				string contentType = GetString(file, 4);
				uint compression = GetUInt32(file, 3);
				stream = GetPointer(file, 7);
				SeekStart(stream);
				fixed (char* filename = name)
				fixed (char* mime = contentType)
				{
					Marshal.ThrowExceptionForHR(((delegate* unmanaged[Stdcall]<IntPtr, char*, char*, uint, IntPtr, int>)Slot(writer, 3))(writer, filename, mime, compression, stream));
				}
				streams.Add(stream);
				stream = IntPtr.Zero;
			}
			finally
			{
				Release(stream);
				Release(file);
			}
		}

		internal void WriteVersionBundle(string outputPath, string? innerName, ulong version)
		{
			if (!bundle)
			{
				throw new InvalidOperationException("The selected source is not a bundle.");
			}
			Dictionary<string, bool> flags = VersionBundleFlags();

			if (!string.Equals(HashMethod(), "http://www.w3.org/2001/04/xmlenc#sha256", StringComparison.OrdinalIgnoreCase))
			{
				throw new NotSupportedException("Version editing currently supports self-contained SHA-256 bundles. No output was published.");
			}

			if (innerName is not null && !flags.ContainsKey(innerName))
			{
				throw new ArgumentException("The selected inner package is not in the bundle.");
			}

			ulong outerVersion = innerName is null ? version : ReadVersionIdentity().Version;

			if (outerVersion is 0)
			{
				throw new NotSupportedException("A zero bundle version cannot be preserved by the native writer.");
			}

			string innerPath = Path.Join(Path.GetDirectoryName(outputPath), $".version-inner-{Guid.CreateVersion7():N}.msix");
			bool innerCreated = false;
			IntPtr output = IntPtr.Zero;
			IntPtr factory = IntPtr.Zero;
			IntPtr writer = IntPtr.Zero;
			IntPtr writer4 = IntPtr.Zero;
			List<IntPtr> streams = new(flags.Count);
			try
			{
				output = OpenFileStream(outputPath, 0x12);
				Guid clsid = new("378E0446-5384-43B7-8877-E7DBDD883446");
				Guid iid = new("BBA65864-965F-4A5F-855F-F074BDBF3A7B");
				Marshal.ThrowExceptionForHR(NativeMethods.CoCreateInstance(in clsid, IntPtr.Zero, 1, in iid, out factory));
				IntPtr nativeWriter = IntPtr.Zero;
				int hr = ((delegate* unmanaged[Stdcall]<IntPtr, IntPtr, ulong, IntPtr*, int>)Slot(factory, 3))(factory, output, outerVersion, &nativeWriter);
				writer = nativeWriter;
				Marshal.ThrowExceptionForHR(hr);
				writer4 = Query(writer, new("9CD9D523-5009-4C01-9882-DC029FBD47A3"));

				foreach (KeyValuePair<string, bool> item in flags)
				{
					IntPtr file = GetFile(item.Key);
					IntPtr stream = IntPtr.Zero;
					try
					{
						stream = GetPointer(file, 7);
						if (innerName is not null && string.Equals(item.Key, innerName, StringComparison.OrdinalIgnoreCase))
						{
							using (FileStream placeholder = new(innerPath, FileMode.CreateNew, FileAccess.Write, FileShare.None)) { innerCreated = true; }
							using (NativePackage selected = new(stream, false))
							{
								selected.ValidateBlockMap();
								selected.WriteVersionPackage(innerPath, version);
							}
							Release(stream);
							stream = IntPtr.Zero;
							stream = OpenFileStream(innerPath, 0x20);
						}
						SeekStart(stream);
						fixed (char* filename = item.Key)
						{
							Marshal.ThrowExceptionForHR(((delegate* unmanaged[Stdcall]<IntPtr, char*, IntPtr, int, int>)Slot(writer4, 3))(writer4, filename, stream, item.Value ? 1 : 0));
						}
						streams.Add(stream);
						stream = IntPtr.Zero;
					}
					finally
					{
						Release(stream);
						Release(file);
					}
				}
				Marshal.ThrowExceptionForHR(((delegate* unmanaged[Stdcall]<IntPtr, int>)Slot(writer, 4))(writer));
			}
			finally
			{
				Release(writer4);
				Release(writer);
				Release(factory);
				Release(output);
				foreach (IntPtr stream in streams)
				{
					Release(stream);
				}
				if (innerCreated && File.Exists(innerPath))
				{
					try
					{
						File.Delete(innerPath);
					}
					catch (Exception ex)
					{
						Logger.Write($"Could not delete version-edit inner file '{innerPath}': {ex.Message}");
					}
				}
			}
		}

		private Dictionary<string, bool> VersionBundleFlags()
		{
			try
			{
				return BundleApplicability();
			}
			catch (NotSupportedException ex)
			{
				throw new NotSupportedException("Version editing does not rebuild optional-reference or flat/external-reference bundles.", ex);
			}
		}

		private static void CompareVersionIdentity(VersionIdentity before, VersionIdentity after, ulong expectedVersion)
		{
			if (!string.Equals(before.Name, after.Name, StringComparison.OrdinalIgnoreCase) ||
				!string.Equals(before.Publisher, after.Publisher, StringComparison.OrdinalIgnoreCase) ||
				!string.Equals(before.ResourceId, after.ResourceId, StringComparison.OrdinalIgnoreCase) ||
				before.Architecture != after.Architecture || after.Version != expectedVersion)
			{
				throw new InvalidDataException("The rebuilt package identity changed outside the selected version.");
			}
		}

		internal void CompareVersionOutput(NativePackage other, string? innerName, ulong version)
		{
			if (!bundle)
			{
				CompareVersionPackage(other, version);
				return;
			}

			CompareVersionIdentity(ReadVersionIdentity(), other.ReadVersionIdentity(), innerName is null ? version : ReadVersionIdentity().Version);

			if (!string.Equals(HashMethod(), other.HashMethod(), StringComparison.OrdinalIgnoreCase))
			{
				throw new InvalidDataException("The bundle hash method changed.");
			}

			if (innerName is not null)
			{
				CompareVersionIdentity(ReadBundleVersionIdentity(innerName), other.ReadBundleVersionIdentity(innerName), version);
			}
			Dictionary<string, bool> expected = VersionBundleFlags();
			Dictionary<string, bool> actual = other.VersionBundleFlags();
			if (expected.Count != actual.Count)
			{
				throw new InvalidDataException("Bundle package membership changed.");
			}
			Dictionary<string, string> beforeMetadata = BundleManifestMetadata();
			Dictionary<string, string> afterMetadata = other.BundleManifestMetadata();
			if (beforeMetadata.Count != afterMetadata.Count)
			{
				throw new InvalidDataException("Bundle manifest membership changed.");
			}
			foreach (KeyValuePair<string, bool> item in expected)
			{
				if (!actual.TryGetValue(item.Key, out bool flag) || flag != item.Value)
				{
					throw new InvalidDataException($"Bundle applicability changed: {item.Key}");
				}

				bool selected = innerName is not null && string.Equals(item.Key, innerName, StringComparison.OrdinalIgnoreCase);
				if (!beforeMetadata.TryGetValue(item.Key, out string? before) || !afterMetadata.TryGetValue(item.Key, out string? after))
				{
					throw new InvalidDataException("Bundle manifest membership changed.");
				}
				if (selected)
				{
					// The first field is the full identity, whose version is intentionally
					// different. Type and all resource qualifiers must still match exactly.
					int beforeSeparator = before.IndexOf('|');
					int afterSeparator = after.IndexOf('|');
					if (beforeSeparator < 0 || afterSeparator < 0 || !before.AsSpan(beforeSeparator).SequenceEqual(after.AsSpan(afterSeparator)))
					{
						throw new InvalidDataException($"Bundle resource metadata changed: {item.Key}");
					}
				}
				else if (!before.AsSpan().SequenceEqual(after.AsSpan()))
				{
					throw new InvalidDataException($"Unselected bundle manifest entry changed: {item.Key}");
				}
				IntPtr left = GetFile(item.Key);
				IntPtr right = IntPtr.Zero;
				IntPtr leftStream = IntPtr.Zero;
				IntPtr rightStream = IntPtr.Zero;
				try
				{
					right = other.GetFile(item.Key);
					if (!selected)
					{
						CompareFiles(left, right, item.Key);
					}
					else
					{
						leftStream = GetPointer(left, 7);
						rightStream = GetPointer(right, 7);
						CompareVersionInnerStreams(leftStream, rightStream, version);
					}
				}
				finally
				{
					Release(rightStream);
					Release(leftStream);
					Release(right);
					Release(left);
				}
			}
		}

		/// <summary>
		/// Own both readers in a short, loop-free scope. The caller retains ownership
		/// of the input streams and releases them only after this method returns.
		/// </summary>
		private static void CompareVersionInnerStreams(IntPtr leftStream, IntPtr rightStream, ulong version)
		{
			// Separate acquisition scopes dispose the first reader if the second constructor fails.
			using NativePackage originalInner = new(leftStream, false);
			using NativePackage changedInner = new(rightStream, false);
			if (changedInner.HasSignature())
			{
				throw new InvalidDataException("The edited inner package still has a signature.");
			}
			changedInner.ValidateBlockMap();
			originalInner.CompareVersionPackage(changedInner, version);
		}

		private void CompareVersionPackage(NativePackage other, ulong version)
		{
			CompareVersionIdentity(ReadVersionIdentity(), other.ReadVersionIdentity(), version);

			if (!string.Equals(HashMethod(), other.HashMethod(), StringComparison.OrdinalIgnoreCase))
			{
				throw new InvalidDataException("The package hash method changed.");
			}

			HashSet<string> expected = PayloadNames();
			if (!expected.SetEquals(other.PayloadNames()))
			{
				throw new InvalidDataException("The edited package payload set changed.");
			}
			foreach (string name in expected)
			{
				IntPtr left = GetFile(name);
				IntPtr right = IntPtr.Zero;
				try
				{
					right = other.GetFile(name);
					CompareFiles(left, right, name);
				}
				finally
				{
					Release(right);
					Release(left);
				}
			}
			CompareFootprint(other, 4, required: false);
			IntPtr first = GetFile("AppxManifest.xml");
			IntPtr second = IntPtr.Zero;
			IntPtr firstStream = IntPtr.Zero;
			IntPtr secondStream = IntPtr.Zero;
			try
			{
				second = other.GetFile("AppxManifest.xml");
				firstStream = GetPointer(first, 7);
				secondStream = GetPointer(second, 7);
				using NativeManifestDocument before = new(firstStream);
				using NativeManifestDocument after = new(secondStream);

				// Compare native DOM serializations after restoring only the original
				// Version value in the comparison document. No other edit is tolerated.
				after.SetVersion(before.VersionText());
				if (!before.RootXml().AsSpan().SequenceEqual(after.RootXml().AsSpan()))
				{
					throw new InvalidDataException("The package manifest changed outside Identity.Version.");
				}
			}
			finally
			{
				Release(secondStream);
				Release(firstStream);
				Release(second);
				Release(first);
			}
		}

		/// <summary>
		/// Windows MSXML 6 DOM, through its native dual-interface vtables. The first
		/// seven slots are IUnknown/IDispatch. VARIANT is the existing
		/// 24-byte native union on both x64 and ARM64; BSTRs are owned explicitly.
		/// </summary>
		internal sealed partial class NativeManifestDocument : IDisposable
		{
			private IntPtr document;
			private IntPtr root;
			private IntPtr identity;

			internal NativeManifestDocument(IntPtr stream)
			{
				if (sizeof(VARIANT) != 24 || sizeof(APPX_PACKAGE_SETTINGS) != 16) { throw new PlatformNotSupportedException("Unexpected native COM structure layout."); }
				try
				{
					Guid clsid = new("88d96a05-f192-11d4-a65f-0040963251e5");
					Guid iid = new("2933BF95-7B36-11D2-B20E-00C04F983E60");
					Marshal.ThrowExceptionForHR(NativeMethods.CoCreateInstance(in clsid, IntPtr.Zero, 1, in iid, out document));
					SetBoolean(63, 0); // put_async: synchronous stream parsing.
					SetBoolean(68, 0); // put_validateOnParse: native package writer validates.
					SetBoolean(70, 0); // put_resolveExternals: never resolve external content.
					SetBoolean(72, -1); // put_preserveWhiteSpace.
					SetProperty("ProhibitDTD", new VARIANT { vt = 11, boolVal = -1 });
					SetProperty("MaxXMLSize", new VARIANT { vt = 3, lVal = 4096 }); // 4096 blocks of 1024 characters.
					SeekStart(stream);

					// Borrow the IStream pointer; clearing this VARIANT would release a
					// reference owned by the caller, so it is intentionally not cleared.
					VARIANT input = new() { vt = 13, punkVal = stream };
					short nativeLoaded = 0;
					int hr = ((delegate* unmanaged[Stdcall]<IntPtr, VARIANT, short*, int>)Slot(document, 58))(document, input, &nativeLoaded);
					Marshal.ThrowExceptionForHR(hr);
					if (Unsafe.Read<short>(&nativeLoaded) is 0)
					{
						IntPtr error = GetPointer(document, 60);
						try
						{
							throw new InvalidDataException($"Native manifest parsing failed: {ReadBstr(error, 9)}");
						}
						finally
						{
							Release(error);
						}
					}
					root = GetPointer(document, 45);
					string ns = ReadBstr(root, 39);
					if (!string.Equals(ns, "http://schemas.microsoft.com/appx/manifest/foundation/windows10", StringComparison.OrdinalIgnoreCase) &&
						!string.Equals(ns, "http://schemas.microsoft.com/appx/2010/manifest", StringComparison.OrdinalIgnoreCase))
					{
						throw new NotSupportedException("The package manifest uses an unsupported foundation namespace.");
					}
					IntPtr xpath = AllocateBstr("/*[local-name()='Package']/*[local-name()='Identity' and namespace-uri()=namespace-uri(..)]");
					IntPtr nodes = IntPtr.Zero;
					IntPtr node = IntPtr.Zero;
					try
					{
						Marshal.ThrowExceptionForHR(((delegate* unmanaged[Stdcall]<IntPtr, IntPtr, IntPtr*, int>)Slot(document, 36))(document, xpath, &nodes));

						if (nodes == IntPtr.Zero)
						{
							throw new InvalidDataException("The native manifest has no Identity node.");
						}

						int nativeCount = 0;
						Marshal.ThrowExceptionForHR(((delegate* unmanaged[Stdcall]<IntPtr, int*, int>)Slot(nodes, 8))(nodes, &nativeCount));
						if (Unsafe.Read<int>(&nativeCount) != 1)
						{
							throw new InvalidDataException("The native manifest must have exactly one foundation Identity node.");
						}
						Marshal.ThrowExceptionForHR(((delegate* unmanaged[Stdcall]<IntPtr, int, IntPtr*, int>)Slot(nodes, 7))(nodes, 0, &node));
						identity = Query(node, new("2933BF86-7B36-11D2-B20E-00C04F983E60"));
					}
					finally
					{
						Release(node);
						Release(nodes);
						NativeMethods.SysFreeString(xpath);
					}
				}
				catch
				{
					Dispose();
					throw;
				}
			}

			private void SetBoolean(int slot, short value) =>
				Marshal.ThrowExceptionForHR(((delegate* unmanaged[Stdcall]<IntPtr, short, int>)Slot(document, slot))(document, value));

			private void SetProperty(string name, VARIANT value)
			{
				IntPtr property = AllocateBstr(name);
				try
				{
					Marshal.ThrowExceptionForHR(((delegate* unmanaged[Stdcall]<IntPtr, IntPtr, VARIANT, int>)Slot(document, 80))(document, property, value));
				}
				finally
				{
					NativeMethods.SysFreeString(property);
				}
			}

			internal void SetVersion(string version)
			{
				IntPtr name = AllocateBstr("Version");
				IntPtr text = IntPtr.Zero;
				try
				{
					text = AllocateBstr(version);
					VARIANT value = new() { vt = 8, bstrVal = text };
					Marshal.ThrowExceptionForHR(((delegate* unmanaged[Stdcall]<IntPtr, IntPtr, VARIANT, int>)Slot(identity, 45))(identity, name, value));
				}
				finally
				{
					NativeMethods.SysFreeString(text);
					NativeMethods.SysFreeString(name);
				}
			}

			internal string VersionText()
			{
				IntPtr name = AllocateBstr("Version");
				VARIANT value = default;
				try
				{
					Marshal.ThrowExceptionForHR(((delegate* unmanaged[Stdcall]<IntPtr, IntPtr, VARIANT*, int>)Slot(identity, 44))(identity, name, &value));
					if (value.vt != 8)
					{
						throw new InvalidDataException("The native manifest Version attribute is missing.");
					}
					return Marshal.PtrToStringBSTR(value.bstrVal);
				}
				finally
				{
					_ = NativeMethods.VariantClear(ref value);
					NativeMethods.SysFreeString(name);
				}
			}

			internal string RootXml() => ReadBstr(root, 34);

			internal void Save(IntPtr stream) =>
				Marshal.ThrowExceptionForHR(((delegate* unmanaged[Stdcall]<IntPtr, VARIANT, int>)Slot(document, 66))(document, new VARIANT { vt = 13, punkVal = stream }));

			private static IntPtr AllocateBstr(string text)
			{
				fixed (char* source = text)
				{
					IntPtr result = NativeMethods.SysAllocStringLen(source, (uint)text.Length);
					return result != IntPtr.Zero ? result : throw new InvalidOperationException("Could not allocate a native BSTR.");
				}
			}

			private static string ReadBstr(IntPtr instance, int slot)
			{
				IntPtr text = IntPtr.Zero;
				try
				{
					Marshal.ThrowExceptionForHR(((delegate* unmanaged[Stdcall]<IntPtr, IntPtr*, int>)Slot(instance, slot))(instance, &text));
					return text == IntPtr.Zero ? string.Empty : Marshal.PtrToStringBSTR(text);
				}
				finally
				{
					NativeMethods.SysFreeString(text);
				}
			}

			public void Dispose()
			{
				Release(identity); identity = IntPtr.Zero;
				Release(root); root = IntPtr.Zero;
				Release(document); document = IntPtr.Zero;
			}
		}
	}

	private static unsafe void RemoveUsingSip(string path)
	{
		if (sizeof(SIP_SUBJECTINFO) != 128)
		{
			throw new PlatformNotSupportedException("Unexpected native SIP structure layout.");
		}
		if (!NativeMethods.CryptSIPRetrieveSubjectGuid(path, IntPtr.Zero, out Guid subjectGuid))
		{
			int error = Marshal.GetLastPInvokeError();
			throw new Win32Exception(error, $"Windows could not identify the package SIP provider (0x{unchecked((uint)error):X8}).");
		}
		fixed (char* filename = path)
		{
			SIP_SUBJECTINFO subject = default;
			subject.cbSize = (uint)sizeof(SIP_SUBJECTINFO);
			subject.pgSubjectType = &subjectGuid;
			subject.hFile = new IntPtr(-1);
			subject.pwsFileName = filename;
			subject.dwEncodingType = 0x00010001; // X509_ASN_ENCODING | PKCS_7_ASN_ENCODING.
			uint encoding = 0;
			uint nativeSize = 0;
			int result = NativeMethods.CryptSIPGetSignedDataMsg(&subject, &encoding, 0, &nativeSize, null);
			uint size = Unsafe.Read<uint>(&nativeSize);
			if (result is 0)
			{
				int error = Marshal.GetLastPInvokeError();
				// A size query may report the required size with ERROR_INSUFFICIENT_BUFFER.
				if (error != 122 || size is 0)
				{
					throw new Win32Exception(error, $"The SIP provider could not read the existing package signature (0x{unchecked((uint)error):X8}).");
				}
			}
			if (size is 0)
			{
				throw new InvalidDataException("The SIP provider reported an empty signature for a signed package.");
			}
			if (NativeMethods.CryptSIPRemoveSignedDataMsg(&subject, 0) is 0)
			{
				int error = Marshal.GetLastPInvokeError();
				throw new Win32Exception(error, $"Native SIP signature removal failed or is unsupported by this provider (0x{unchecked((uint)error):X8}). No output was published.");
			}
		}
	}
}

/// <summary>
/// Data-only explorer item. XAML owns all row visuals; no UIElement is stored in
/// the hierarchy or shared between presenters.
/// </summary>
internal sealed partial class PackageExplorerItem : INotifyPropertyChanged
{
	internal PackageExplorerItem(string name, string sizeText, string toolTip, bool isDirectory, int childCapacity)
	{
		Name = name;
		SizeText = sizeText;
		ToolTip = toolTip;
		IsDirectory = isDirectory;
		string extension = Path.GetExtension(name);
		// Actual folders keep their folder icon, including names ending in a package extension.
		IsPackage = !isDirectory &&
			(string.Equals(extension, ".msix", StringComparison.OrdinalIgnoreCase) ||
			 string.Equals(extension, ".msixbundle", StringComparison.OrdinalIgnoreCase) ||
			 string.Equals(extension, ".appx", StringComparison.OrdinalIgnoreCase) ||
			 string.Equals(extension, ".appxbundle", StringComparison.OrdinalIgnoreCase));
		Children = new List<PackageExplorerItem>(childCapacity);
	}

	public string Name { get; }
	public string SizeText { get; }
	public string ToolTip { get; }
	public bool IsDirectory { get; }
	public bool IsPackage { get; }
	public List<PackageExplorerItem> Children { get; }
	public string AccessibleName => string.IsNullOrEmpty(SizeText) ? Name : $"{Name}, {SizeText}";
	public Visibility FolderIconVisibility => IsDirectory ? Visibility.Visible : Visibility.Collapsed;
	public Visibility FileIconVisibility => !IsDirectory && !IsPackage ? Visibility.Visible : Visibility.Collapsed;
	public Visibility PackageIconVisibility => IsPackage ? Visibility.Visible : Visibility.Collapsed;
	public Visibility SizeVisibility => string.IsNullOrEmpty(SizeText) ? Visibility.Collapsed : Visibility.Visible;

	public bool IsExpanded
	{
		get; set
		{
			if (field != value)
			{
				field = value;
				PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsExpanded)));
			}
		}
	}

	public event PropertyChangedEventHandler? PropertyChanged;
}

/// <summary>
/// Native-reader identity data.
/// </summary>
internal sealed class PackageVersionRecord(string name, string? innerName, ulong version, bool bundle)
{
	internal string Name { get; } = name;
	internal string? InnerName { get; } = innerName;
	internal ulong Version { get; } = version;
	internal bool IsBundle { get; } = bundle;
}

/// <summary>
/// Independent editable row. Only its Save callback submits its draft.
/// </summary>
internal sealed partial class PackageVersionItem : INotifyPropertyChanged
{
	private readonly Func<PackageVersionItem, Task> save;

	internal PackageVersionItem(PackageVersionRecord record, Func<PackageVersionItem, Task> saveCallback)
	{
		DisplayName = record.InnerName is null ? (record.IsBundle ? "Bundle version" : "Package version") : record.Name;
		InnerName = record.InnerName;
		OriginalVersion = record.Version;
		VersionText = PackageSignatureRemover.FormatPackageVersion(record.Version);
		save = saveCallback;
	}

	public string DisplayName { get; }
	internal string? InnerName { get; }
	internal ulong OriginalVersion { get; private set; }
	public string VersionText
	{
		get; set
		{
			if (!string.Equals(field, value, StringComparison.OrdinalIgnoreCase))
			{
				field = value;
				PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(VersionText)));
			}
		}
	} = string.Empty;

	/// <summary>
	/// Bound directly to the XAML Save button.
	/// </summary>
	internal async void Save_Click() => await save(this);

	internal void AcceptVersion(ulong version)
	{
		OriginalVersion = version;
		VersionText = PackageSignatureRemover.FormatPackageVersion(version);
	}

	public event PropertyChangedEventHandler? PropertyChanged;
}
