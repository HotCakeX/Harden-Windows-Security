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
using System.IO.Compression;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

#pragma warning disable CA1303, CS0162, CA1819

// https://learn.microsoft.com/windows/uwp/monetize/manage-app-submissions#listing-object
// https://learn.microsoft.com/windows/uwp/monetize/update-an-app-submission
// https://learn.microsoft.com/windows/apps/publish/msstore-dev-cli/commands
// https://learn.microsoft.com/windows/apps/publish/partner-center/associate-existing-azure-ad-tenant-with-partner-center-account
// https://learn.microsoft.com/partner-center/marketplace-offers/azure-app-apis

namespace PartnerCenter;

[JsonSerializable(typeof(ApplicationPackage))]
[JsonSerializable(typeof(ApplicationPackage[]))]
[JsonSourceGenerationOptions(WriteIndented = false)]
internal sealed partial class ApplicationPackageJsonContext : JsonSerializerContext
{
}

internal sealed class ApplicationPackage
{
	[JsonInclude]
	[JsonPropertyName("fileName")]
	internal string FileName { get; init; } = string.Empty;

	[JsonInclude]
	[JsonPropertyName("fileStatus")]
	internal string FileStatus { get; init; } = "PendingUpload";

	[JsonInclude]
	[JsonPropertyName("minimumDirectXVersion")]
	internal string MinimumDirectXVersion { get; init; } = "None";

	[JsonInclude]
	[JsonPropertyName("minimumSystemRam")]
	internal string MinimumSystemRam { get; init; } = "None";

	[JsonInclude]
	[JsonPropertyName("id")]
	internal string? Id { get; init; }

	[JsonInclude]
	[JsonPropertyName("version")]
	internal string? Version { get; init; }

	[JsonInclude]
	[JsonPropertyName("architecture")]
	internal string? Architecture { get; init; }

	[JsonInclude]
	[JsonPropertyName("targetPlatform")]
	internal string? TargetPlatform { get; init; }

	[JsonInclude]
	[JsonPropertyName("languages")]
	internal string[]? Languages { get; init; }

	[JsonInclude]
	[JsonPropertyName("capabilities")]
	internal string[]? Capabilities { get; init; }

	[JsonInclude]
	[JsonPropertyName("targetDeviceFamilies")]
	internal string[]? TargetDeviceFamilies { get; init; }

	/// <summary>
	/// Validates that the JSON object contains exactly the expected properties.
	/// Throws an exception if there are missing or extra properties.
	/// </summary>
	internal static void ValidateJsonStructure(JsonElement jsonElement)
	{
		// Defining the expected properties
		HashSet<string> expectedProperties = new(StringComparer.Ordinal)
		{
			"fileName",
			"fileStatus",
			"minimumDirectXVersion",
			"minimumSystemRam",
			"id",
			"version",
			"architecture",
			"targetPlatform",
			"languages",
			"capabilities",
			"targetDeviceFamilies"
		};

		// Get actual properties from JSON
		HashSet<string> actualProperties = new();
		foreach (JsonProperty property in jsonElement.EnumerateObject())
		{
			_ = actualProperties.Add(property.Name);
		}

		// Check for missing properties
		HashSet<string> missingProperties = new(expectedProperties);
		missingProperties.ExceptWith(actualProperties);

		// Check for extra properties
		HashSet<string> extraProperties = new(actualProperties);
		extraProperties.ExceptWith(expectedProperties);

		// TargetPlatform property disappears from all packages once we mark the oldest package for deletion!
		// So commenting this check because it would just always throw and wouldn't let us continue.

		// Throw exceptions if there are discrepancies, shouldn't continue.
		// if (missingProperties.Count > 0)
		// {
		//	throw new InvalidOperationException($"Missing required properties in ApplicationPackage JSON: {string.Join(", ", missingProperties)}");
		// }

		// Throwing on extra properties is good to keep because that means we need to update the JSON class for source-generated (de)serialization.
		if (extraProperties.Count > 0)
		{
			throw new InvalidOperationException($"Unexpected extra properties in ApplicationPackage JSON: {string.Join(", ", extraProperties)}. This may indicate new features have been added to the API that are not supported by this version of the code.");
		}
	}

	/// <summary>
	/// An ApplicationPackage from JsonElement with validation.
	/// </summary>
	internal static ApplicationPackage FromJsonElement(JsonElement jsonElement)
	{
		ValidateJsonStructure(jsonElement);

		ApplicationPackage? package = JsonSerializer.Deserialize(jsonElement.GetRawText(), ApplicationPackageJsonContext.Default.ApplicationPackage);
		return package ?? throw new InvalidOperationException("Failed to deserialize ApplicationPackage");
	}
}

internal static class Helpers
{
	private const int MaxRetries = 7;
	private const int BaseDelayMs = 1000;
	private const int StandardTimeoutSeconds = 200;
	private const int ExtendedTimeoutSeconds = 300;
	private const int PackageUploadTimeoutSeconds = 1800; // 30 minutes
	private const int DeleteDelayMinutes = 3;
	private const int CommitStatusTimeoutMinutes = 30; // timeout for commit status checking
	private const int CommitStatusCheckIntervalSeconds = 10; // Check every 10 seconds
	private const int MaxApplicationPackages = 30; // Maximum number of application packages allowed in Partner Center

	// Set to false when in production
	private const bool WriteSensitiveLogsEnabled = false;

	internal static void WriteSensitiveLogs(string msg)
	{
		if (!WriteSensitiveLogsEnabled)
			return;

#if DEBUG
		Console.WriteLine(msg);
#endif
	}

	/// <summary>
	/// Executes a network request with retry logic for resilience.
	/// </summary>
	private static async Task<T> ExecuteWithRetryAsync<T>(Func<Task<T>> networkRequest, string operationName)
	{
		for (int attempt = 1; attempt <= MaxRetries; attempt++)
		{
			try
			{
				Console.WriteLine($"Attempt {attempt} of {MaxRetries} for {operationName}...");
				return await networkRequest();
			}
			catch (HttpRequestException ex) when (attempt < MaxRetries)
			{
				Console.WriteLine($"Network error on attempt {attempt} for {operationName}.");
				WriteSensitiveLogs($"Error message: {ex.Message}");
				Console.WriteLine($"Retrying in {BaseDelayMs * attempt} ms...");
				await Task.Delay(BaseDelayMs * attempt);
			}
			catch (TaskCanceledException ex) when (attempt < MaxRetries)
			{
				Console.WriteLine($"Request timeout on attempt {attempt} for {operationName}.");
				WriteSensitiveLogs($"Error message: {ex.Message}");
				Console.WriteLine($"Retrying in {BaseDelayMs * attempt} ms...");
				await Task.Delay(BaseDelayMs * attempt);
			}
		}

		throw new InvalidOperationException($"Failed to execute {operationName} after {MaxRetries} attempts");
	}

	internal static async Task<string> GetClientCredentialAccessToken(
		string tokenEndpoint,
		string clientId,
		string clientSecret,
		string scope)
	{
		return await ExecuteWithRetryAsync(async () =>
		{
			using HttpClient client = new()
			{
				Timeout = TimeSpan.FromSeconds(StandardTimeoutSeconds)
			};
			using HttpRequestMessage request = new(
					HttpMethod.Post,
					tokenEndpoint);

			string form =
				"grant_type=client_credentials"
				+ $"&client_id={clientId}"
				+ $"&client_secret={clientSecret}"
				+ $"&resource={scope}";

			request.Content = new StringContent(form, Encoding.UTF8,
				"application/x-www-form-urlencoded");

			using HttpResponseMessage response = await client.SendAsync(request);
			string responseContent = await response.Content.ReadAsStringAsync();

			if (response.IsSuccessStatusCode)
			{
				using JsonDocument doc = JsonDocument.Parse(responseContent);
				JsonElement root = doc.RootElement;

				string accessToken = root
					.GetProperty("access_token")
					.GetString()!;

				Console.WriteLine("Access token obtained successfully!");
				return accessToken;
			}
			else
			{
				WriteSensitiveLogs($"Response Content: {responseContent}");
				throw new HttpRequestException($"Access token request failed with status {response.StatusCode}.");
			}
		}, "get access token");
	}

	/// <summary>
	/// Retrieves the application data and returns the pending submission ID if it exists.
	/// </summary>
	internal static async Task<string?> GetPendingSubmissionIdAsync(
		string accessToken,
		string applicationId)
	{
		return await ExecuteWithRetryAsync(async () =>
		{
			using HttpClient client = new()
			{
				Timeout = TimeSpan.FromSeconds(StandardTimeoutSeconds)
			};
			client.DefaultRequestHeaders.Authorization =
				new AuthenticationHeaderValue("Bearer", accessToken);

			Uri requestUrl = new($"https://manage.devcenter.microsoft.com/v1.0/my/applications/{applicationId}");

			WriteSensitiveLogs($"Making request to: {requestUrl}");

			using HttpResponseMessage response = await client.GetAsync(requestUrl);

			Console.WriteLine($"Response status: {response.StatusCode}");
			string responseContent = await response.Content.ReadAsStringAsync();
			WriteSensitiveLogs($"Response content: {responseContent}");

			if (response.IsSuccessStatusCode)
			{
				using JsonDocument doc = JsonDocument.Parse(responseContent);
				JsonElement root = doc.RootElement;

				// Check if pendingApplicationSubmission exists and has an id
				if (!root.TryGetProperty("pendingApplicationSubmission", out JsonElement pendingSubmission))
				{
					return null; // No pending submission found
				}

				if (!pendingSubmission.TryGetProperty("id", out JsonElement idElement))
				{
					return null; // Pending submission exists but has no ID
				}

				string? submissionId = idElement.GetString();
				Console.WriteLine("Pending submission ID retrieved successfully!");
				return submissionId;
			}
			else
			{
				WriteSensitiveLogs($"Response Content: {responseContent}");
				throw new HttpRequestException($"Get pending submission ID request failed with status {response.StatusCode}.");
			}
		}, "get pending submission ID");
	}

	/// <summary>
	/// Deletes the existing pending submission for the application.
	/// </summary>
	internal static async Task DeletePendingSubmissionAsync(
		string accessToken,
		string applicationId,
		string submissionId)
	{
		_ = await ExecuteWithRetryAsync(async () =>
		{
			using HttpClient client = new()
			{
				Timeout = TimeSpan.FromSeconds(StandardTimeoutSeconds)
			};
			client.DefaultRequestHeaders.Authorization =
				new AuthenticationHeaderValue("Bearer", accessToken);

			Uri requestUrl = new($"https://manage.devcenter.microsoft.com/v1.0/my/applications/{applicationId}/submissions/{submissionId}");

			WriteSensitiveLogs($"Deleting submission at: {requestUrl}");

			using HttpResponseMessage response = await client.DeleteAsync(requestUrl);

			Console.WriteLine($"Delete response status: {response.StatusCode}");
			string responseContent = await response.Content.ReadAsStringAsync();
			WriteSensitiveLogs($"Delete response content: {responseContent}");

			if (response.IsSuccessStatusCode)
			{
				Console.WriteLine("Submission deleted successfully!");
			}
			else
			{
				WriteSensitiveLogs($"Response Content: {responseContent}");
				throw new HttpRequestException($"Delete submission request failed with status {response.StatusCode}.");
			}

			return 0; // Dummy value to satisfy the method sig.

		}, "delete pending submission");

		Console.WriteLine($"Waiting {DeleteDelayMinutes} minutes...");

		// Waiting before immediately creating a new submission otherwise we'd get "Conflict" error.
		await Task.Delay(TimeSpan.FromMinutes(DeleteDelayMinutes));
	}

	/// <summary>
	/// Creates a new draft submission for the application.
	/// </summary>
	internal static async Task<string> CreateDraftSubmissionAsync(
		string accessToken,
		string applicationId)
	{
		return await ExecuteWithRetryAsync(async () =>
		{
			using HttpClient client = new()
			{
				Timeout = TimeSpan.FromSeconds(StandardTimeoutSeconds)
			};
			client.DefaultRequestHeaders.Authorization =
				new AuthenticationHeaderValue("Bearer", accessToken);

			Uri requestUrl = new($"https://manage.devcenter.microsoft.com/v1.0/my/applications/{applicationId}/submissions");

			WriteSensitiveLogs($"Creating new draft submission at: {requestUrl}");

			using HttpResponseMessage response = await client.PostAsync(requestUrl, null);

			Console.WriteLine($"Create response status: {response.StatusCode}");
			string responseContent = await response.Content.ReadAsStringAsync();
			WriteSensitiveLogs($"Create response content: {responseContent}");

			if (response.IsSuccessStatusCode)
			{
				using JsonDocument doc = JsonDocument.Parse(responseContent);
				JsonElement root = doc.RootElement;

				string submissionId = root
					.GetProperty("id")
					.GetString()!;

				Console.WriteLine("Draft submission created successfully!");
				return submissionId;
			}
			else
			{
				WriteSensitiveLogs($"Response Content: {responseContent}");
				throw new HttpRequestException($"Create draft submission request failed with status {response.StatusCode}.");
			}
		}, "create draft submission");
	}

	/// <summary>
	/// Gets or creates a pending submission ID for the application.
	/// </summary>
	internal static async Task<string> GetOrCreatePendingSubmissionIdAsync(
		string accessToken,
		string applicationId,
		bool deleteExistingDraft = true)
	{
		// First, try to get existing pending submission
		string? existingSubmissionId = await GetPendingSubmissionIdAsync(accessToken, applicationId);

		if (existingSubmissionId != null)
		{
			WriteSensitiveLogs($"Found existing pending submission: {existingSubmissionId}");

			if (deleteExistingDraft)
			{
				Console.WriteLine("Deleting existing pending submission to create a new one...");
				await DeletePendingSubmissionAsync(accessToken, applicationId, existingSubmissionId);
				Console.WriteLine("Existing submission deleted successfully.");
			}
			else
			{
				Console.WriteLine("Using existing pending submission (not deleting).");
				return existingSubmissionId;
			}
		}
		else
		{
			Console.WriteLine("No existing pending submission found.");
		}

		// Create new draft submission (only if we deleted the existing one or there was none)
		if (deleteExistingDraft || existingSubmissionId is null)
		{
			Console.WriteLine("Creating new draft submission...");
			string newSubmissionId = await CreateDraftSubmissionAsync(accessToken, applicationId);
			WriteSensitiveLogs($"New draft submission created with ID: {newSubmissionId}");
			return newSubmissionId;
		}

		// This should not be reached, but return the existing ID as fallback
		return existingSubmissionId;
	}

	/// <summary>
	/// Retrieves the full JSON payload of the specified submission.
	/// </summary>
	internal static async Task<string> GetSubmissionConfigAsync(
		string accessToken,
		string applicationId,
		string submissionId)
	{
		return await ExecuteWithRetryAsync(async () =>
		{
			using HttpClient client = new()
			{
				Timeout = TimeSpan.FromSeconds(StandardTimeoutSeconds)
			};
			client.DefaultRequestHeaders.Authorization =
				new AuthenticationHeaderValue("Bearer", accessToken);

			Uri requestUrl = new($"https://manage.devcenter.microsoft.com/v1.0/my/applications/{applicationId}/submissions/{submissionId}");

			using HttpResponseMessage response = await client.GetAsync(requestUrl);

			if (response.IsSuccessStatusCode)
			{
				string responseContent = await response.Content.ReadAsStringAsync();
				Console.WriteLine("Submission config retrieved successfully!");
				return responseContent;
			}
			else
			{
				string responseContent = await response.Content.ReadAsStringAsync();
				WriteSensitiveLogs($"Response Content: {responseContent}");
				throw new HttpRequestException($"Get submission config request failed with status {response.StatusCode}.");
			}
		}, "get submission config");
	}

	/// <summary>
	/// Waits for submission commit processing to complete by checking the submission status periodically.
	/// Follows the Microsoft sample pattern of waiting for commit status changes.
	/// </summary>
	internal static async Task WaitForCommitProcessingAsync(
		string accessToken,
		string applicationId,
		string submissionId)
	{
		Console.WriteLine("Waiting for submission commit processing to complete...");

		DateTime startTime = DateTime.UtcNow;
		DateTime timeoutTime = startTime.AddMinutes(CommitStatusTimeoutMinutes);

		string? submissionStatus = null;

		do
		{
			if (DateTime.UtcNow >= timeoutTime)
			{
				TimeSpan totalElapsed = DateTime.UtcNow - startTime;
				throw new TimeoutException($"Commit processing timeout after {totalElapsed.TotalMinutes:F1} minutes. Status was: {submissionStatus}");
			}

			await Task.Delay(TimeSpan.FromSeconds(CommitStatusCheckIntervalSeconds));

			try
			{
				string submissionJson = await GetSubmissionConfigAsync(accessToken, applicationId, submissionId);
				using JsonDocument doc = JsonDocument.Parse(submissionJson);
				JsonElement root = doc.RootElement;

				if (root.TryGetProperty("status", out JsonElement statusElement))
				{
					submissionStatus = statusElement.GetString();
					Console.WriteLine($"Current status: {submissionStatus}");
				}
				else
				{
					Console.WriteLine("No status found in submission response");
					submissionStatus = "Unknown";
				}
			}
			catch (Exception ex)
			{
				WriteSensitiveLogs($"Error during commit status check: {ex.Message}");
				Console.WriteLine($"Retrying in {CommitStatusCheckIntervalSeconds} seconds...");
			}
		}
		while (string.Equals(submissionStatus, "CommitStarted", StringComparison.OrdinalIgnoreCase));

		if (string.Equals(submissionStatus, "CommitFailed", StringComparison.OrdinalIgnoreCase))
		{
			Console.WriteLine("Submission has failed. Please check the submission details for errors.");

			// Get detailed error information
			try
			{
				await CheckSubmissionStatusAsync(accessToken, applicationId, submissionId);
			}
			catch (Exception ex)
			{
				WriteSensitiveLogs($"Failed to get detailed error information: {ex.Message}");
			}

			throw new InvalidOperationException("Submission commit failed");
		}
		else
		{
			Console.WriteLine($"Submission commit completed successfully! Final status: {submissionStatus}");
		}
	}

	/// <summary>
	/// Checks the status of a submission and displays detailed information.
	/// </summary>
	internal static async Task CheckSubmissionStatusAsync(
		string accessToken,
		string applicationId,
		string submissionId)
	{
		WriteSensitiveLogs($"Checking status for submission ID: {submissionId}");

		string submissionJson = await GetSubmissionConfigAsync(accessToken, applicationId, submissionId);

		using JsonDocument doc = JsonDocument.Parse(submissionJson);
		JsonElement root = doc.RootElement;

		if (root.TryGetProperty("status", out JsonElement statusElement))
		{
			string? status = statusElement.GetString();
			Console.WriteLine($"Submission Status: {status}");
		}
		else
		{
			Console.WriteLine("No status information found in submission.");
		}

		if (root.TryGetProperty("statusDetails", out JsonElement statusDetailsElement))
		{
			Console.WriteLine("\nStatus Details:");

			if (statusDetailsElement.TryGetProperty("errors", out JsonElement errorsElement) && errorsElement.GetArrayLength() > 0)
			{
				Console.WriteLine("Errors:");
				foreach (JsonElement error in errorsElement.EnumerateArray())
				{
					if (error.TryGetProperty("code", out JsonElement codeElement) &&
						error.TryGetProperty("details", out JsonElement detailsElement))
					{
						WriteSensitiveLogs($"  • {codeElement.GetString()}: {detailsElement.GetString()}");
					}
				}
			}

			if (statusDetailsElement.TryGetProperty("warnings", out JsonElement warningsElement) && warningsElement.GetArrayLength() > 0)
			{
				Console.WriteLine("Warnings:");
				foreach (JsonElement warning in warningsElement.EnumerateArray())
				{
					if (warning.TryGetProperty("code", out JsonElement codeElement) &&
						warning.TryGetProperty("details", out JsonElement detailsElement))
					{
						WriteSensitiveLogs($"  • {codeElement.GetString()}: {detailsElement.GetString()}");
					}
				}
			}

			if (statusDetailsElement.TryGetProperty("certificationNotes", out JsonElement certNotesElement))
			{
				string? certNotes = certNotesElement.GetString();
				if (!string.IsNullOrEmpty(certNotes))
				{
					WriteSensitiveLogs($"Certification Notes: {certNotes}");
				}
			}
		}

		// Display submission dates if available
		if (root.TryGetProperty("targetPublishDate", out JsonElement targetPublishDateElement))
		{
			string? targetPublishDate = targetPublishDateElement.GetString();
			if (!string.IsNullOrEmpty(targetPublishDate))
			{
				WriteSensitiveLogs($"Target Publish Date: {targetPublishDate}");
			}
		}

		// Display package information
		if (root.TryGetProperty("applicationPackages", out JsonElement packagesElement) && packagesElement.GetArrayLength() > 0)
		{
			Console.WriteLine("\nApplication Packages:");
			foreach (JsonElement package in packagesElement.EnumerateArray())
			{
				if (package.TryGetProperty("fileName", out JsonElement fileNameElement) &&
					package.TryGetProperty("fileStatus", out JsonElement fileStatusElement))
				{
					string? fileName = fileNameElement.GetString();
					string? fileStatus = fileStatusElement.GetString();
					WriteSensitiveLogs($"  • {fileName} - Status: {fileStatus}");
				}
			}
		}

		Console.WriteLine("\nStatus check completed.");
	}

	/// <summary>
	/// Creates a ZIP file with the package and uploads it to Azure Blob Storage.
	/// </summary>
	internal static async Task<string> UploadPackageAsync(
		string accessToken,
		string applicationId,
		string submissionId,
		string packageFilePath)
	{
		// First get the submission to get the file upload URL
		string submissionJson = await GetSubmissionConfigAsync(accessToken, applicationId, submissionId);
		using JsonDocument doc = JsonDocument.Parse(submissionJson);
		JsonElement root = doc.RootElement;

		if (!root.TryGetProperty("fileUploadUrl", out JsonElement fileUploadUrlElement))
		{
			throw new InvalidOperationException("File upload URL not found in submission");
		}

		string fileUploadUrl = fileUploadUrlElement.GetString()!;
		string fileName = Path.GetFileName(packageFilePath);

		Console.WriteLine($"Creating ZIP archive with package: {fileName}");
		Console.WriteLine($"File size: {new FileInfo(packageFilePath).Length / (1024 * 1024)} MB");

		// Create a temporary ZIP file containing the package
		string tempZipPath = Path.GetTempFileName();
		try
		{
			using (FileStream zipStream = new(tempZipPath, FileMode.Create))
			using (ZipArchive archive = new(zipStream, ZipArchiveMode.Create))
			{
				ZipArchiveEntry entry = archive.CreateEntry(fileName);
				using Stream entryStream = await entry.OpenAsync();
				using FileStream packageStream = new(packageFilePath, FileMode.Open, FileAccess.Read);
				await packageStream.CopyToAsync(entryStream);
			}

			Console.WriteLine($"ZIP archive created: {new FileInfo(tempZipPath).Length / (1024 * 1024)} MB");

			return await ExecuteWithRetryAsync(async () =>
			{
				using HttpClient client = new()
				{
					Timeout = TimeSpan.FromSeconds(PackageUploadTimeoutSeconds)
				};

				WriteSensitiveLogs($"Uploading ZIP to: {fileUploadUrl}");

				using FileStream zipFileStream = new(tempZipPath, FileMode.Open, FileAccess.Read);
				using StreamContent content = new(zipFileStream);

				content.Headers.ContentType = new MediaTypeHeaderValue("application/zip");

				using HttpRequestMessage request = new(HttpMethod.Put, fileUploadUrl)
				{
					Content = content
				};

				request.Headers.Add("x-ms-blob-type", "BlockBlob");

				using HttpResponseMessage response = await client.SendAsync(request);

				if (response.IsSuccessStatusCode)
				{
					Console.WriteLine("ZIP archive uploaded successfully!");
					return fileName;
				}
				else
				{
					string responseContent = await response.Content.ReadAsStringAsync();
					WriteSensitiveLogs($"Upload failed. Response: {responseContent}");
					throw new HttpRequestException($"ZIP upload failed with status {response.StatusCode}.");
				}
			}, "upload ZIP archive");
		}
		finally
		{
			// Clean up temporary ZIP file
			if (File.Exists(tempZipPath))
			{
				File.Delete(tempZipPath);
			}
		}
	}

	/// <summary>
	/// Updates the submission with the uploaded package information.
	/// </summary>
	internal static async Task<string> UpdateSubmissionWithPackageAsync(
		string accessToken,
		string applicationId,
		string submissionId,
		string packageFileName)
	{
		// First, get the current submission data
		string currentSubmissionJson = await GetSubmissionConfigAsync(accessToken, applicationId, submissionId);

		JsonNode? submissionNode = JsonNode.Parse(currentSubmissionJson) ?? throw new InvalidOperationException("Failed to parse submission JSON");

		// Get existing application packages with validation
		List<ApplicationPackage> existingPackages = new();
		if (submissionNode["applicationPackages"] is JsonArray existingPackagesArray)
		{
			using JsonDocument packagesDoc = JsonDocument.Parse(existingPackagesArray.ToJsonString());
			JsonElement packagesElement = packagesDoc.RootElement;

			for (int i = 0; i < packagesElement.GetArrayLength(); i++)
			{
				JsonElement packageElement = packagesElement[i];
				try
				{
					// This will validate the structure and throw if there are missing/extra properties
					ApplicationPackage package = ApplicationPackage.FromJsonElement(packageElement);
					existingPackages.Add(package);
					WriteSensitiveLogs($"Validated existing package: {package.FileName}");
				}
				catch (InvalidOperationException ex)
				{
					Console.WriteLine($"Validation failed for existing package at index {i}.");
					WriteSensitiveLogs(ex.Message);
					throw;
				}
			}
		}

		Console.WriteLine($"Total packages before adding new one: {existingPackages.Count}");

		// Add the new package
		ApplicationPackage newPackage = new()
		{
			FileName = packageFileName,
			FileStatus = "PendingUpload",
			MinimumDirectXVersion = "None",
			MinimumSystemRam = "None"
		};

		existingPackages.Add(newPackage);

		Console.WriteLine($"Total packages after adding new one: {existingPackages.Count}");

		// Serialize the updated packages array
		string packagesJson = JsonSerializer.Serialize(existingPackages.ToArray(), ApplicationPackageJsonContext.Default.ApplicationPackageArray);

		// Parse the packages JSON as a JsonArray and update the submission
		JsonArray? updatedPackagesArray = JsonNode.Parse(packagesJson)?.AsArray();
		if (updatedPackagesArray != null)
		{
			submissionNode["applicationPackages"] = updatedPackagesArray;
		}

		// Serialize back to JSON
		string updatedJson = submissionNode.ToJsonString(new JsonSerializerOptions
		{
			WriteIndented = false,
			Encoder = System.Text.Encodings.Web.JavaScriptEncoder.Create(System.Text.Unicode.UnicodeRanges.All)
		});

		return await ExecuteWithRetryAsync(async () =>
		{
			using HttpClient client = new()
			{
				Timeout = TimeSpan.FromSeconds(ExtendedTimeoutSeconds)
			};
			client.DefaultRequestHeaders.Authorization =
				new AuthenticationHeaderValue("Bearer", accessToken);

			Uri requestUrl = new($"https://manage.devcenter.microsoft.com/v1.0/my/applications/{applicationId}/submissions/{submissionId}");

			using StringContent content = new(updatedJson, Encoding.UTF8, "application/json");
			_ = (content.Headers?.ContentType?.CharSet = "UTF-8");

			using HttpResponseMessage response = await client.PutAsync(requestUrl, content);

			Console.WriteLine($"Update submission response status: {response.StatusCode}");
			string responseContent = await response.Content.ReadAsStringAsync();

			if (response.IsSuccessStatusCode)
			{
				Console.WriteLine("Submission updated with package information successfully!");
				return responseContent;
			}
			else
			{
				WriteSensitiveLogs($"Response Content: {responseContent}");
				throw new HttpRequestException($"Update submission with package failed with status {response.StatusCode}.");
			}
		}, "update submission with package");
	}

	/// <summary>
	/// Marks the oldest active package as PendingDelete
	/// when the active (non-PendingDelete) package count has reached the configured MaxApplicationPackages limit before adding a new one.
	/// </summary>
	/// <param name="accessToken"></param>
	/// <param name="applicationId"></param>
	/// <param name="submissionId"></param>
	/// <param name="maxPackages"></param>
	/// <returns></returns>
	/// <exception cref="InvalidOperationException"></exception>
	/// <exception cref="HttpRequestException"></exception>
	internal static async Task RemoveOldestPackageIfLimitReachedAsync(
		string accessToken,
		string applicationId,
		string submissionId,
		int maxPackages)
	{
		// Get current submission to inspect packages
		string currentSubmissionJson = await GetSubmissionConfigAsync(accessToken, applicationId, submissionId);
		JsonNode? submissionNode = JsonNode.Parse(currentSubmissionJson) ?? throw new InvalidOperationException("Failed to parse submission JSON (package removal stage).");

		JsonNode? packagesNode = submissionNode["applicationPackages"];
		if (packagesNode is not JsonArray packagesArray)
		{
			// No packages array present
			return;
		}

		// Build list of (index, node) for active packages (anything not already PendingDelete)
		List<(int Index, JsonObject PackageObject)> activePackages = new(capacity: packagesArray.Count);
		for (int i = 0; i < packagesArray.Count; i++)
		{
			JsonNode? node = packagesArray[i];
			if (node is JsonObject obj)
			{
				// If fileStatus != PendingDelete (case-insensitive) treat as active
				if (!obj.TryGetPropertyValue("fileStatus", out JsonNode? statusNode))
				{
					// if missing status treat as active to avoid exceeding limit silently
					activePackages.Add((i, obj));
					continue;
				}

				string? statusValue = statusNode?.GetValue<string>();
				if (!string.Equals(statusValue, "PendingDelete", StringComparison.OrdinalIgnoreCase))
				{
					activePackages.Add((i, obj));
				}
			}
		}

		int activeCount = activePackages.Count;
		Console.WriteLine($"Active (non-PendingDelete) application packages count: {activeCount}");

		// Only proceed if we have reached or exceeded the threshold before adding a new package.
		if (activeCount < maxPackages)
		{
			return; // Nothing to do yet.
		}

		// Find the oldest active package -> lowest index among activePackages
		(int Index, JsonObject PackageObject) oldest = activePackages[0];

		// Validate before modification
		try
		{
			using JsonDocument singleDoc = JsonDocument.Parse(oldest.PackageObject.ToJsonString());
			ApplicationPackage _ = ApplicationPackage.FromJsonElement(singleDoc.RootElement);
			WriteSensitiveLogs($"Oldest active package candidate for marking PendingDelete: {oldest.PackageObject["fileName"]?.GetValue<string>() ?? "<unknown>"}");
		}
		catch (Exception ex)
		{
			WriteSensitiveLogs($"Validation of oldest package before marking PendingDelete failed: {ex.Message}");
			throw;
		}

		// Set fileStatus = PendingDelete (must keep ALL other fields intact; API requires retaining the entry)
		// If fileStatus property missing, we add it.
		oldest.PackageObject["fileStatus"] = "PendingDelete";

		string removedFileName = oldest.PackageObject.TryGetPropertyValue("fileName", out JsonNode? removedNameNode)
			? (removedNameNode?.GetValue<string>() ?? "<unknown>")
			: "<unknown>";

		Console.WriteLine($"Marked oldest package for deletion: {removedFileName}");

		// Serialize updated submission (without adding the new package yet). This ensures deletion marking happens first.
		string updatedJson = submissionNode.ToJsonString(new JsonSerializerOptions
		{
			WriteIndented = false,
			Encoder = System.Text.Encodings.Web.JavaScriptEncoder.Create(System.Text.Unicode.UnicodeRanges.All)
		});

		// PUT update to persist the status change prior to uploading/adding the new package
		_ = await ExecuteWithRetryAsync(async () =>
		{
			using HttpClient client = new()
			{
				Timeout = TimeSpan.FromSeconds(ExtendedTimeoutSeconds)
			};
			client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

			Uri requestUrl = new($"https://manage.devcenter.microsoft.com/v1.0/my/applications/{applicationId}/submissions/{submissionId}");

			using StringContent content = new(updatedJson, Encoding.UTF8, "application/json");
			_ = (content.Headers?.ContentType?.CharSet = "UTF-8");

			using HttpResponseMessage response = await client.PutAsync(requestUrl, content);

			Console.WriteLine($"PendingDelete marking update response status: {response.StatusCode}");
			string responseContent = await response.Content.ReadAsStringAsync();
			if (response.IsSuccessStatusCode)
			{
				Console.WriteLine("Oldest package successfully marked as PendingDelete (submission updated).");
				return 0;
			}
			else
			{
				WriteSensitiveLogs($"Response Content: {responseContent}");
				throw new HttpRequestException($"Failed to update submission when marking oldest package PendingDelete. Status {response.StatusCode}.");
			}
		}, "mark oldest package PendingDelete");
	}

	/// <summary>
	/// Uploads a package and updates the submission with package information.
	/// </summary>
	internal static async Task AddPackageToSubmissionAsync(
		string accessToken,
		string applicationId,
		string submissionId,
		string packageFilePath)
	{
		if (!File.Exists(packageFilePath))
		{
			throw new FileNotFoundException($"Package file not found: {packageFilePath}");
		}

		Console.WriteLine($"Adding package to submission: {Path.GetFileName(packageFilePath)}");

		// Ensure we enforce the maximum number of packages by removing the oldest first if limit reached.
		await RemoveOldestPackageIfLimitReachedAsync(
			accessToken,
			applicationId,
			submissionId,
			MaxApplicationPackages);

		// Upload the package file (as ZIP)
		string uploadedFileName = await UploadPackageAsync(accessToken, applicationId, submissionId, packageFilePath);

		// Update the submission with package information
		_ = await UpdateSubmissionWithPackageAsync(accessToken, applicationId, submissionId, uploadedFileName);

		Console.WriteLine("Package added to submission successfully!");
	}

	/// <summary>
	/// Updates the release notes for the English (en-us) listing in the submission.
	/// </summary>
	internal static async Task<string> UpdateReleaseNotesAsync(
		string accessToken,
		string applicationId,
		string submissionId,
		string releaseNotes)
	{
		// First, get the current submission data
		string currentSubmissionJson = await GetSubmissionConfigAsync(accessToken, applicationId, submissionId);

		JsonNode? submissionNode = JsonNode.Parse(currentSubmissionJson) ?? throw new InvalidOperationException("Failed to parse submission JSON");

		// Navigate to the English listing and update release notes
		JsonNode? listingsNode = submissionNode["listings"];
		if (listingsNode != null)
		{
			JsonNode? enUsNode = listingsNode["en-us"];
			if (enUsNode != null)
			{
				JsonNode? baseListingNode = enUsNode["baseListing"];
				_ = (baseListingNode?["releaseNotes"] = releaseNotes);
			}
		}

		// Serialize back to JSON
		string updatedJson = submissionNode.ToJsonString(new JsonSerializerOptions
		{
			WriteIndented = false,
			Encoder = System.Text.Encodings.Web.JavaScriptEncoder.Create(System.Text.Unicode.UnicodeRanges.All)
		});

		return await ExecuteWithRetryAsync(async () =>
		{
			using HttpClient client = new()
			{
				Timeout = TimeSpan.FromSeconds(ExtendedTimeoutSeconds)
			};
			client.DefaultRequestHeaders.Authorization =
				new AuthenticationHeaderValue("Bearer", accessToken);

			Uri requestUrl = new($"https://manage.devcenter.microsoft.com/v1.0/my/applications/{applicationId}/submissions/{submissionId}");

			using StringContent content = new(updatedJson, Encoding.UTF8, "application/json");
			_ = (content.Headers?.ContentType?.CharSet = "UTF-8");

			using HttpResponseMessage response = await client.PutAsync(requestUrl, content);

			Console.WriteLine($"Update response status: {response.StatusCode}");
			string responseContent = await response.Content.ReadAsStringAsync();

			if (response.IsSuccessStatusCode)
			{
				Console.WriteLine("Release notes updated successfully!");
				return responseContent;
			}
			else
			{
				WriteSensitiveLogs($"Response Content: {responseContent}");
				throw new HttpRequestException($"Update request failed with status {response.StatusCode}.");
			}
		}, "update release notes");
	}

	/// <summary>
	/// Commits the pending submission for the application.
	/// </summary>
	internal static async Task<string> CommitSubmissionAsync(
		string accessToken,
		string applicationId,
		string submissionId)
	{
		return await ExecuteWithRetryAsync(async () =>
		{
			using HttpClient client = new()
			{
				Timeout = TimeSpan.FromSeconds(ExtendedTimeoutSeconds)
			};
			client.DefaultRequestHeaders.Authorization =
				new AuthenticationHeaderValue("Bearer", accessToken);

			Uri requestUrl = new($"https://manage.devcenter.microsoft.com/v1.0/my/applications/{applicationId}/submissions/{submissionId}/commit");

			WriteSensitiveLogs($"Committing submission at: {requestUrl}");

			using HttpResponseMessage response = await client.PostAsync(requestUrl, null);

			Console.WriteLine($"Commit response status: {response.StatusCode}");
			string responseContent = await response.Content.ReadAsStringAsync();
			WriteSensitiveLogs($"Commit response content: {responseContent}");

			if (response.IsSuccessStatusCode)
			{
				// Parse the response to get commit status information
				using JsonDocument doc = JsonDocument.Parse(responseContent);
				JsonElement root = doc.RootElement;

				if (root.TryGetProperty("status", out JsonElement statusElement))
				{
					string? status = statusElement.GetString();
					WriteSensitiveLogs($"Submission commit status: {status}");
				}

				if (root.TryGetProperty("statusDetails", out JsonElement statusDetailsElement))
				{
					if (statusDetailsElement.TryGetProperty("errors", out JsonElement errorsElement) && errorsElement.GetArrayLength() > 0)
					{
						Console.WriteLine("Commit errors found:");
						foreach (JsonElement error in errorsElement.EnumerateArray())
						{
							if (error.TryGetProperty("code", out JsonElement codeElement) &&
								error.TryGetProperty("details", out JsonElement detailsElement))
							{
								WriteSensitiveLogs($"  Error {codeElement.GetString()}: {detailsElement.GetString()}");
							}
						}
					}

					if (statusDetailsElement.TryGetProperty("warnings", out JsonElement warningsElement) && warningsElement.GetArrayLength() > 0)
					{
						Console.WriteLine("Commit warnings found:");
						foreach (JsonElement warning in warningsElement.EnumerateArray())
						{
							if (warning.TryGetProperty("code", out JsonElement codeElement) &&
								warning.TryGetProperty("details", out JsonElement detailsElement))
							{
								WriteSensitiveLogs($"  Warning {codeElement.GetString()}: {detailsElement.GetString()}");
							}
						}
					}

					if (statusDetailsElement.TryGetProperty("certificationNotes", out JsonElement certNotesElement))
					{
						string? certNotes = certNotesElement.GetString();
						if (!string.IsNullOrEmpty(certNotes))
						{
							WriteSensitiveLogs($"Certification notes: {certNotes}");
						}
					}
				}

				Console.WriteLine("Submission committed successfully!");
				return responseContent;
			}
			else
			{
				WriteSensitiveLogs($"Response Content: {responseContent}");
				throw new HttpRequestException($"Commit submission request failed with status {response.StatusCode}.");
			}
		}, "commit submission");
	}
}

internal sealed class Program
{
	public static async Task Main(string[] args)
	{
		// Check if first argument is the status command
		if (args.Length > 0 && args[0].Equals("status", StringComparison.OrdinalIgnoreCase))
		{
			await HandleStatusCommandAsync(args);
			return;
		}

		if (args.Length != 6)
		{
			Console.WriteLine("Usage for submission:");
			Console.WriteLine("  <tokenEndpoint> <clientId> <clientSecret> <applicationId> <packageFilePath> <releaseNotesFilePath>");
			Console.WriteLine();
			Console.WriteLine("Usage for status check:");
			Console.WriteLine("  status <tokenEndpoint> <clientId> <clientSecret> <applicationId>");
			return;
		}

		string tokenEndpoint = args[0];
		string clientId = args[1];
		string clientSecret = args[2];
		string applicationId = args[3];
		string packageFilePath = args[4];
		string releaseNotesFilePath = args[5];

		string releaseNotes;
		try
		{
			releaseNotes = await File.ReadAllTextAsync(releaseNotesFilePath);
		}
		catch (Exception ex)
		{
			await Console.Error.WriteLineAsync($"Failed to read release notes file: {ex.Message}");
			return;
		}

		const string scope = "https://manage.devcenter.microsoft.com";
		const bool deleteExistingDraft = true;

		Console.WriteLine("Getting authorization token...");
		string accessToken = await Helpers.GetClientCredentialAccessToken(
			tokenEndpoint,
			clientId,
			clientSecret,
			scope);

		Console.WriteLine("Authorization token received.");
		Console.WriteLine("Getting or creating pending submission ID...");
		string submissionId = await Helpers.GetOrCreatePendingSubmissionIdAsync(
			accessToken,
			applicationId,
			deleteExistingDraft);

		Helpers.WriteSensitiveLogs($"Using submission ID: {submissionId}");
		Console.WriteLine("Uploading package and updating submission...");
		await Helpers.AddPackageToSubmissionAsync(
			accessToken,
			applicationId,
			submissionId,
			packageFilePath);

		Console.WriteLine("Updating release notes...");
		_ = await Helpers.UpdateReleaseNotesAsync(
			accessToken,
			applicationId,
			submissionId,
			releaseNotes);

		Console.WriteLine("Committing submission...");
		_ = await Helpers.CommitSubmissionAsync(
			accessToken,
			applicationId,
			submissionId);

		Console.WriteLine("Waiting for commit processing to complete...");
		await Helpers.WaitForCommitProcessingAsync(
			accessToken,
			applicationId,
			submissionId);

		Console.WriteLine("Submission process completed successfully.");
	}

	private static async Task HandleStatusCommandAsync(string[] args)
	{
		if (args.Length != 5)
		{
			Console.WriteLine("Usage for status check:");
			Console.WriteLine("  status <tokenEndpoint> <clientId> <clientSecret> <applicationId>");
			return;
		}

		string tokenEndpoint = args[1];
		string clientId = args[2];
		string clientSecret = args[3];
		string applicationId = args[4];

		const string scope = "https://manage.devcenter.microsoft.com";

		try
		{
			Console.WriteLine("Getting authorization token...");
			string accessToken = await Helpers.GetClientCredentialAccessToken(
				tokenEndpoint,
				clientId,
				clientSecret,
				scope);

			Console.WriteLine("Authorization token received.");
			Console.WriteLine("Getting pending submission ID...");
			string? submissionId = await Helpers.GetPendingSubmissionIdAsync(accessToken, applicationId);

			if (submissionId is null)
			{
				Console.WriteLine("No pending submission found for this application.");
				return;
			}

			Console.WriteLine("Checking submission status...");
			await Helpers.CheckSubmissionStatusAsync(accessToken, applicationId, submissionId);
		}
		catch (Exception ex)
		{
			Helpers.WriteSensitiveLogs($"Error checking submission status: {ex.Message}");
		}
	}
}
