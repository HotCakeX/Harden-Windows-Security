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

using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace CommonCore.Others;

internal static class HTTPHandler
{

	private const int HttpMaxRetries = 4;                    // Total attempts including the first try
	private const int HttpBaseDelayMs = 500;                 // Base delay for backoff
	private const int HttpJitterMaxMs = 250;                 // Max additional random jitter per attempt
	private const int MaxBackoffMilliseconds = 8000;         // Cap for per-attempt backoff

	/// <summary>
	/// Centralized resilient HTTP execution with retry handling for transient failures (429 / selected 5xx / network errors).
	/// Returns the first non-transient response immediately (successful or logical failure).
	/// Throws only if all attempts fail with transient exceptions and no HTTP response is obtained.
	/// Caller is responsible for disposing the returned response.
	/// </summary>
	internal static async Task<HttpResponseMessage> ExecuteHttpWithRetryAsync(
		string operationName,
		Func<HttpRequestMessage> requestFactory,
		HttpClient client,
		CancellationToken cancellationToken = default)
	{

		Exception? lastException = null;

		for (int attempt = 1; attempt <= HttpMaxRetries; attempt++)
		{
			HttpRequestMessage request = requestFactory();
			HttpResponseMessage? response = null;

			try
			{
				response = await client.SendAsync(
					request,
					HttpCompletionOption.ResponseHeadersRead,
					cancellationToken).ConfigureAwait(false);

				// If status is not retryable or this was the final attempt, return it immediately.
				if (!IsRetryableStatus(response.StatusCode) || attempt == HttpMaxRetries)
				{
					return response;
				}

				TimeSpan delay = GetDelayForAttempt(attempt);
				Logger.Write($"HTTP Retry: Operation='{operationName}', Attempt={attempt}/{HttpMaxRetries}, Status={(int)response.StatusCode} {response.StatusCode}, NextDelayMs={delay.TotalMilliseconds:F0}");

				// Dispose response before retry to free resources.
				response.Dispose();

				await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
				continue;
			}
			catch (TaskCanceledException ex) when (!cancellationToken.IsCancellationRequested && attempt < HttpMaxRetries)
			{
				lastException = ex;
				TimeSpan delay = GetDelayForAttempt(attempt);
				Logger.Write($"HTTP Retry: Operation='{operationName}', Attempt={attempt}/{HttpMaxRetries}, Timeout (TaskCanceledException), NextDelayMs={delay.TotalMilliseconds:F0}");
				await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
				continue;
			}
			catch (HttpRequestException ex) when (attempt < HttpMaxRetries)
			{
				lastException = ex;
				TimeSpan delay = GetDelayForAttempt(attempt);
				Logger.Write($"HTTP Retry: Operation='{operationName}', Attempt={attempt}/{HttpMaxRetries}, Network exception (HttpRequestException), NextDelayMs={delay.TotalMilliseconds:F0}");
				await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
				continue;
			}
			catch
			{
				// Non-transient or final-attempt.
				throw;
			}
			finally
			{
				// If we threw before assigning response, ensure request is disposed (response.Dispose() already above on retry path).
				// HttpClient disposes HttpRequestMessage after send normally, but if SendAsync fails early it may not.
				if (response is null)
				{
					request.Dispose();
				}
			}
		}

		throw new InvalidOperationException(
			$"Failed to complete '{operationName}' after {HttpMaxRetries} attempts.", lastException);
	}

	/// <summary>
	/// Determines whether an HTTP status code is considered transient/retryable.
	/// </summary>
	private static bool IsRetryableStatus(HttpStatusCode statusCode)
	{
		// 429 (throttling) and common recoverable 5xx codes.
		return statusCode == HttpStatusCode.TooManyRequests ||
			   statusCode == HttpStatusCode.InternalServerError ||
			   statusCode == HttpStatusCode.BadGateway ||
			   statusCode == HttpStatusCode.ServiceUnavailable ||
			   statusCode == HttpStatusCode.GatewayTimeout;
	}

	/// <summary>
	/// Backoff with linear base + jitter, capped.
	/// </summary>
	private static TimeSpan GetDelayForAttempt(int attempt)
	{
		int basePortion = HttpBaseDelayMs * attempt;
		int jitter = RandomNumberGenerator.GetInt32(0, HttpJitterMaxMs + 1);
		int total = basePortion + jitter;
		if (total > MaxBackoffMilliseconds)
		{
			total = MaxBackoffMilliseconds;
		}
		return TimeSpan.FromMilliseconds(total);
	}
}
