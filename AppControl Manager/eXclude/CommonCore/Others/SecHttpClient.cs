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

using System.Net.Http;

namespace CommonCore.Others;

/// <summary>
/// This class acts as a centralized provider for a Singleton HttpClient instance.
/// https://learn.microsoft.com/dotnet/fundamentals/networking/http/httpclient-guidelines
/// </summary>
internal static class SecHttpClient
{
	private static readonly Lazy<HttpClient> _instance = new(() =>
	{
		SocketsHttpHandler handler = new()
		{
			// Recreates the connection every 15 minutes to handle any possible DNS changes
			// This is to avoid communicating with stale IP addresses
			PooledConnectionLifetime = TimeSpan.FromMinutes(15)
		};

		// Create and configure the client
		HttpClient client = new(handler)
		{
			DefaultVersionPolicy = HttpVersionPolicy.RequestVersionOrHigher
		};

		return client;
	});

	internal static HttpClient Instance => _instance.Value;
}
