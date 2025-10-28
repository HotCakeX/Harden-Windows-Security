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

namespace CommonCore.Others;

/// <summary>
/// a class to throw a custom exception when the certificate has HashMismatch
/// </summary>
internal sealed class HashMismatchInCertificateException : Exception
{
	/// <summary>
	/// Initializes a new instance of the HashMismatchInCertificateException class. This constructor does not take any
	/// parameters.
	/// </summary>
	internal HashMismatchInCertificateException()
	{
	}

	/// <summary>
	/// Initializes a new instance of the HashMismatchInCertificateException class with a specified error message.
	/// </summary>
	/// <param name="message">The error message that describes the reason for the exception.</param>
	internal HashMismatchInCertificateException(string message)
		: base(message)
	{
	}

	/// <summary>
	/// Initializes a new instance of the HashMismatchInCertificateException class with a message and function name.
	/// </summary>
	/// <param name="message">Provides details about the error encountered.</param>
	/// <param name="functionName">Indicates the name of the function where the error occurred.</param>
	internal HashMismatchInCertificateException(string message, string functionName)
		: base($"{functionName}: {message}")
	{
	}

	/// <summary>
	/// Initializes a new instance of the HashMismatchInCertificateException class with a specified error message and an
	/// inner exception.
	/// </summary>
	/// <param name="message">Provides a description of the error that occurred.</param>
	/// <param name="innerException">Holds the exception that is the cause of the current exception.</param>
	internal HashMismatchInCertificateException(string message, Exception innerException)
		: base(message, innerException)
	{
	}
}
