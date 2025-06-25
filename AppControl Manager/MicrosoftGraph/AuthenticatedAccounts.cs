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
using AppControlManager.Others;
using Microsoft.Identity.Client;

namespace AppControlManager.MicrosoftGraph;

internal sealed class AuthenticatedAccounts : Main.IRestrictedAuthenticatedAccounts
{
	internal string AccountIdentifier { get; }
	internal string Username { get; }
	internal string TenantID { get; }
	internal string Permissions { get; }
	internal AuthenticationContext AuthContext { get; }

	// Backing fields for the restricted properties.
	private readonly AuthenticationResult _authResult;
	private readonly IAccount _account;

	// The following two properties are implemented explicitly so that they are only accessible within the Main class which uses the interface.
	AuthenticationResult Main.IRestrictedAuthenticatedAccounts.AuthResult
	{
		get => _authResult;
		set => throw new InvalidOperationException(
			GlobalVars.GetStr("AuthResultImmutableErrorMessage"));
	}
	IAccount Main.IRestrictedAuthenticatedAccounts.Account
	{
		get => _account;
		set => throw new InvalidOperationException(
			GlobalVars.GetStr("AccountImmutableErrorMessage"));
	}

	internal AuthenticatedAccounts(string accountIdentifier, string userName, string tenantID, string permissions, AuthenticationContext authContext, AuthenticationResult authResult, IAccount account)
	{
		AccountIdentifier = accountIdentifier;
		Username = userName;
		TenantID = tenantID;
		Permissions = permissions;
		AuthContext = authContext;
		_authResult = authResult;
		_account = account;
	}


	public override bool Equals(object? obj)
	{
		if (ReferenceEquals(this, obj))
			return true;
		if (obj is null || obj.GetType() != GetType())
			return false;
		AuthenticatedAccounts other = (AuthenticatedAccounts)obj;
		return StringComparer.OrdinalIgnoreCase.Equals(AccountIdentifier, other.AccountIdentifier)
			&& StringComparer.OrdinalIgnoreCase.Equals(Username, other.Username)
			&& StringComparer.OrdinalIgnoreCase.Equals(TenantID, other.TenantID)
			&& StringComparer.OrdinalIgnoreCase.Equals(Permissions, other.Permissions);
	}

	public override int GetHashCode()
	{
		unchecked // Not strictly necessary, but good practice for future-proofing and consistency
		{
			return HashCode.Combine(
				StringComparer.OrdinalIgnoreCase.GetHashCode(AccountIdentifier),
				StringComparer.OrdinalIgnoreCase.GetHashCode(Username),
				StringComparer.OrdinalIgnoreCase.GetHashCode(TenantID),
				StringComparer.OrdinalIgnoreCase.GetHashCode(Permissions));
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

	public static bool operator !=(AuthenticatedAccounts? left, AuthenticatedAccounts? right)
	{
		return !(left == right);
	}
}
