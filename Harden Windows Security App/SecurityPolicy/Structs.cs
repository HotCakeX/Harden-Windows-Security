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
using System.Runtime.InteropServices;

namespace HardenWindowsSecurity.SecurityPolicy;

// https://learn.microsoft.com/openspecs/windows_protocols/ms-samr/d74231bd-81e2-4229-9e82-ce6d3713cc62
[StructLayout(LayoutKind.Sequential)]
internal struct SAM_USER_GENERAL_INFORMATION
{
	internal LSA_UNICODE_STRING UserName;
	internal LSA_UNICODE_STRING FullName;
	internal uint PrimaryGroupId;
	internal LSA_UNICODE_STRING AdminComment;
	internal LSA_UNICODE_STRING UserComment;
}

// https://learn.microsoft.com/windows/win32/api/lmaccess/ns-lmaccess-user_modals_info_0
[StructLayout(LayoutKind.Sequential)]
internal struct USER_MODALS_INFO_0
{
	internal uint min_passwd_len;
	internal uint max_passwd_age;
	internal uint min_passwd_age;
	internal uint force_logoff;
	internal uint password_hist_len;
}

// https://learn.microsoft.com/windows/win32/api/lmaccess/ns-lmaccess-user_modals_info_1
[StructLayout(LayoutKind.Sequential)]
internal struct USER_MODALS_INFO_1
{
	internal uint role;
	[MarshalAs(UnmanagedType.LPWStr)]
	internal string primary;
}

// https://learn.microsoft.com/windows/win32/api/lmaccess/ns-lmaccess-user_modals_info_3
[StructLayout(LayoutKind.Sequential)]
internal struct USER_MODALS_INFO_3
{
	internal uint lockout_duration;
	internal uint lockout_observation_window;
	internal uint lockout_threshold;
}

// https://learn.microsoft.com/windows/win32/api/lmaccess/ns-lmaccess-user_info_1
[StructLayout(LayoutKind.Sequential)]
internal struct USER_INFO_1
{
	[MarshalAs(UnmanagedType.LPWStr)]
	internal string usri1_name;
	[MarshalAs(UnmanagedType.LPWStr)]
	internal string usri1_password;
	internal uint usri1_password_age;
	internal uint usri1_priv;
	[MarshalAs(UnmanagedType.LPWStr)]
	internal string usri1_home_dir;
	[MarshalAs(UnmanagedType.LPWStr)]
	internal string usri1_comment;
	internal uint usri1_flags;
	[MarshalAs(UnmanagedType.LPWStr)]
	internal string usri1_script_path;
}

// https://learn.microsoft.com/windows/win32/api/lsalookup/ns-lsalookup-lsa_unicode_string
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct LSA_UNICODE_STRING
{
	internal ushort Length;
	internal ushort MaximumLength;
	internal IntPtr Buffer;

	internal LSA_UNICODE_STRING(string? s)
	{
		if (s is null)
		{
			Length = MaximumLength = 0;
			Buffer = IntPtr.Zero;
		}
		else
		{
			Length = (ushort)(s.Length * 2);
			MaximumLength = (ushort)(Length + 2);
			Buffer = Marshal.StringToHGlobalUni(s);
		}
	}
}

// https://learn.microsoft.com/windows/win32/api/lsalookup/ns-lsalookup-lsa_string
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
internal struct LSA_STRING
{
	internal ushort Length;
	internal ushort MaximumLength;
	internal IntPtr Buffer;

	internal LSA_STRING(string s)
	{
		if (s is null)
		{
			Length = MaximumLength = 0;
			Buffer = IntPtr.Zero;
		}
		else
		{
			Length = (ushort)s.Length;
			MaximumLength = (ushort)(Length + 1);
			Buffer = Marshal.StringToHGlobalAnsi(s);
		}
	}
}

// https://learn.microsoft.com/windows/win32/api/lsalookup/ns-lsalookup-lsa_object_attributes
[StructLayout(LayoutKind.Sequential)]
internal struct LSA_OBJECT_ATTRIBUTES
{
	internal int Length;
	internal IntPtr RootDirectory;
	internal IntPtr ObjectName;
	internal int Attributes;
	internal IntPtr SecurityDescriptor;
	internal IntPtr SecurityQualityOfService;
}

// https://learn.microsoft.com/windows/win32/api/ntsecapi/ns-ntsecapi-lsa_enumeration_information
[StructLayout(LayoutKind.Sequential)]
internal struct LSA_ENUMERATION_INFORMATION
{
	internal IntPtr PSid;
}

// https://learn.microsoft.com/windows/win32/api/ntsecapi/ns-ntsecapi-audit_policy_information
[StructLayout(LayoutKind.Sequential)]
internal struct AUDIT_POLICY_INFORMATION
{
	internal Guid AuditSubCategoryGuid;
	internal uint AuditingInformation;
	internal Guid AuditCategoryGuid;
}

// https://learn.microsoft.com/windows/win32/api/lsalookup/ns-lsalookup-policy_account_domain_info
[StructLayout(LayoutKind.Sequential)]
internal struct POLICY_ACCOUNT_DOMAIN_INFO
{
	internal LSA_UNICODE_STRING DomainName;
	internal IntPtr DomainSid;
}

// https://learn.microsoft.com/windows/win32/api/ntsecapi/ns-ntsecapi-domain_password_information
[StructLayout(LayoutKind.Sequential)]
internal struct DOMAIN_PASSWORD_INFORMATION
{
	internal ushort MinPasswordLength;
	internal ushort PasswordHistoryLength;
	internal uint PasswordProperties;
	internal long MaxPasswordAge;
	internal long MinPasswordAge;
}
