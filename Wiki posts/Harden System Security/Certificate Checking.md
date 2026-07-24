# Certificate Checking | Harden System Security

<p align="center"><img src="https://raw.githubusercontent.com/HotCakeX/.github/0180bc6ace1ea086653cc405f142d1aada424150/Pictures/Readme%20Categories/Certificate%20Checking/Certificate%20Checking.svg" alt="Certificate Checking Commands - Harden Windows Security" width="550"></p>

<br>

This page in the [Harden System Security App](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Harden-System-Security) is dedicated to enumerating every certificate across all stores in the **Local Machine** and **Current User** scopes. Certificates can be sorted, searched, and removed as needed.

There is a key capability identifying certificates that are **not rooted** to [the Microsoft's Trusted Roots list](https://learn.microsoft.com/security/trusted-root/participants-list) and presents options for remediation. When evaluating trust, the app does **not** rely on the system's certificate store; it uses an independent, built-in trust anchor to validate certificates, so its checks remain unaffected by a potentially compromised system store.

<br>

## Available Operations

The page provides two certificate collection workflows:

- **Start Analysis**: Lists all of the certificates that are not rooted to the trusted Microsoft root certificate list. The list gets downloaded from the Microsoft server when you press this button.

    - A certificate appearing in the results is not proof that it is malicious. Private enterprise certification authorities, development certificates, test environments, VPN products, device-management systems and other legitimate software can use certificates that are outside Microsoft's public trusted root program.

- **Get Local Certificates**: Lists all of the certificates from all stores that belong to any context.

## Results Customization

2 toggle buttons exist on the UI that lets you customize the results.

### Include Expired Certificates

* On: Includes expired certificates and certificates that are not yet valid.
* Off: Shows only certificates that are currently valid.

### Include Expired Certificates

* On: Includes certificates even when Windows cannot build a complete, trusted certificate chain.
* Off: Shows only certificates with a complete, valid, Windows-trusted chain.

## Sigcheck Equivalent

Microsoft Sysinternals Sigcheck provides the following parameter for checking certificate stores:

```
-t[u][v]
```

The same exact type of check can be easily performed directly in the Harden System Security app:

1. Turn off Include Expired Certificates.
2. Turn off Include Invalid Chains.
3. Select Start Analysis.

Unlike Sigcheck, which requires separate commands for the machine and user scopes, the app checks both scopes in a single operation.

The app does not run or depend on Sigcheck. It performs the certificate enumeration and trusted-root comparison using its own built-in implementation.

## Removing Certificates

You can remove any of the certificates that are listed. You can remove them one by one or multiple certificates at once. A confirmation dialog will be displayed to you before that action is performed so that you can review the certificate information and confirm the removal.

1. Select the certificate or certificates you want to remove.
2. Right-click (or tap + hold) on the selection and choose **Delete Certificate**, or press the `Delete` key on keyboard.
3. Review the certificate information in the confirmation dialog.
4. Confirm the removal.

> [!TIP]
> Only remove a certificate when you are certain it is unwanted.
