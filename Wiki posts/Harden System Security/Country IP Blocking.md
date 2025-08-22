# Country IP Blocking | Harden System Security

<p align="center"><img src="https://raw.githubusercontent.com/HotCakeX/.github/0180bc6ace1ea086653cc405f142d1aada424150/Pictures/Readme%20Categories/Country%20IP%20Blocking/Country%20IP%20Blocking.svg" alt="Country IP Blocking - Harden Windows Security GitHub repository" width="500"></p>

<br>

## Targeted Lists

The [Harden System Security App](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Harden-System-Security) uses the newest range of `IPv4` and `IPv6` addresses of [State Sponsors of Terrorism](https://www.state.gov/state-sponsors-of-terrorism/) and [OFAC Sanctioned Countries](https://orpa.princeton.edu/export-controls/sanctioned-countries), directly [from official IANA sources](https://github.com/HotCakeX/Official-IANA-IP-blocks) repository, then creates 2 rules (inbound and outbound) for each list in Windows firewall, completely blocking connections to and from those countries.

Once you have those Firewall rules added, you can [use this method](https://github.com/HotCakeX/Harden-Windows-Security/wiki/Event-Viewer#how-to-identify-which-windows-firewall-rule-is-responsible-for-a-blocked-packets) to see if any of the blocked connections were from/to those countries.


> [!NOTE]\
> Threat actors can use VPN, VPS etc. to mask their originating IP address and location. So don't take this category as the perfect solution for network protection.

<br>

## Individual Country IP Blocking

<div align="center">

<img src="https://raw.githubusercontent.com/HotCakeX/.github/35ec97127b017787697d59d7b44a8a4e3e274418/Pictures/APNGs/HardenSystemSecurity-CountryIPBlockingDemo.apng" alt="Harden System Security Country IP Blocking page" />

</div>

<br>

You can use this feature to block individual countries in Windows Firewall. Simply search for a country's name in the list and block/unblock all of its IPv4 and IPV6 ranges in just a few seconds.

<br>
