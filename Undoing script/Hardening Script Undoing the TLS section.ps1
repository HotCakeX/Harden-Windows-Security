$ErrorActionPreference = 'SilentlyContinue'

# Enable NULL Cipher Suites - 1 
Enable-TlsCipherSuite TLS_RSA_WITH_NULL_SHA256
# Enable NULL Cipher Suites - 2
Enable-TlsCipherSuite TLS_RSA_WITH_NULL_SHA
# Enable NULL Cipher Suites - 3
Enable-TlsCipherSuite TLS_PSK_WITH_NULL_SHA384
# Enable NULL Cipher Suites - 4
Enable-TlsCipherSuite TLS_PSK_WITH_NULL_SHA256

Enable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_256_GCM_SHA384"
Enable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_128_GCM_SHA256"
Enable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_256_CBC_SHA256"
Enable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_128_CBC_SHA256"
Enable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_256_CBC_SHA"
Enable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_128_CBC_SHA"
Enable-TlsCipherSuite -Name "TLS_PSK_WITH_AES_256_GCM_SHA384"
Enable-TlsCipherSuite -Name "TLS_PSK_WITH_AES_128_GCM_SHA256"
Enable-TlsCipherSuite -Name "TLS_PSK_WITH_AES_256_CBC_SHA384"
Enable-TlsCipherSuite -Name "TLS_PSK_WITH_AES_128_CBC_SHA256"


@( # Deleting the registry keys
    'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56', # DES 56-bit
    'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128', # RC2 40-bit
    'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128', # RC2 56-bit
    'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128', # RC2 128-bit
    'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128', # RC4 40-bit
    'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128', # RC4 56-bit
    'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128', # RC4 64-bit
    'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128', # RC4 128-bit
    'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168', # 3DES 168-bit (Triple DES 168)
    'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\', # DWORD, Disable TLS v1
    'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\' # DWORD, Disable TLS v1.1
    'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5' # MD5 Hashing Algorithm
) | ForEach-Object { Remove-Item -Path $_ }