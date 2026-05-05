---
description: Amazon Web Services
icon: aws
---

# AWS

AWS is one of those things where the attack surface isn't obvious until you understand how the identity model works. Most environments have misconfigured IAM, exposed storage, or overpermissive roles sitting there untouched because cloud security is still catching up to how fast teams ship infrastructure.

I didn't really get AWS from a red team perspective until I started poking at it hands-on. Once the IAM model clicked, the misconfigurations started making sense. This series covers the techniques I've worked through, written the way I wish someone had explained them to me the first time.

The cloud attack surface is different from Active Directory. There's no lateral movement through SMB, no Kerberos to abuse directly. Everything goes through the API. That means identity is everything -- who you are, what you can assume, and what conditions your policies evaluate under. Understanding that model is what separates cloud recon from guessing.

The pages that follow cover the techniques I've actually worked through.
