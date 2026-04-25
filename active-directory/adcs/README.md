---
description: ADCS attacks series
---

# ADCS

Active Directory Certificate Services aka ADCS is one of those things that looks harmless until it isn't. Most environments have it running, most admins don't fully understand it, and most pentesters walk right past it.

I didn't really get ADCS until I started abusing it. Once it clicked, I kept finding it everywhere. This series covers the misconfigurations I've actually worked through, ESC3, ESC7, ESC8,etc written the way I wish someone had explained them to me the first time.

In 2021 Will Schroeder and Lee Christensen from SpecterOps published a [whitepaper](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf) called "Certified Pre-Owned" that changed how the offensive security community looked at Active Directory. ADCS had existed for years but nobody had systematically mapped out how misconfigured certificate templates could be abused for privilege escalation and persistence. That paper introduced the ESC1 through ESC8 attack classes and suddenly every internal network assessment had a new critical finding hiding in plain sight.

The research didn't stop at ESC8. Oliver Lyak extended it with ESC9 and ESC10, targeting weak certificate mapping introduced after Microsoft's Certifried patch. The community kept pushing and today the list runs to ESC16, covering everything from YubiHSM CA abuse to CA-wide security extension bypass.

ADCS is still one of the most overlooked attack surfaces in enterprise environments. Admins deploy it, forget about it, and move on. That's exactly why it keeps showing up in assessments.

The pages that follow covers the techniques I've actually worked through.
