# !! SPOILER ALERT !!
# Scenario 2 - CRTP-TBBT#1 - Solution

## Vulnerabilities
This is what you need to perform in order to achieve Enterprise Admins in the forest.
* Domain/Forest Enumeration:
    * Domains
    * Trusts
    * Users
    * Groups
    * Computers
    * GPOs
    * ACLs
* Local Privilege Escalation
* Post Exploitation
    * NTLM hashes dump
    * Tickets dump
* Kerberoasting
* Unconstrained Delegation
* ACLs Abuse:
    * User-Force-Change-Password
    * Self
    * Write Property
* Cross Trust Privilege Escalation
      
      
## Exploitation Path

### TEST Server - Local Privilege Escalation
1. TEST\testuser can elevate his privileges to SYSTEM through UnquotedPath Service (WiseBootAssistant).
2. POST EXPLOITATION: dump TBBT\amy.farrahfowler's NTLM hash.

### Domain Enumeration:
1. TBBT\emily.sweeney is Kerberoastable, her password can be obtained.
2. "CALTECH" server is vulnerable to Unconstrained Delegation.
3. GPOs: "Caltech Council" is the local admin in "CALTECH" server.
4. GPOs: "Apartment Key" is the local admin in "HOME" server.

### HOME Server - Domain Privilege Escalation
1. TBBT\emily.sweeney (owned) has "User-Force-Change-Password" on TBBT\rajesh.koothrappali.
2. TBBT\rajesh.koothrappali (owned) has "Self" on "Backup Apartment Key".
3. "Backup Apartment Key" is nested into "Apartment Key", so TBBT\rajesh.koothrappali is a Local Admin in "HOME" server.
4. POST EXPLOITATION: dump TBBT\howard.wolowitz's NTLM hash.

### CALTECH Server - Domain Privilege Escalation
1. TBBT\howard.wolowitz (owned) is part of "Engineers".
2. "Engineers" has "WritePropety" on "Caltech Council", that is a Local Admin Group in "CALTECH" server.
4. POST EXPLOITATION: dump TBBT\chuck.lorre's TGT.

### TBBT-DC - Domain Admins
1. Inject TBBT\chuck.lorre's TGT in memory, he's a Domain Admin.

### DC - Enterprise Admins
1. Simple Cross Trust Privilege Escalation using "KRBTGT"/"TRUST" hash.


