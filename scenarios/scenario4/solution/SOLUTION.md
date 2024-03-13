# !! SPOILER ALERT !!
# Scenario 4 - THEOFFICE - Solution

## Vulnerabilities
This is what you need to perform in order to achieve Enterprise Admins in the forest.
* Domain/Forest Enumeration:
    * Domains
    * Trusts
    * Users
    * Groups
    * Computers
    * ACLs
* Post Exploitation
    * NTLM hashes dump
* ASREPRoasting
* Resource Based Constrained Delegation
* ACLs Abuse:
    * Generic Write
    * User-Force-Change-Password
    * Write DACL
    * Self
    * Write Property
* DCSync Attack
* ADCS Attack
    * ESC1 (with custom low-privileged group)
* Cross Trust Privilege Escalation through Foreign Group Membership
      
      
## Exploitation Path

### Domain Enumeration
1. SCRANTON\pam.beesly is ASREPRoastable, her password can be obtained.

### SALES Server - Domain Privilege Escalation
1. SCRANTON\pam.beesly (owned) has "User-Force-Change-Password" on SCRANTON\jim.halpert.
2. SCRANTON\jim.halpert (owned) is part of "Sales Admins", and as a consequence, he's a server's local administrator.
3. POST EXPLOITATION: dump SCRANTON\dwight.schrute's NTLM hash.

### ACCOUNTING Server - Domain Privilege Escalation
1. SCRANTON\dwight.schrute (owned) has "GenericWrite" on ACCOUNTING server.
2. A Resource Based Constrained Delegation attack can be performed on ACCOUNTING server.
2. POST EXPLOITATION: dump SCRANTON\oscar.martinez's NTLM hash.

### SCRANTON-DC - Domain Admins
1. SCRANTON\oscar.martinez (owned) has "WriteDACL" on the domain, that guarantees DCSync permissions.
2. DCSync Attack.

### Forest Enumeration:
1. "Certificates Managers" group has permissions to enroll a vulnerable certificate template (custom ESC1).

### OFFICE Server - Forest Privilege Escalation
1. SCRANTON\michael.scott (owned) has "Self" on "Office Admins".
2. "Office Admins" is a local administrator group.
3. POST EXPLOITATION: dump DUNDERMIFFLIN\jan.levinson's NTLM hash.

### DC - Enterprise Admins
1. DUNDERMIFFLIN\jan.levinson has "WriteProperty" on "Certificates Managers" group.
2. ADCS Privilege Escalation (custom ESC1) can be performed to achieve Enterprise Admins through "Certificates Managers" group.

















