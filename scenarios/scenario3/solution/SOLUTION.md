# !! SPOILER ALERT !!
# Scenario 3 - CRTP-TBBT#2 - Solution

## Vulnerabilities
This is what you need to perform in order to achieve Enterprise Admins in the forest.
* Domain/Forest Enumeration:
    * Domains
    * Trusts
    * Users
    * Groups
    * Computers
    * ACLs
* Local Privilege Escalation
* Post Exploitation
    * NTLM hashes dump
* ASREPRoasting
* Constrained Delegation
* ACLs Abuse:
    * Generic Write
    * Write Owner
    * Write DACL
* Protected Groups Abuse
* DCSync Attack
* Cross Trust Privilege Escalation
      
      
## Exploitation Path

### TEST Server - Local Privilege Escalation
1. TBBT\test.user can elevate his privileges to SYSTEM through "Cached Credentials in Registry Autologons".
2. POST EXPLOITATION: dump TBBT\amy.farrahfowler's NTLM hash.

### Domain Enumeration:
1. TBBT\bernadette.wolowitz is ASREPRoastable, her password can be obtained.
2. TBBT\stuart.bloom is vulnerable to Constrained Delegation ("time/SHOP"'s spn).
3. The group "Domain Managers" has "Write DACL" on TBBT.ADLAB.ORG.

### SHOP Server - Domain Privilege Escalation
1. TBBT\bernadette.wolowitz (owned) has "Generic Write" on TBBT\penny.hofstadter.
2. TBBT\penny.hofstadter can then be Kerberoasted and her password obtained.
3. TBBT\penny.hofstadter (owned) has "Write Owner" on TBBT\stuart.bloom.
4. Constrained Delegation ("time/SHOP"'s spn) can be used to compromise SHOP server, through TBBT\stuart.bloom (owned).
5. POST EXPLOITATION: dump TBBT\leonard.hofstadter's NTLM hash.

### HOME Server - Domain Privilege Escalation
1. TBBT\leonard.hofstadter (owned) is part of "Local Admins", and as a consequence, a server's local administrator.
2. POST EXPLOITATION: dump TBBT\sheldon.cooper's NTLM hash.

### TBBT-DC - Domain Admins
1. TBBT\sheldon.cooper (owned) is part of "Account Operators" and can add members to the group "Domain Managers".
2. "Domain Managers" permissions guarantee DCSync permissions.
3. DCSync Attack.

### DC - Enterprise Admins
1. Simple Cross Trust Privilege Escalation using "KRBTGT"/"TRUST" hash.


