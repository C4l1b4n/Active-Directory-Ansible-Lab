# Custom Scenario


## Description
This laboratory is based on a full custom configuration. Custom scripts could be run in the chosen hosts.
User can write a custom script for each host, then they will be uploaded and run on them.
This module can be used to test particular configurations or to create a custom vulnerable scenario.
Below an example that contains each host's type:
1 - one Forest's Root Domain, composed by one DC (dc01)
2 - one Child Domain, joined to the Forest, composed by one DC (dc02)
3 - one Server (srv01), joined to the Child Domain

## Build the hosts
This scenario can be used with one or more hosts. Create them accordingly.
Both Domain Controllers and Servers need Windows Server as OS and to be part of the same network.

NOTE: The lab is tested on Windows Server 2016 and Windows Server 2019.

## How to import the Scenario
Step-by-step operations to import the Scenario are the following.

### 1 - Configure main.yml
The line that imports the scenario in [ansible-playbook/main.yml](../../ansible-playbook/main.yml) needs to be uncommented.<br />
Line: 
```
- import_playbook: playbook/modules/custom.yml
```
Be sure that other scenarios are commented.

### 2 - Configure inventory
Copy [scenarios/scenario1/inventory-custom](inventory-custom) in [ansible-playbook/](../../ansible-playbook/).

The parameters:
* ansible_host: host's address; public address if in a Cloud environment
* ansible_user: administrator's username
* ansible_password: administrator's password<br />

need to be configured accordingly.

NOTE: Different groups are used for different purposes; hosts in "DCs_root" will be configured as "Root Domain DCs", hosts in "DCs_child" will be configured as "Child Domain DCs" and joined to their parents, hosts in "Servers" will be configured as servers and joined to their domain.

### 3 - Configure vars.yml
Copy [scenarios/custom/vars.yml](vars.yml) in [ansible-playbook/playbook/vars/](../../ansible-playbook/playbook/vars/).

Parameters need to be configured accordingly.

Root Domain (default dc01):
* hostname: Domain Controller's hostname.
* private_address: host's private address; it's used to differentiate public and private address if they are different.
* domain: domain's name.
* database_path: NTDS's path.
* log_path: logs' path.
* sysvol_path: SYSVOL's path.
* safe_mode_password: Safe mode administrator's password.

Child Domain (default dc02):
* hostname: Domain Controller's hostname.
* private_address: host's private address; it's used to differentiate public and private address if they are different.
* root_dc_host: host's name of the domain controller of the Root domain.
* domain: domain's name.
* database_path: NTDS's path.
* log_path: logs' path.
* sysvol_path: SYSVOL's path.
* safe_mode_password: Safe mode administrator's password.

Server (default srv01):
* hostname: Server's hostname.
* domain_dc_host: host's name of the domain controller of the chosen domain.

Optional parameters, that can be used for each host's type:
* script: script's local path; it will be uploaded to the target machine, run, and then removed.
* rdp: yes|true ; it will install and configure RDP in the target machine.
* autologon: yes|true ; it will upload "Autologon64.exe" in the target machine.


## Build the scenario
```
cd ansible-playbook/
ansible-playbook -i inventory-custom main.yml
```

## License
This project is licensed under MIT License - see the LICENSE.md file for details.

