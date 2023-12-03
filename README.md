# Active Directory Ansible Lab
This project, based on Ansible, aims to automate the configuration of an Active Directory Lab, for pentesting purposes.
Different scenarios can be choosen and imported in the lab, making it vulnerable in different ways.
The goal of this project is to make the process easy and effortless.

The project covers only the systems' configuration; private networks, virtualization environments and Cloud's solutions are supported.


## Scenarios
Inside the directory [scenarios](scenarios/), instructions about vulnerable scenarios and how they can be configured can be found.


## Description
The playbook provided is highly configurable and it can be used to create:
* a Domain with a single Domain Controller
* multiple Domains each with a single Domain Controller
* a Forest with a Root Domain and multiple Child Domain, each with a Single Domain Controller
* servers in every domain

Different scripts are gonna be run to make the hosts configured/vulnerable, if needed.

Only Domain Controller and Server configuration is supported.
Workstations could be supported in the future.


## Notes
I developed the playbook's "first version" and the "Forest Privilege Escalation"'s scenario as a thesis for my Master degree in Computer Engineering at Alma Mater Studiorum, Bologna, Italy.

## License
This project is licensed under MIT License - see the LICENSE.md file for details.

