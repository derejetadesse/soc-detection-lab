\# 🏗️ AWS Cloud SOC Detection Lab Architecture



\## Overview



This document describes the architecture of the AWS Cloud SOC Detection Lab.



The lab was designed to demonstrate how a cloud-hosted Linux system can be hardened, monitored, and investigated using layered security controls.



The architecture combines AWS network security, Linux host security, secure remote administration, and host-based audit logging.



\## Architecture Diagram



```text

Security Analyst Workstation

&#x20;       |

&#x20;       | SSH over TCP/22

&#x20;       v

AWS Security Group

&#x20;       |

&#x20;       | Restricted administrative access

&#x20;       v

Amazon EC2

Ubuntu Linux Server

&#x20;       |

&#x20;       +----------------------+

&#x20;       |                      |

&#x20;       v                      v

OpenSSH                  UFW Host Firewall

&#x20;       |                      |

&#x20;       +----------+-----------+

&#x20;                  |

&#x20;                  v

&#x20;             Linux auditd

&#x20;                  |

&#x20;       +----------+-----------+

&#x20;       |          |           |

&#x20;       v          v           v

&#x20;/etc/passwd   /etc/group   /etc/sudoers

&#x20;       |

&#x20;       v

&#x20;/etc/ssh/sshd\_config

&#x20;       |

&#x20;       v

Security Audit Events

&#x20;       |

&#x20;       v

ausearch Investigation

&#x20;       |

&#x20;       v

SOC Analysis and Documentation

```



\## 1. Security Analyst Workstation



The analyst workstation is used to administer and investigate the AWS-hosted Linux system.



Administrative access is performed through SSH using a private key.



Example connection:



```bash

ssh -i "CloudSOC-Key.pem" ubuntu@<EC2-PUBLIC-DNS>

```



The private SSH key is stored locally and is never committed to GitHub.



\## 2. AWS Security Group



The AWS Security Group provides the first network security layer.



SSH traffic uses:



```text

TCP/22

```



Access was restricted to the authorized source IP rather than allowing unrestricted internet access.



This reduces unnecessary exposure of the EC2 instance.



\## 3. Amazon EC2 Ubuntu Server



The monitored workload is an Ubuntu Linux EC2 instance.



This system represents a cloud server that could host a production application or business service.



The instance was used to demonstrate:



\- Linux administration

\- Patch management

\- SSH security

\- Firewall configuration

\- Audit logging

\- Security event generation

\- SOC investigation



\## 4. SSH Security



Remote administration is protected with SSH public-key authentication.



The effective SSH configuration was validated:



```text

permitrootlogin prohibit-password

pubkeyauthentication yes

passwordauthentication no

```



This reduces risk from password guessing and brute-force authentication attacks.



\## 5. UFW Host Firewall



UFW provides a second network security layer directly on the Linux server.



The firewall uses a default-deny inbound policy.



```text

Default: deny (incoming), allow (outgoing)

```



SSH remains explicitly allowed.



This creates defense in depth between AWS network security controls and the operating system.



\## 6. Linux auditd



Linux `auditd` provides host-level visibility into security-sensitive activity.



The following files were monitored:



```text

/etc/passwd

/etc/group

/etc/sudoers

/etc/ssh/sshd\_config

```



These files are important because changes may indicate:



\- New account creation

\- Group membership changes

\- Privilege escalation

\- Sudo configuration changes

\- SSH configuration tampering



\## 7. Detection Rules



Persistent audit rules were configured:



```text

\-w /etc/passwd -p wa -k identity\_changes

\-w /etc/group -p wa -k identity\_changes

\-w /etc/sudoers -p wa -k privilege\_changes

\-w /etc/ssh/sshd\_config -p wa -k ssh\_changes

```



The rules assign searchable keys that allow the analyst to quickly investigate specific security categories.



\## 8. Security Event Flow



The detection workflow operates as follows:



```text

Security-Sensitive Change

&#x20;       |

&#x20;       v

Linux auditd Captures Event

&#x20;       |

&#x20;       v

Audit Rule Assigns Key

&#x20;       |

&#x20;       v

Event Written to Audit Logs

&#x20;       |

&#x20;       v

Analyst Queries Event

&#x20;       |

&#x20;       v

Process and File Identified

&#x20;       |

&#x20;       v

Security Impact Evaluated

&#x20;       |

&#x20;       v

Incident Documented

```



\## 9. Example Detection Scenario



A temporary account was created during a controlled test:



```bash

sudo useradd phase4test

```



The event was investigated using:



```bash

sudo ausearch -k identity\_changes -ts recent

```



Audit records identified:



```text

comm="useradd"

exe="/usr/sbin/useradd"

key="identity\_changes"

```



The affected files included:



```text

/etc/passwd

/etc/group

```



This demonstrated the full detection path from system change to analyst investigation.



\## 10. Defense-in-Depth Model



The lab implements multiple security layers:



```text

Layer 1: AWS Security Group

Layer 2: SSH Key Authentication

Layer 3: UFW Host Firewall

Layer 4: Linux Security Configuration

Layer 5: auditd Monitoring

Layer 6: Log Investigation

Layer 7: Incident Documentation

```



If one defensive control fails, additional controls continue to provide protection or visibility.



\## 11. Skills Demonstrated



This architecture demonstrates practical experience with:



\- AWS cloud security

\- Amazon EC2

\- AWS Security Groups

\- Linux administration

\- SSH authentication

\- Host firewall security

\- Defense-in-depth design

\- Linux audit logging

\- Detection engineering fundamentals

\- SOC investigation

\- Security event analysis

\- Incident documentation



\## Future Architecture Improvements



The lab can later be extended with:



```text

AWS EC2 Endpoint

&#x20;      |

&#x20;      v

Wazuh Agent

&#x20;      |

&#x20;      v

Centralized Wazuh SIEM

&#x20;      |

&#x20;      +---- Detection Rules

&#x20;      +---- MITRE ATT\&CK Mapping

&#x20;      +---- Alerting

&#x20;      +---- Dashboard

```



Additional AWS services could include:



\- AWS CloudTrail

\- Amazon GuardDuty

\- Amazon CloudWatch

\- AWS Config

\- Security Hub



\## Conclusion



The AWS Cloud SOC Detection Lab demonstrates a layered approach to securing and monitoring a cloud-hosted Linux system.



The architecture combines preventive controls with detective controls so that unauthorized or security-sensitive changes can be both limited and investigated.

