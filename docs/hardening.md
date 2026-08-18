\# 🔐 AWS EC2 Linux Security Hardening



\## Overview



This document describes the security hardening performed on an Ubuntu Linux EC2 instance as part of the AWS Cloud SOC Detection Lab.



The objective was to reduce the attack surface of the server, strengthen remote access, enforce host-level firewall controls, and prepare the system for security monitoring with Linux `auditd`.



\## Environment



\- Cloud Provider: Amazon Web Services (AWS)

\- Service: Amazon EC2

\- Operating System: Ubuntu Linux

\- Remote Administration: SSH

\- Host Firewall: UFW

\- Security Monitoring: Linux auditd

\- Network Security: AWS Security Groups



\## 1. AWS Security Group



The EC2 instance was protected using an AWS Security Group.



SSH access was provided over:



```text

TCP/22

```



The security group acts as the first network-level security control protecting the EC2 instance.



\### Security Principle



Only services required for administration should be exposed.



This follows the principle of reducing unnecessary network exposure.



\## 2. SSH Hardening



SSH configuration was reviewed to reduce the risk of unauthorized remote access.



The following settings were validated:



```text

PermitRootLogin prohibit-password

PubkeyAuthentication yes

PasswordAuthentication no

```



\### Security Benefits



These settings provide several protections:



\- Disables password-based SSH authentication.

\- Uses cryptographic SSH keys for authentication.

\- Prevents password-based root login.

\- Reduces exposure to password guessing and brute-force attacks.



\## 3. Host Firewall — UFW



Ubuntu's Uncomplicated Firewall (`UFW`) was configured to provide host-level network protection.



SSH was allowed before enabling the firewall:



```bash

sudo ufw allow OpenSSH

sudo ufw enable

```



Firewall configuration was verified using:



```bash

sudo ufw status verbose

```



The resulting security posture included:



```text

Status: active

Default: deny (incoming), allow (outgoing)

22/tcp (OpenSSH) ALLOW IN

```



\### Security Benefit



The default-deny inbound policy blocks unsolicited inbound connections unless they have been explicitly permitted.



This provides an additional defensive layer beyond the AWS Security Group.



\## 4. Linux Audit Service



Linux `auditd` was used to provide host-level security monitoring.



Service status was verified using:



```bash

sudo systemctl is-active auditd

```



Expected result:



```text

active

```



\## 5. Critical File Monitoring



Audit rules were configured to detect modifications to security-sensitive Linux files.



```text

\-w /etc/passwd -p wa -k identity\_changes

\-w /etc/group -p wa -k identity\_changes

\-w /etc/sudoers -p wa -k privilege\_changes

\-w /etc/ssh/sshd\_config -p wa -k ssh\_changes

```



These rules monitor:



| File | Security Purpose |

|---|---|

| `/etc/passwd` | User account monitoring |

| `/etc/group` | Group membership monitoring |

| `/etc/sudoers` | Privilege configuration monitoring |

| `/etc/ssh/sshd\_config` | SSH configuration monitoring |



The configured rules were verified with:



```bash

sudo auditctl -l

```



\## 6. Defense-in-Depth Architecture



The EC2 instance uses multiple security layers:



```text

Internet

&#x20;  |

&#x20;  v

AWS Security Group

&#x20;  |

&#x20;  v

SSH Key Authentication

&#x20;  |

&#x20;  v

UFW Host Firewall

&#x20;  |

&#x20;  v

Ubuntu Linux EC2

&#x20;  |

&#x20;  v

auditd Monitoring

&#x20;  |

&#x20;  v

Security Logs / Investigation

```



This demonstrates a defense-in-depth approach where multiple controls protect and monitor the system.



\## 7. Security Validation



A controlled account-creation event was generated to validate the monitoring configuration.



```bash

sudo useradd phase4test

```



The event was investigated using:



```bash

sudo ausearch -k identity\_changes -ts recent

```



The audit records identified:



```text

comm="useradd"

exe="/usr/sbin/useradd"

key="identity\_changes"

```



This confirmed that the monitoring configuration successfully detected changes to Linux identity files.



\## Security Controls Implemented



\- AWS Security Group

\- SSH key-based authentication

\- Password authentication disabled

\- Root SSH access restricted

\- UFW host firewall

\- Default-deny inbound firewall policy

\- Linux auditd monitoring

\- Identity-file monitoring

\- Privilege configuration monitoring

\- SSH configuration monitoring

\- Security event validation



\## Skills Demonstrated



\- AWS EC2 security

\- Linux system administration

\- Linux security hardening

\- SSH hardening

\- Host firewall configuration

\- Defense in depth

\- Linux auditd

\- Security monitoring

\- Log investigation

\- Identity monitoring

\- Cloud security fundamentals

\- SOC detection engineering



\## Conclusion



This hardening process established multiple defensive layers around the AWS-hosted Ubuntu server.



Network controls, secure remote administration, host firewall rules, and audit monitoring were combined to reduce attack surface while providing visibility into security-sensitive system changes.

