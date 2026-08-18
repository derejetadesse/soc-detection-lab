\# 🚨 SOC Incident Report — Linux Account Creation Detection



\## Incident Summary



A controlled security event was generated on an AWS-hosted Ubuntu Linux server to validate host-based identity monitoring using Linux `auditd`.



A temporary Linux user account named `phase4test` was created. The audit subsystem successfully detected modifications to critical identity files and recorded the process responsible for the changes.



\## Environment



\- Platform: Amazon Web Services (AWS)

\- Service: Amazon EC2

\- Operating System: Ubuntu Linux

\- Security Monitoring: Linux auditd

\- Investigation Tool: ausearch

\- Detection Category: Identity / Account Management



\## Detection Rule



The following audit rules monitored changes to Linux identity files:



```bash

\-w /etc/passwd -p wa -k identity\_changes

\-w /etc/group -p wa -k identity\_changes

