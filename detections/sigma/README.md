title: SSH Brute Force Detection
id: ssh-bruteforce-001
status: experimental
description: Detects multiple failed SSH login attempts within a short timeframe
author: Dereje Deressa
logsource:
  product: linux
  service: auth
detection:
  selection:
    message|contains: "Failed password"
  timeframe: 5m
  condition: selection | count() by src_ip > 5
fields:
  - src_ip
falsepositives:
  - Users mistyping passwords
level: medium
tags:
  - attack.T1110
