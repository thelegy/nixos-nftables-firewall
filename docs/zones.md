# Zones
Zones define a part of network topology.
They are usually defined as a list of subnets or by a list of interfaces, though custom rules for matching traffic are possible.
There exists an implicit `all` Zone, that matches all traffic.
Traffic originating or targeting the local machine are matched by a predefined zone called `fw` (short for firewall) by default.

There exists inheritance for zones.
Each zone will automatically get the rules of its parent zone applied, after the more specific rules get applied.

## Options
%networking.nftables.firewall.zones%
