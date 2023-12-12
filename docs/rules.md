# Rules
Rules define what should happen with the trafiic matched by the zones.
Each rule has a list of `from` zones and `to` zones.
A rule only gets applied, if the traffic in question originated in one of the `from` zones and is heading to one of the `to` zones.

If matched, the rule can define ports to open, a terminating `verdict` or any custom `nft` rules by using `extraLines`.

Rules are applied from most specific to least specific, traversing the `from` side before the `to` side.
To allow for more complex setups (mostly custom drop/reject rules) rules are applied in multipe passes.
Each `rule` has a `ruleType`.
Rules are gruped by their type and applied in these groups, so that all rules are applied for the first type, before rules of the next type are taken into consideration.

## Options
%networking.nftables.firewall.rules%
