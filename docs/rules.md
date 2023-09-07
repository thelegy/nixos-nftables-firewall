# Rules
Rules define what should happen with the trafiic matched by the zones.
Each rule has a list of `from` zones and `to` zones.
A rule only gets applied, if the traffic in question originated in one of the `from` zones and is heading to one of the `to` zones.

If matched, the rule can define ports to open, a terminating `verdict` or any custom `nft` rules by using `extraLines`.

Rules are applied from most specific to least specific, traversing the `from` side before the `to` side.
To allow for more complex setups (mostly custom drop/reject rules) rules are applied in two passes.
First all rules with the `ruleType` of `rule` get applied, and after that all with a type of `policy`.

## Options
%networking.nftables.firewall.rules%
