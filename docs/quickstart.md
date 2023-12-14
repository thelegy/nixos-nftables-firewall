# Quickstart guide

## Installation of the module
To use the firewall you first need to load the module.
Currently only nix flakes are supported, though adding support for the traditional way should not be too difficult.

```{note}
Currently almost all of what this module does needs to be enabled first, but there is one thing, the module will do by just including it:

The module changes adds the [stopRuleset](common.md#networking-nftables-stopruleset) Option, that is required.
It will change the undelying `nftables` service, to apply this ruleset in case, that the service is stopped, or the real ruleset fails to apply.

If you forget to define it, nix will complain, when you try to build your machine.
```

Loading the module might depend on how you construct your machines configuration, but probably something along the following lines will do the trick:
```
{
  inputs.nnf.url = "github:thelegy/nixos-nftables-firewall";

  ...

  outputs = {nnf, nixpkgs, ...}: {
    nixosConfigurations.my-machine = nixpkgs.lib.nixosSystem {
      system = "...";
      modules = [
        ./configuration.nix
        nnf.nixosModules.default
      ];
    };
    ...,
  };
}
```

## Using the module
We will start using [snippets](snippets).
Snippets are very opinionated and may change in unexpected ways, though they are great for starting.
I encourage you to read through what the snippets do, you use and maybe even to copy them, so you are in control how they change.
For now we will just use them.

We will look at the following `configuration.nix´.
```
{config, ...}: {
  ...

  networking.nftables.firewall = {
    enable = true;
    snippets.nnf-common.enable = true;
```
This will enable the firewall and also the `nnf-common` snippet.

### Zones
Next we will add some [zones](zones):
```
    zones.uplink = {
      interfaces = [ "eth0" "eth1" ];
    };
    zones.local = {
      parent = "uplink";
      ipv4Addresses = [ "192.168.1.0/24" ];
    };
```
This will define the two zones `uplink` and `local`.

The `uplink` zone is defined by the interfaces `eth0` and `eth1`.
For incoming traffic this will match all traffic originating from those interfaces and for outgoing traffic it will match traffic destined to those interfaces.
You can understand that as "my communication partner is reachable via the interfaces eth0 or eth1".

The `local` zone is defined a subzone of the `uplink`, it also is defined by some ipv4 subnet.
For incoming traffic this will match all traffic that is matched by the `uplink` zone and also having a source address in the subnet, for outgoing traffic it will match traffic that is matched by the `uplink` zone and having a desination addres in the subnet.
You can unserstand that as "my communication partner already belongs to the `uplink` zone and has an ipv4 address in the subnet".

This is often all the complxity you need, but you can also do things more manually to fit your needs:

```
    zones.banned = {
      ingressExpression = [
        "ip saddr @banlist"
        "ip6 saddr @banlist6"
      ];
      egressExpression = [
        "ip daddr @banlist"
        "ip6 daddr @banlist6"
      ];
    };
```
With this example a `banned` zone is defined by manually specifying how traffic should be matched.
In this case we assume, that some nftables sets `banlist` and `banlist6` are defined and the zone matches traffic with a cummunication partner, that has a banned ip.

### Rules
Next we will add some [rules](rules):
```
    rules.http = {
      from = "all";
      to = [ "fw" ];
      allowedTCPPorts = [ 80 443 ];
    };
```
The rule `http` allows TCP traffic to port 80 and 443 from anywhere to the local machine.
(The `fw` stands for the local machine, it is short for "firewall", you can change it at the [localZoneName](common.md/#networking-nftables-firewall-localzonename) option).

This has the same effect as `networking.firewall.allowedTCPPorts = [80 443];`.
Depending on which snippets you have enabled ([nnf-nixos-firewall](snippets.md#nnf-nixos-firewall) is responsible, which is included by [nnf-common](snippets.md#nnf-common), which we have enabled), that will actually still work.

```
    rules.mqtt = {
      from = [ "local" ];
      to = [ "fw" ];
      allowedTCPPorts = [ 1883 ];
    };
```
The rule `mqtt` allows TCP traffic to port 1883 from the `local` zone to the local machine.
Here [from](rules.md/#networking-nftables-firewall-rules-name-from) is defined as a list of zones insted of the `"all"` string earlier.
Usually it is a list of zone names, but instead it can be this special value, that we have seen previous.
The same is actually possible for the [to](rules.md/#networking-nftables-firewall-rules-name-to).

```
    zones.private = {
      interfaces = [ "eth3" ];
    };
    rules.private-ssh = {
      from = "all";
      to = [ "private" ];
      allowedTCPPorts = [ 22 ];
    };
    rules.private-outgoing = {
      from = [ "private" ];
      to = [ "uplink" ];
      verdict = "accept";
    };
```
Now we define another zone `private` via the interface `eth3`.
The rule `private-ssh` allows traffic from anywhere to reach TCP port 22 in zone `private`.
So this will actually generate our first "forward" rule.

The rule `private-outgoing` also generates a "forward" rule.
With it any traffic from the "private" zone to the "uplink" zone is allowd.

It is actually possible for a rule to generate nft rules in the "input" and "forward" chains at the same time.
This can be achieved by including multiple zones in the `to` field, some being subzones of `fw` and some not.

Currently this firewall does not generate nft rules for the "output" chain, so limiting outgoing traffic from the local mache is not possible yet.

```
    rules.ban = {
      from = ["banned"];
      to = "all";
      ruleType = "ban";
      extraLines = [
        "counter drop"
      ];
    };
```
The rule `ban` is a more advanced example.
It drops any draffic, that is originated in the `banned` zone.
It also adds a counter, so we can inspect how much traffic and packets were actually dropped by it.

As it is your first rule to drop traffic instead of allow it, we finally need to think about order of rules.
For the most part we can ignore order, as traffic is matched from least specific to most specific and rules are usually applied on the way back from most specific to least specific.
Bit in this example we have a pretty generic rule, that we want to apply very early, to ensure traffic is blocked prior to all the other rules accepting the traffic.
For this there is the [ruleType](rules.md/#networking-nftables-firewall-rules-name-ruletype) option.

The actually verdict is not supplied as a `verdict = "drop"` here, but as [extraLines](rules.md/#networking-nftables-firewall-rules-name-extralines).
With it you can supply raw nft rules, that are applied to all traffic the rule affects.

```
  };
}
```
