"""Decode and check the two optional DNS profiles; never install or change DNS."""

import ipaddress
import plistlib
from pathlib import Path
from uuid import UUID


EXPECTED = {
    "Cloudflare": (
        "https://cloudflare-dns.com/dns-query",
        {"1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"},
    ),
    "Google": (
        "https://dns.google/dns-query",
        {"8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"},
    ),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    directory = Path(__file__).resolve().parent
    seen_uuids = set()
    seen_identifiers = set()
    for provider, (endpoint, addresses) in EXPECTED.items():
        path = directory / f"VeilDNS-{provider}.mobileconfig"
        with path.open("rb") as stream:
            profile = plistlib.load(stream)
        require(profile["PayloadType"] == "Configuration", "Invalid profile type")
        require(profile["PayloadScope"] == "System", "Expected system scope")
        require(profile["PayloadRemovalDisallowed"] is False, "Removal must be allowed")
        require(len(profile["PayloadContent"]) == 1, "Only one DNS payload is allowed")
        payload = profile["PayloadContent"][0]
        require(payload["PayloadType"] == "com.apple.dnsSettings.managed", "Unexpected payload")
        require(payload.get("ProhibitDisablement", False) is False, "Disabling must be allowed")
        require(payload["OnDemandRules"] == [{"Action": "Connect"}], "Expected catch-all Connect")
        settings = payload["DNSSettings"]
        require(set(settings) == {"DNSProtocol", "ServerURL", "ServerAddresses"}, "Unexpected DNS keys")
        require(settings["DNSProtocol"] == "HTTPS", "DoH is required")
        require(settings["ServerURL"] == endpoint, "Unexpected DoH endpoint")
        require(set(settings["ServerAddresses"]) == addresses, "Unexpected bootstrap addresses")
        require(len(settings["ServerAddresses"]) == 4, "Duplicate bootstrap address")
        require({ipaddress.ip_address(address).version for address in addresses} == {4, 6}, "Both IP families required")
        for item in (profile, payload):
            require(item["PayloadVersion"] == 1, "Unexpected payload version")
            identifier = item["PayloadIdentifier"]
            uuid = UUID(item["PayloadUUID"])
            require(identifier not in seen_identifiers, "Duplicate payload identifier")
            require(uuid not in seen_uuids, "Duplicate payload UUID")
            seen_identifiers.add(identifier)
            seen_uuids.add(uuid)
        require(plistlib.loads(plistlib.dumps(profile)) == profile, "Plist round-trip failed")
        print(f"PASS {path.name}: one DoH payload, IPv4/IPv6 bootstrap, all domains, removable")
    print("Static validation only; macOS installation and effective DNS routing require a Mac.")


if __name__ == "__main__":
    main()
