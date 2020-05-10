#!/usr/bin/env python3

import sys
import argparse
from collections import defaultdict
import logging
import typing


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-d", "--debug", action="store_true", help="Enable debug messages."
    )
    parser.add_argument(
        "input",
        action="store",
        type=argparse.FileType(mode="r"),
        help="The ifcfg-rh file (e. g. /etc/sysconfig/network-scripts/ifcfg-Ethernet)",
    )
    parser.add_argument(
        "output",
        action="store",
        type=argparse.FileType(mode="w"),
        help="The keyfile (e. g. /etc/NetworkManager/system-connections/Ethernet.nmconnection)",
    )

    return parser.parse_args()


#: List of supported sections per connection type
CONNECTION_TYPE_SECTIONS = {
    "ethernet": {"connection", "ipv4", "ipv6", "proxy"},
    "wifi": {
        "connection",
        "wifi",
        "802-11-wireless",
        "802-11-wireless-security",
        "802-1x",
        "ipv4",
        "ipv6",
        "proxy",
    },
}


PROPERTIES = {
    "connection.id": {
        "ifcfg": "NAME",
        "type": str,
        "required": True,
        "from_ifcfg": lambda v: v.strip(),
    },
    "connection.uuid": {"ifcfg": "UUID", "type": str, "required": True,},
    "connection.type": {
        "ifcfg": "TYPE",
        "type": str,
        "choices": frozenset(CONNECTION_TYPE_SECTIONS.keys()),
        "required": True,
        "from_ifcfg": lambda v: {"Ethernet": "ethernet", "Wireless": "wifi",}[v],
    },
    "connection.stable-id": {},
    "connection.interface-name": {"ifcfg": "DEVICE"},
    "connection.autoconnect": {},
    "connection.autoconnect-priority": {"type": int,},
    "connection.autoconnect-retries": {},
    "connection.multi-connect": {},
    "connection.auth-retries": {},
    "connection.timestamp": {},
    "connection.read-only": {},
    "connection.permissions": {},
    "connection.zone": {"ifcfg": "ZONE"},
    "connection.master": {},
    "connection.slave-type": {},
    "connection.autoconnect-slaves": {},
    "connection.secondaries": {},
    "connection.gateway-ping-timeout": {},
    "connection.metered": {},
    "connection.lldp": {},
    "connection.mdns": {},
    "connection.llmnr": {},
    "connection.wait-device-timeout": {},
    "ipv4.method": {"type": str, "default": "auto", "choices": {"auto"}},
    "ipv4.dns": {},
    "ipv4.dns-search": {"type": str,},
    "ipv4.dns-options": {},
    "ipv4.dns-priority": {},
    # TODO this is a list with IPADDR1, IPADDR2, ...
    "ipv4.addresses": {"ifcfg": "IPADDR"},
    "ipv4.gateway": {},
    "ipv4.routes": {},
    "ipv4.route-metric": {},
    "ipv4.route-table": {},
    "ipv4.routing-rules": {},
    "ipv4.ignore-auto-routes": {},
    "ipv4.ignore-auto-dns": {},
    "ipv4.dhcp-client-id": {},
    "ipv4.dhcp-iaid": {},
    "ipv4.dhcp-timeout": {},
    "ipv4.dhcp-send-hostname": {},
    "ipv4.dhcp-hostname": {},
    "ipv4.dhcp-fqdn": {},
    "ipv4.dhcp-hostname-flags": {},
    "ipv4.never-default": {},
    "ipv4.may-fail": {},
    "ipv4.dad-timeout": {},
    "ipv6.method": {
        "ifcfg": "IPV6_AUTOCONF",
        "type": str,
        "choices": {"auto"},
        "from_ifcfg": lambda v: "auto" if v == "yes" else None,
    },
    "ipv6.dns": {},
    "ipv6.dns-search": {"type": str,},
    "ipv6.dns-options": {},
    "ipv6.dns-priority": {},
    "ipv6.addresses": {},
    "ipv6.gateway": {},
    "ipv6.routes": {},
    "ipv6.route-metric": {},
    "ipv6.route-table": {},
    "ipv6.routing-rules": {},
    "ipv6.ignore-auto-routes": {},
    "ipv6.ignore-auto-dns": {},
    "ipv6.never-default": {},
    "ipv6.may-fail": {},
    "ipv6.ip6-privacy": {},
    "ipv6.addr-gen-mode": {
        "ifcfg": "IPV6_ADDR_GEN_MODE",
        "type": str,
        "choices": {"stable-privacy"},
    },
    "ipv6.ra-timeout": {},
    "ipv6.dhcp-duid": {},
    "ipv6.dhcp-iaid": {},
    "ipv6.dhcp-timeout": {},
    "ipv6.dhcp-send-hostname": {},
    "ipv6.dhcp-hostname": {},
    "ipv6.dhcp-hostname-flags": {},
    "ipv6.token": {},
    "802-1x.optional": {},
    "802-1x.eap": {"ifcfg": "IEEE_8021X_EAP_METHODS"},
    "802-1x.identity": {"ifcfg": "IEEE_8021X_IDENTITY"},
    "802-1x.anonymous-identity": {"ifcfg": "IEEE_8021X_ANON_IDENTITY"},
    "802-1x.pac-file": {},
    "802-1x.ca-cert": {},
    "802-1x.ca-cert-password": {},
    "802-1x.ca-cert-password-flags": {"ifcfg": "IEEE_8021X_PASSWORD_FLAGS"},
    "802-1x.ca-path": {"ifcfg": "IEEE_8021X_CA_CERT"},
    "802-1x.subject-match": {},
    "802-1x.altsubject-matches": {},
    "802-1x.domain-suffix-match": {"ifcfg": "IEEE_8021X_DOMAIN_SUFFIX_MATCH"},
    "802-1x.domain-match": {},
    "802-1x.client-cert": {},
    "802-1x.client-cert-password": {},
    "802-1x.client-cert-password-flags": {},
    "802-1x.phase1-peapver": {},
    "802-1x.phase1-peaplabel": {},
    "802-1x.phase1-fast-provisioning": {},
    "802-1x.phase1-auth-flags": {},
    "802-1x.phase2-auth": {"ifcfg": "IEEE_8021X_INNER_AUTH_METHODS"},
    "802-1x.phase2-autheap": {},
    "802-1x.phase2-ca-cert": {},
    "802-1x.phase2-ca-cert-password": {},
    "802-1x.phase2-ca-cert-password-flags": {},
    "802-1x.phase2-ca-path": {},
    "802-1x.phase2-subject-match": {},
    "802-1x.phase2-altsubject-matches": {},
    "802-1x.phase2-domain-suffix-match": {},
    "802-1x.phase2-domain-match": {},
    "802-1x.phase2-client-cert": {},
    "802-1x.phase2-client-cert-password": {},
    "802-1x.phase2-client-cert-password-flags": {},
    "802-1x.password": {},
    "802-1x.password-flags": {},
    "802-1x.password-raw": {},
    "802-1x.password-raw-flags": {},
    "802-1x.private-key": {},
    "802-1x.private-key-password": {},
    "802-1x.private-key-password-flags": {},
    "802-1x.phase2-private-key": {},
    "802-1x.phase2-private-key-password": {},
    "802-1x.phase2-private-key-password-flags": {},
    "802-1x.pin": {},
    "802-1x.pin-flags": {},
    "802-1x.system-ca-certs": {},
    "802-1x.auth-timeout": {},
    "802-3-ethernet.port": {},
    "802-3-ethernet.speed": {},
    "802-3-ethernet.duplex": {},
    "802-3-ethernet.auto-negotiate": {},
    "802-3-ethernet.mac-address": {},
    "802-3-ethernet.cloned-mac-address": {},
    "802-3-ethernet.generate-mac-address-mas": {},
    "802-3-ethernet.mac-address-blacklist": {},
    "802-3-ethernet.mtu": {},
    "802-3-ethernet.s390-subchannels": {},
    "802-3-ethernet.s390-nettype": {},
    "802-3-ethernet.s390-options": {},
    "802-3-ethernet.wake-on-lan": {},
    "802-3-ethernet.wake-on-lan-password": {},
    "802-11-wireless.ssid": {"ifcfg": "ESSID"},
    "802-11-wireless.mode": {"ifcfg": "MODE"},
    "802-11-wireless.band": {},
    "802-11-wireless.channel": {},
    "802-11-wireless.bssid": {},
    "802-11-wireless.rate": {},
    "802-11-wireless.tx-power": {},
    # TODO mac-address needs to use MACADDR but this is the same for ethernet.mac-address...
    # TODO the algorithm does not work. We need to dymacially resolve all values using all other values
    # TODO maybe we have to determine global vars that won't be used in the output config as "foobar_enabled"
    "802-11-wireless.mac-address": {},
    "802-11-wireless.cloned-mac-address": {},
    "802-11-wireless.generate-mac-address-mask": {},
    "802-11-wireless.mac-address-blacklist": {},
    "802-11-wireless.mac-address-randomization": {"ifcfg": "MAC_ADDRESS_RANDOMIZATION"},
    "802-11-wireless.mtu": {},
    "802-11-wireless.seen-bssids": {},
    "802-11-wireless.hidden": {},
    "802-11-wireless.powersave": {},
    "802-11-wireless.wake-on-wlan": {},
    "802-11-wireless-security.key-mgmt": {"ifcfg": "KEY_MGMT"},
    "802-11-wireless-security.wep-tx-keyidx": {},
    "802-11-wireless-security.auth-alg": {},
    "802-11-wireless-security.proto": {},
    "802-11-wireless-security.pairwise": {},
    "802-11-wireless-security.group": {},
    "802-11-wireless-security.pmf": {},
    "802-11-wireless-security.leap-username": {},
    "802-11-wireless-security.wep-key0": {},
    "802-11-wireless-security.wep-key1": {},
    "802-11-wireless-security.wep-key2": {},
    "802-11-wireless-security.wep-key3": {},
    "802-11-wireless-security.wep-key-flags": {},
    "802-11-wireless-security.wep-key-type": {},
    "802-11-wireless-security.psk": {},
    "802-11-wireless-security.psk-flags": {"ifcfg": "WPA_PSK_FLAGS"},
    "802-11-wireless-security.leap-password": {},
    "802-11-wireless-security.leap-password-flags": {},
    "802-11-wireless-security.wps-method": {},
    "802-11-wireless-security.fils": {},
    "proxy.method": {"type": str, "choices": [],},
    "proxy.browser-only": {},
    "proxy.pac-url": {},
    "proxy.pac-script": {},
}

# TODO some of them have to be implemented
IGNORE_PROPERTIES = {
    "BOOTPROTO",
    "BROWSER_ONLY",
    "DEFROUTE",
    "ETHTOOL_OPTS",
    "IPV4_FAILURE_FATAL",
    "IPV6INIT",
    "IPV6_DEFROUTE",
    "IPV6_FAILURE_FATAL",
    "ONBOOT",
    "SECURITYMODE",
    "USERS",
}


def get_ifcfg_name(prop_name, settings) -> str:
    if "ifcfg" in settings:
        return settings["ifcfg"]

    else:
        return prop_name.replace(".", "_").upper()


KEY_CONVERSION_MAP = {
    get_ifcfg_name(prop_name, settings): prop_name
    for prop_name, settings in PROPERTIES.items()
}

DEFAULT_PARAMS = {
    prop_name: settings["default"]
    for prop_name, settings in PROPERTIES.items()
    if "default" in settings
}


def default_from_ifcfg(value: str) -> typing.Optional[str]:
    """The default conversion function to get the keyfile property from the ifcfg property."""

    value = value.strip().lower()

    if value == "none":
        return None

    return value


def parse_ifcfg(config: str) -> typing.Dict[str, typing.Union[str, int, bool]]:
    params_raw: typing.Dict[str, str] = {}

    for line in config.splitlines():
        if line.lstrip().startswith("#"):
            continue

        try:
            prop, value = line.split("=", 1)
        except ValueError as err:
            logging.warning("Invalid line %s: %s", line, str(err))

            continue

        if prop in IGNORE_PROPERTIES:
            logging.warning("Ignoring property %s.", prop)

            continue

        key_file_prop_name = KEY_CONVERSION_MAP.get(prop)

        if not key_file_prop_name:
            logging.error(
                "Invalid or unsupported (read: not implemented) property %s.", prop
            )
            sys.exit(1)

        params_raw[key_file_prop_name] = value

    if "connection.type" not in params_raw:
        logging.error(
            'Could not get connection type. Missing property "TYPE" in ifcfg file.'
        )
        sys.exit(1)

    connection_type = PROPERTIES["connection.type"]["from_ifcfg"](
        params_raw["connection.type"]
    )

    if connection_type not in PROPERTIES["connection.type"]["choices"]:
        logging.error(
            "Invalid or unsupported (read: not implemented) connection type %s.",
            connection_type,
        )
        sys.exit(1)

    params_cleaned: typing.Dict[str, typing.Union[str, int, bool]] = DEFAULT_PARAMS

    for prop, value in params_raw.items():
        section = prop.split(".", 1)[0]

        if section not in CONNECTION_TYPE_SECTIONS[connection_type]:
            logging.error(
                "Invalid or unsupported (read: not implemented) property for connection type %s: %s.",
                connection_type,
                prop,
            )
            sys.exit(1)

        settings = PROPERTIES[prop]
        logging.debug("%s: Value read from ifcfg:\t %s", prop, value)
        value = settings.get("from_ifcfg", default_from_ifcfg)(value)
        logging.debug("%s: Value after converting it:\t %s", prop, value)

        if value is None:
            logging.debug("%s: Skipping empty value.", prop)

            continue

        value = settings.get("type", str)(value)
        logging.debug("%s: Value after converting type:\t %s", prop, repr(value))
        params_cleaned[prop] = value

    # check required params
    required_params = {
        param
        for param, settings in PROPERTIES.items()
        if settings.get("required")
        and param.split(".", 1)[0] in CONNECTION_TYPE_SECTIONS[connection_type]
    }

    for param in required_params:
        if param not in params_cleaned:
            logging.error("Required parameter %s not set.", param)
            sys.exit(1)

    return params_cleaned


def dump_keyfile(params: typing.Dict[str, typing.Union[str, int, bool]]) -> str:
    connection_type: str = params["connection.type"]
    params_by_section = defaultdict(dict)

    for param, value in params.items():
        section, param_name = param.split(".", 1)
        params_by_section[section][param_name] = value

    key_file_lines = []

    for section in CONNECTION_TYPE_SECTIONS[connection_type]:
        if section in params_by_section:
            key_file_lines.append(f"[{section}]")

            for param, value in params_by_section[section].items():
                key_file_lines.append(f"{param}={value}")

            key_file_lines.append("")

    return "\n".join(key_file_lines)


def main():
    args = parse_args()
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO)
    ifcfg: str = args.input.read()
    args.input.close()
    config = parse_ifcfg(ifcfg)
    keyfile_config: str = dump_keyfile(config)
    logging.info(f"Writing config to {args.output.name}.")
    args.output.write(keyfile_config)


if __name__ == "__main__":
    main()
