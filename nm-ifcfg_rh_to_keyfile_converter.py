#!/usr/bin/env python3
"""
Convert nm-settings-ifcfg-rh settings files to nm-settings (e. g. in keyfile format).

This is not a complete implementation but a MVP.
It may also differ from specification,
because I just wanted to implement it so that it "works for me".
Most things to know are documented here:
https://developer.gnome.org/NetworkManager/stable/nm-settings-ifcfg-rh.html
"""

import argparse
import ipaddress
import logging
import re
import sys
import typing
from collections import defaultdict

KEYFILE_SCALAR_VALUE_TYPE = typing.Union[str, int, bool]
KEYFILE_VALUE_TYPE = typing.Union[
    KEYFILE_SCALAR_VALUE_TYPE, typing.List[KEYFILE_SCALAR_VALUE_TYPE]
]
KEYFILE_CONFIG_TYPE = typing.Dict[str, KEYFILE_VALUE_TYPE]
JOB_QUEUE_TYPE = typing.List[
    typing.Callable[[KEYFILE_CONFIG_TYPE, "JOB_QUEUE_TYPE"], None]
]


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


JOB_QUEUE_RETRY_LIMIT = 5

#: List of supported sections per connection type
CONNECTION_TYPE_SECTIONS = {
    "ethernet": ("connection", "802-3-ethernet", "ipv4", "ipv6", "proxy"),
    "wifi": (
        "connection",
        "wifi",
        "802-11-wireless",
        "802-11-wireless-security",
        "802-1x",
        "ipv4",
        "ipv6",
        "proxy",
    ),
    "bridge": ("connection", "ipv4", "ipv6", "bridge", "proxy"),
}


def validate_assigned_mac_address(prop, value):
    choices = {"preserve", "permanent", "random", "stable"}

    if value in choices:
        return

    if re.match(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", value):
        return

    raise ValueError(
        f"Invalid value '%s' for %s: It must be either a MAC address or one of {', '.join(choices)}"
    )


NM_SETTINGS_SECRET_FLAG_TYPES = {
    "none": 0,
    "agent-owned": 1,
    "not-saved": 2,
    "not-required": 4,
}

NM_SETTINGS_PROPERTIES: typing.Dict[str, typing.Dict[str, typing.Any]] = {
    "connection.id": {"type": str, "required": True,},
    "connection.uuid": {"type": str, "required": True,},
    "connection.type": {
        "type": str,
        "choices": frozenset(CONNECTION_TYPE_SECTIONS.keys()),
        "required": True,
    },
    "connection.stable-id": {},
    "connection.interface-name": {},
    "connection.autoconnect": {"type": bool, "default": True,},
    "connection.autoconnect-priority": {"type": int,},
    "connection.autoconnect-retries": {},
    "connection.multi-connect": {},
    "connection.auth-retries": {},
    "connection.timestamp": {},
    "connection.read-only": {},
    "connection.permissions": {"typing": list, "list_type": str},
    "connection.zone": {},
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
    "ipv4.method": {
        "type": str,
        "default": "auto",
        "choices": {"auto", "disabled", "link-local", "manual", "shared"},
    },
    "ipv4.dns": {},
    "ipv4.dns-search": {"type": str,},
    "ipv4.dns-options": {},
    "ipv4.dns-priority": {"type": int},
    "ipv4.addresses": {"type": list, "list_type": str},
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
    "ipv4.never-default": {"type": bool, "default": False,},
    "ipv4.may-fail": {"type": bool,},
    "ipv4.dad-timeout": {},
    "ipv6.method": {
        "type": str,
        "choices": {
            "auto",
            "dhcp",
            "disabled",
            "ignore",
            "link-local",
            "manual",
            "shared",
        },
        "required": True,
        "default": "auto",
    },
    "ipv6.dns": {},
    "ipv6.dns-search": {"type": str,},
    "ipv6.dns-options": {},
    "ipv6.dns-priority": {"type": int},
    "ipv6.addresses": {},
    "ipv6.gateway": {},
    "ipv6.routes": {},
    "ipv6.route-metric": {},
    "ipv6.route-table": {},
    "ipv6.routing-rules": {},
    "ipv6.ignore-auto-routes": {},
    "ipv6.ignore-auto-dns": {},
    "ipv6.never-default": {"type": bool, "default": False,},
    "ipv6.may-fail": {"type": bool,},
    "ipv6.ip6-privacy": {},
    "ipv6.addr-gen-mode": {"type": str, "choices": {"stable-privacy"},},
    "ipv6.ra-timeout": {},
    "ipv6.dhcp-duid": {},
    "ipv6.dhcp-iaid": {},
    "ipv6.dhcp-timeout": {},
    "ipv6.dhcp-send-hostname": {},
    "ipv6.dhcp-hostname": {},
    "ipv6.dhcp-hostname-flags": {},
    "ipv6.token": {},
    "802-1x.optional": {},
    "802-1x.eap": {"type": list, "list_type": str,},
    "802-1x.identity": {},
    "802-1x.anonymous-identity": {},
    "802-1x.pac-file": {},
    "802-1x.ca-cert": {},
    "802-1x.ca-cert-password": {},
    "802-1x.ca-cert-password-flags": {
        "choices": frozenset(NM_SETTINGS_SECRET_FLAG_TYPES.keys()),
        "format_for_keyfile": lambda v: NM_SETTINGS_SECRET_FLAG_TYPES[v],
    },
    "802-1x.ca-path": {},
    "802-1x.subject-match": {},
    "802-1x.altsubject-matches": {},
    "802-1x.domain-suffix-match": {},
    "802-1x.domain-match": {},
    "802-1x.client-cert": {},
    "802-1x.client-cert-password": {},
    "802-1x.client-cert-password-flags": {
        "choices": frozenset(NM_SETTINGS_SECRET_FLAG_TYPES.keys()),
        "format_for_keyfile": lambda v: NM_SETTINGS_SECRET_FLAG_TYPES[v],
    },
    "802-1x.phase1-peapver": {},
    "802-1x.phase1-peaplabel": {},
    "802-1x.phase1-fast-provisioning": {},
    "802-1x.phase1-auth-flags": {
        "choices": frozenset(NM_SETTINGS_SECRET_FLAG_TYPES.keys()),
        "format_for_keyfile": lambda v: NM_SETTINGS_SECRET_FLAG_TYPES[v],
    },
    "802-1x.phase2-auth": {},
    "802-1x.phase2-autheap": {},
    "802-1x.phase2-ca-cert": {},
    "802-1x.phase2-ca-cert-password": {},
    "802-1x.phase2-ca-cert-password-flags": {
        "choices": frozenset(NM_SETTINGS_SECRET_FLAG_TYPES.keys()),
        "format_for_keyfile": lambda v: NM_SETTINGS_SECRET_FLAG_TYPES[v],
    },
    "802-1x.phase2-ca-path": {},
    "802-1x.phase2-subject-match": {},
    "802-1x.phase2-altsubject-matches": {},
    "802-1x.phase2-domain-suffix-match": {},
    "802-1x.phase2-domain-match": {},
    "802-1x.phase2-client-cert": {},
    "802-1x.phase2-client-cert-password": {},
    "802-1x.phase2-client-cert-password-flags": {
        "choices": frozenset(NM_SETTINGS_SECRET_FLAG_TYPES.keys()),
        "format_for_keyfile": lambda v: NM_SETTINGS_SECRET_FLAG_TYPES[v],
    },
    "802-1x.password": {},
    "802-1x.password-flags": {
        "choices": frozenset(NM_SETTINGS_SECRET_FLAG_TYPES.keys()),
        "format_for_keyfile": lambda v: NM_SETTINGS_SECRET_FLAG_TYPES[v],
    },
    "802-1x.password-raw": {},
    "802-1x.password-raw-flags": {},
    "802-1x.private-key": {},
    "802-1x.private-key-password": {},
    "802-1x.private-key-password-flags": {
        "choices": frozenset(NM_SETTINGS_SECRET_FLAG_TYPES.keys()),
        "format_for_keyfile": lambda v: NM_SETTINGS_SECRET_FLAG_TYPES[v],
    },
    "802-1x.phase2-private-key": {},
    "802-1x.phase2-private-key-password": {},
    "802-1x.phase2-private-key-password-flags": {
        "choices": frozenset(NM_SETTINGS_SECRET_FLAG_TYPES.keys()),
        "format_for_keyfile": lambda v: NM_SETTINGS_SECRET_FLAG_TYPES[v],
    },
    "802-1x.pin": {},
    "802-1x.pin-flags": {
        "choices": frozenset(NM_SETTINGS_SECRET_FLAG_TYPES.keys()),
        "format_for_keyfile": lambda v: NM_SETTINGS_SECRET_FLAG_TYPES[v],
    },
    "802-1x.system-ca-certs": {},
    "802-1x.auth-timeout": {},
    "802-3-ethernet.port": {},
    "802-3-ethernet.speed": {},
    "802-3-ethernet.duplex": {},
    "802-3-ethernet.auto-negotiate": {"type": bool, "default": False,},
    "802-3-ethernet.assigned-mac-address": {
        "type": str,
        "validate": validate_assigned_mac_address,
    },
    "802-3-ethernet.mac-address": {},
    "802-3-ethernet.cloned-mac-address": {"deprecated": True,},
    "802-3-ethernet.generate-mac-address-mas": {},
    "802-3-ethernet.mac-address-blacklist": {},
    "802-3-ethernet.mtu": {},
    "802-3-ethernet.s390-subchannels": {},
    "802-3-ethernet.s390-nettype": {},
    "802-3-ethernet.s390-options": {},
    "802-3-ethernet.wake-on-lan": {},
    "802-3-ethernet.wake-on-lan-password": {},
    "802-11-wireless.ssid": {},
    "802-11-wireless.mode": {
        "choices": {"infrastructure", "mesh", "adhoc", "ap"},
        "default": "infrastructure",
    },
    "802-11-wireless.band": {},
    "802-11-wireless.channel": {},
    "802-11-wireless.bssid": {},
    "802-11-wireless.rate": {},
    "802-11-wireless.tx-power": {},
    "802-11-wireless.assigned-mac-address": {
        "type": str,
        "validate": validate_assigned_mac_address,
    },
    "802-11-wireless.mac-address": {},
    "802-11-wireless.cloned-mac-address": {"deprecated": True,},
    "802-11-wireless.generate-mac-address-mask": {},
    "802-11-wireless.mac-address-blacklist": {},
    "802-11-wireless.mac-address-randomization": {
        "choices": {"default", "never", "always"},
        "deprecated": True,
        "format_for_keyfile": lambda v: {"default": 0, "never": 1, "always": 2,}[v],
    },
    "802-11-wireless.mtu": {},
    "802-11-wireless.seen-bssids": {},
    "802-11-wireless.hidden": {},
    "802-11-wireless.powersave": {},
    "802-11-wireless.wake-on-wlan": {},
    "802-11-wireless-security.key-mgmt": {
        "choices": {"ieee8021x", "none", "owe", "sae", "wpa-eap", "wpa-psk"},
    },
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
    "802-11-wireless-security.wep-key-flags": {
        "choices": frozenset(NM_SETTINGS_SECRET_FLAG_TYPES.keys()),
        "format_for_keyfile": lambda v: NM_SETTINGS_SECRET_FLAG_TYPES[v],
    },
    "802-11-wireless-security.wep-key-type": {},
    "802-11-wireless-security.psk": {},
    "802-11-wireless-security.psk-flags": {
        "choices": frozenset(NM_SETTINGS_SECRET_FLAG_TYPES.keys()),
        "format_for_keyfile": lambda v: NM_SETTINGS_SECRET_FLAG_TYPES[v],
    },
    "802-11-wireless-security.leap-password": {},
    "802-11-wireless-security.leap-password-flags": {
        "choices": frozenset(NM_SETTINGS_SECRET_FLAG_TYPES.keys()),
        "format_for_keyfile": lambda v: NM_SETTINGS_SECRET_FLAG_TYPES[v],
    },
    "802-11-wireless-security.wps-method": {},
    "802-11-wireless-security.fils": {},
    "proxy.method": {
        "type": str,
        "choices": {"auto", "none"},
        "format_for_keyfile": lambda v: {"auto": 1, "none": 0,}[v],
    },
    "proxy.browser-only": {"type": bool,},
    "proxy.pac-url": {},
    "proxy.pac-script": {},
    "bridge.ageing-time": {},
    "bridge.forward-delay": {},
    "bridge.group-address": {},
    "bridge.group-forward-mask": {},
    "bridge.hello-time": {},
    "bridge.interface-name": {},
    "bridge.mac-address": {},
    "bridge.max-age": {},
    "bridge.multicast-querier": {},
    "bridge.multicast-query-use-ifaddr": {},
    "bridge.multicast-router": {},
    "bridge.multicast-snooping": {},
    "bridge.priority": {},
    "bridge.stp": {"type": bool,},
    "bridge.vlan-default-pvid": {},
    "bridge.vlan-filtering": {},
    "bridge.vlan-protocol": {},
    "bridge.vlan-stats-enabled": {},
    "bridge.vlans": {},
}


KEYFILE_SECTION_NAMES = {
    "802-11-wireless": "wifi",
    "802-11-wireless-security": "wifi-security",
    "802-1x": "802-1x",
    "802-3-ethernet": "ethernet",
    "bridge": "bridge",
    "connection": "connection",
    "ipv4": "ipv4",
    "ipv6": "ipv6",
    "proxy": "proxy",
    "wifi": "wifi",
}


YES_NO_CONVERSION_MAP = {
    "yes": True,
    "no": False,
}
SECRET_FLAGS_CONVERSION_MAP = {
    "user": "agent-owned",
    "ask": "not-saved",
}


def set_list(
    keyfile_property: str,
    value: KEYFILE_VALUE_TYPE,
    keyfile_config: KEYFILE_CONFIG_TYPE,
    index: int,
) -> None:
    if keyfile_property in keyfile_config:
        prop_lst = keyfile_config[keyfile_property]
        assert isinstance(
            prop_lst, list
        ), f"Expected property {prop_lst} to be a list, but it is a {type(prop_lst).__name__}: {prop_lst}."
        prop_lst.extend([None] * (1 + index - len(prop_lst)))
        prop_lst[index] = value
    else:
        keyfile_config[keyfile_property] = [value]


def action_ignore(
    prop: str,
    value: str,
    keyfile_config: KEYFILE_CONFIG_TYPE,
    index: typing.Optional[int] = None,
    job_queue: JOB_QUEUE_TYPE = [],
) -> None:
    logging.warning("Ignoring %s=%s", prop, value)


class ActionSetProperty:
    def __init__(
        self,
        keyfile_property_name: str,
        conversion_map: typing.Optional[typing.Dict[str, KEYFILE_VALUE_TYPE]] = None,
    ):
        self.keyfile_property_name = keyfile_property_name
        self.conversion_map = conversion_map

    def __call__(
        self,
        prop: str,
        value: str,
        keyfile_config: KEYFILE_CONFIG_TYPE,
        index: typing.Optional[int],
        job_queue: JOB_QUEUE_TYPE = [],
    ) -> None:
        # determine target_type
        target_type = NM_SETTINGS_PROPERTIES[self.keyfile_property_name].get(
            "type", str
        )

        if target_type == list:
            target_type = NM_SETTINGS_PROPERTIES[self.keyfile_property_name].get(
                "list_type", str
            )

            if index is None:
                logging.error(
                    "Index is missing for property %s, which is of type list of %s.",
                    prop,
                    target_type.__name__,
                )

        # convert value and convert it to target type
        value_converted: KEYFILE_SCALAR_VALUE_TYPE

        if self.conversion_map is not None:
            try:
                value_converted = target_type(self.conversion_map[value])
            except KeyError:
                logging.error(
                    "Invalid or unknown value %s for property %s.", value, prop
                )
                sys.exit(1)
        else:
            value_converted = target_type(value)

        # set value

        if index is not None:
            set_list(self.keyfile_property_name, value_converted, keyfile_config, index)
        else:
            keyfile_config[self.keyfile_property_name] = value_converted


class ActionSetPropertyWhen:
    def __init__(
        self, condition: str, keyfile_property_name: str, value: KEYFILE_VALUE_TYPE,
    ):
        self.condition = condition
        self.value = value
        self.action_set_property = ActionSetProperty(keyfile_property_name)

    def __call__(
        self,
        prop: str,
        value: str,
        keyfile_config: KEYFILE_CONFIG_TYPE,
        index: typing.Optional[int],
        job_queue: JOB_QUEUE_TYPE = [],
    ) -> None:
        if value != self.condition:
            logging.debug(
                "Ignoring %s=%s as %s != %s", prop, value, value, self.condition
            )

            return

        self.action_set_property(prop, self.value, keyfile_config, index, job_queue)


def action_prefix(
    prop: str,
    value: str,
    keyfile_config: KEYFILE_CONFIG_TYPE,
    index: typing.Optional[int] = None,
    job_queue: JOB_QUEUE_TYPE = [],
) -> None:
    assert index is not None
    netmask = 32 - int(value)

    def action(keyfile_config: KEYFILE_CONFIG_TYPE, job_queue: JOB_QUEUE_TYPE,) -> None:
        ip_addr_lst = keyfile_config["ipv4.addresses"]
        assert isinstance(ip_addr_lst, list)

        if ip_addr_lst and len(ip_addr_lst) > index and ip_addr_lst[index] is not None:
            ip_addr_str = ip_addr_lst[index]
            ip_addr = ipaddress.IPv4Interface(f"{ip_addr_str}/{netmask}")
            ip_addr_lst[index] = str(ip_addr)
        else:
            job_queue.append(action)

    action(keyfile_config, job_queue)


def action_ethtool_opts(
    prop: str,
    value: str,
    keyfile_config: KEYFILE_CONFIG_TYPE,
    index: typing.Optional[int] = None,
    job_queue: JOB_QUEUE_TYPE = [],
) -> None:
    #  def remove_auto_negotiate_if_not_ethernet(
    #      keyfile_config: KEYFILE_CONFIG_TYPE, job_queue: JOB_QUEUE_TYPE,
    #  ) -> None:
    #      print(keyfile_config["connection.type"])
    #      if "connection.type" in keyfile_config:
    #          if keyfile_config["connection.type"] != "ethernet":
    #              logging.info("Removing superflous autonegotiation setting as type is not ethernet")
    #              keyfile_config.pop("802-3-ethernet.auto-negotiate")
    #      else:
    #          job_queue.append(remove_auto_negotiate_if_not_ethernet)

    # "speed" and "duplex" may also occur

    if value == "autoneg on":
        keyfile_config["802-3-ethernet.auto-negotiate"] = True
        #  job_queue.append(remove_auto_negotiate_if_not_ethernet)
    elif value == "autoneg off":
        keyfile_config["802-3-ethernet.auto-negotiate"] = False
        #  job_queue.append(remove_auto_negotiate_if_not_ethernet)
    else:
        logging.error("Unsupported value %s for %s", value, prop)


def action_users(
    prop: str,
    value: str,
    keyfile_config: KEYFILE_CONFIG_TYPE,
    index: typing.Optional[int] = None,
    job_queue: JOB_QUEUE_TYPE = [],
) -> None:
    users = value.split(":")  # TODO how can you specify multiple users?
    keyfile_config["connection.permissions"] = [f"user:{user}" for user in users]


def action_macaddr(
    prop: str,
    value: str,
    keyfile_config: KEYFILE_CONFIG_TYPE,
    index: typing.Optional[int] = None,
    job_queue: JOB_QUEUE_TYPE = [],
) -> None:
    def action(keyfile_config: KEYFILE_CONFIG_TYPE, job_queue: JOB_QUEUE_TYPE,) -> None:
        if "connection.type" in keyfile_config:
            connection_type = keyfile_config["connection.type"]

            if connection_type == "ethernet":
                keyfile_config["802-3-ethernet.mac-address"] = value
            elif connection_type == "wifi":
                keyfile_config["802-11-wireless.mac-address"] = value
            else:
                logging.error(
                    "Unsupported prop %s for connection type %s", prop, connection_type
                )
        else:
            job_queue.append(action)

    action(keyfile_config, job_queue)


IFCFG_PROPERTIES = {
    "BOOTPROTO": {
        "action": ActionSetProperty(
            "ipv4.method",
            {
                "none": "manual",  # or disabled?
                "dhcp": "auto",
                #  "bootp": None,  # not supported
                "static": "manual",
                #  "ibft": None,  # not supported
                "autoip": "link-local",
                "shared": "shared",
            },
        ),
    },
    "BROWSER_ONLY": {
        "action": ActionSetProperty("proxy.browser-only", YES_NO_CONVERSION_MAP),
    },
    "DEFROUTE": {
        "action": ActionSetProperty("ipv4.never-default", {"yes": False, "no": True,}),
    },
    "DEVICE": {"action": ActionSetProperty("connection.interface-name"),},
    "ESSID": {"action": ActionSetProperty("802-11-wireless.ssid"),},
    "ETHTOOL_OPTS": {"action": action_ethtool_opts},
    "GATEWAY": {"action": ActionSetProperty("ipv4.gateway")},
    "IPV6_DEFAULTGW": {"action": ActionSetProperty("ipv6.gateway")},
    "IEEE_8021X_ANON_IDENTITY": {
        "action": ActionSetProperty("802-1x.anonymous-identity"),
    },
    "IEEE_8021X_CA_CERT": {"action": ActionSetProperty("802-1x.ca-cert"),},
    "IEEE_8021X_DOMAIN_SUFFIX_MATCH": {
        "action": ActionSetProperty("802-1x.domain-suffix-match"),
    },
    "IEEE_8021X_EAP_METHODS": {
        "action": ActionSetProperty(
            "802-1x.eap",
            {
                "FAST": "fast",
                "LEAP": "leap",
                "PEAP": "peap",
                "PWD": "pwd",
                "TLS": "tls",
                "TTLS": "ttls",
            },
        ),
        "list": True,
    },
    "IEEE_8021X_IDENTITY": {"action": ActionSetProperty("802-1x.identity"),},
    "IEEE_8021X_INNER_AUTH_METHODS": {
        "action": ActionSetProperty(
            "802-1x.phase2-auth",
            {
                "CHAP": "chap",
                "GTC": "gtc",
                "MD5": "md5",
                "MSCHAP": "mschap",
                "MSCHAPV2": "mschapv2",
                "OTP": "otp",
                "PAP": "pap",
                "TLS": "tls",
            },
        ),
    },
    "IEEE_8021X_PASSWORD_FLAGS": {
        "action": ActionSetProperty(
            "802-1x.password-flags", SECRET_FLAGS_CONVERSION_MAP,
        ),
    },
    "IPADDR": {"action": ActionSetProperty("ipv4.addresses"), "list": True,},
    "IPV6ADDR": {"action": ActionSetProperty("ipv6.addresses")},
    #  "IPV4_DNS_PRIORITY": {"100"},
    "IPV4_FAILURE_FATAL": {
        "action": ActionSetProperty("ipv4.may-fail", {"yes": False, "no": True,}),
    },
    "IPV6_ADDR_GEN_MODE": {"action": ActionSetProperty("ipv6.addr-gen-mode"),},
    "IPV6_AUTOCONF": {"action": ActionSetPropertyWhen("yes", "ipv6.method", "auto")},
    "IPV6_DISABLED": {
        "action": ActionSetPropertyWhen("yes", "ipv6.method", "disabled")
    },
    "DHCPV6C": {"action": ActionSetPropertyWhen("yes", "ipv6.method", "dhcp")},
    "IPV6_DEFROUTE": {
        "action": ActionSetProperty("ipv6.never-default", {"yes": False, "no": True,}),
    },
    #  "IPV6_DNS_PRIORITY": {"100"},
    "IPV6_FAILURE_FATAL": {
        "action": ActionSetProperty("ipv6.may-fail", {"yes": False, "no": True,}),
    },
    "IPV6INIT": {"action": ActionSetPropertyWhen("no", "ipv6.method", "ignore")},
    "KEY_MGMT": {
        "action": ActionSetProperty(
            "802-11-wireless-security.key-mgmt",
            {"WPA-PSK": "wpa-psk", "WPA-EAP": "wpa-eap",},
        ),
    },
    "MACADDR": {"action": action_macaddr,},
    "MAC_ADDRESS_RANDOMIZATION": {
        "action": ActionSetProperty("802-11-wireless.mac-address-randomization"),
    },
    "MODE": {
        "action": ActionSetProperty(
            "802-11-wireless.mode", {"Managed": "infrastructure", "Ad-Hoc": "adhoc",}
        ),
    },
    "NAME": {"action": ActionSetProperty("connection.id")},
    "ONBOOT": {
        "action": ActionSetProperty("connection.autoconnect", YES_NO_CONVERSION_MAP)
    },
    "PREFIX": {"action": action_prefix, "list": True,},
    "PROXY_METHOD": {"action": ActionSetProperty("proxy.method")},
    "SECURITYMODE": {"action": ActionSetProperty("802-11-wireless-security.auth-alg"),},
    "STP": {"action": ActionSetProperty("bridge.stp", YES_NO_CONVERSION_MAP),},
    "TYPE": {
        "action": ActionSetProperty(
            "connection.type",
            {"Bridge": "bridge", "Ethernet": "ethernet", "Wireless": "wifi",},
        ),
    },
    "USERS": {"action": action_users,},
    "UUID": {"action": ActionSetProperty("connection.uuid"),},
    "WPA_PSK_FLAGS": {
        "action": ActionSetProperty(
            "802-11-wireless-security.psk-flags", SECRET_FLAGS_CONVERSION_MAP,
        ),
    },
    "ZONE": {"action": ActionSetProperty("connection.zone")},
    "IPV4_DNS_PRIORITY": {"action": ActionSetProperty("ipv4.dns-priority")},
    "IPV6_DNS_PRIORITY": {"action": ActionSetProperty("ipv6.dns-priority")},
}


IFCFG_LIST_PROPS = {
    prop for prop, setting in IFCFG_PROPERTIES.items() if setting.get("list")
}


def parse_ifcfg(config: str) -> KEYFILE_CONFIG_TYPE:
    keyfile_config: KEYFILE_CONFIG_TYPE = {}
    job_queue: JOB_QUEUE_TYPE = []

    for line in config.splitlines():
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        try:
            prop, value = line.split("=", 1)
        except ValueError as err:
            logging.warning("Invalid line %s: %s", line, str(err))

            continue

        # evaluate lists

        if any(
            prop.startswith(ifcfg_list_prop) for ifcfg_list_prop in IFCFG_LIST_PROPS
        ):
            # strip numbers on the right side if type is an list (e. g. IPADDR, IPADDR1)
            prop_name = prop.rstrip("1234567890")
            index: typing.Optional[int] = int(prop[len(prop_name) :] or 0)
            prop = prop_name
        else:
            index = None

        # unwrap enquoted values

        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]

        ifcfg_property = IFCFG_PROPERTIES.get(prop)

        if not ifcfg_property:
            logging.warning(
                "Invalid or unsupported (read: not implemented) ifcfg property %s=%s.",
                prop,
                value,
            )

            continue

        logging.debug(
            "Dispatching action with params (%r, %r, %r, %r, %r)",
            prop,
            value,
            keyfile_config,
            index,
            job_queue,
        )
        ifcfg_property.get("action", action_ignore)(
            prop, value, keyfile_config, index, job_queue
        )

    # running delayed jobs

    for i in range(JOB_QUEUE_RETRY_LIMIT):
        if job_queue:
            new_job_queue: JOB_QUEUE_TYPE = []

            for action in job_queue:
                logging.debug(
                    "Dispatching queued action with params (%r, %r)",
                    keyfile_config,
                    new_job_queue,
                )
                action(keyfile_config, new_job_queue)

            job_queue = new_job_queue

    if job_queue:
        logging.error("Reached maximum job queue limit. Config may not be complete.")

    return keyfile_config


def validate_keyfile_config(keyfile_config: KEYFILE_CONFIG_TYPE) -> None:
    if "connection.type" not in keyfile_config:
        logging.error(
            'Could not get connection type. Missing property "TYPE" in ifcfg file.'
        )
        sys.exit(1)

    connection_type: str = keyfile_config["connection.type"]

    if connection_type not in NM_SETTINGS_PROPERTIES["connection.type"]["choices"]:
        logging.error(
            "Invalid or unsupported (read: not implemented) connection type %s.",
            connection_type,
        )
        sys.exit(1)

    for prop, value in keyfile_config.items():
        section = prop.split(".", 1)[0]

        if section not in CONNECTION_TYPE_SECTIONS[connection_type]:
            logging.error(
                "Invalid or unsupported (read: not implemented) property for connection type %s: %s.",
                connection_type,
                prop,
            )
            sys.exit(1)

        prop_settings = NM_SETTINGS_PROPERTIES[prop]

        choices = prop_settings.get("choices", None)

        if choices and value not in choices:
            logging.error(
                "Invalid or unknown (read: not implemented) value for %s=%s. Valid values are %s",
                prop,
                value,
                "'" + "', '".join(choices) + "'",
            )
            sys.exit(1)

        if "validate" in prop_settings:
            try:
                prop_settings["validate"](value)
            except ValueError as err:
                logging.error(str(err))
                sys.exit(1)

    # check required params
    required_params = {
        param
        for param, settings in NM_SETTINGS_PROPERTIES.items()
        if settings.get("required")
        and param.split(".", 1)[0] in CONNECTION_TYPE_SECTIONS[connection_type]
    }

    for param in required_params:
        if param not in keyfile_config:
            logging.error("Required parameter %s not set.", param)
            sys.exit(1)


def format_value_for_keyfile(value: KEYFILE_SCALAR_VALUE_TYPE) -> str:
    if isinstance(value, str):
        return value
    elif isinstance(value, bool):
        return "true" if value else "false"
    elif isinstance(value, int):
        return str(value)

    raise ValueError(f"Invalid type {type(value)} for {value}")


def dump_keyfile(keyfile_config: KEYFILE_CONFIG_TYPE) -> str:
    connection_type: str = keyfile_config["connection.type"]
    params_by_section: typing.Dict[str, KEYFILE_CONFIG_TYPE] = defaultdict(dict)

    for prop, value in keyfile_config.items():
        section, _param_name = prop.split(".", 1)
        section_keyfile = KEYFILE_SECTION_NAMES[section]
        params_by_section[section_keyfile][prop] = value

    key_file_lines = []

    # get sections in correct order
    sections = (
        KEYFILE_SECTION_NAMES[section]
        for section in CONNECTION_TYPE_SECTIONS[connection_type]
    )

    for section in sections:
        if section in params_by_section:
            key_file_lines.append(f"[{section}]")

            for prop, value in params_by_section[section].items():
                formatter = NM_SETTINGS_PROPERTIES[prop].get(
                    "format_for_keyfile", format_value_for_keyfile
                )
                param = prop.split(".", 1)[1]

                if isinstance(value, list):
                    for index, val in enumerate(value):
                        key_file_lines.append(
                            f"{param}{index if index else ''}={formatter(val)}"
                        )
                else:
                    key_file_lines.append(f"{param}={formatter(value)}")

            key_file_lines.append("")

    return "\n".join(key_file_lines)


def main():
    args = parse_args()
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO)
    ifcfg: str = args.input.read()
    args.input.close()
    config = parse_ifcfg(ifcfg)
    validate_keyfile_config(config)
    keyfile_config: str = dump_keyfile(config)
    logging.info(f"Writing config to {args.output.name}.")
    args.output.write(keyfile_config)


if __name__ == "__main__":
    main()
