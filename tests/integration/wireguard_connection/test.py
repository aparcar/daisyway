import sys
import json
from types import SimpleNamespace

def eprint(*a, **kw):
    print(*a, **{"file": sys.stderr, **kw})

config = json.loads(configJson, object_hook=lambda d: SimpleNamespace(**d))
eprint("Config: ", config, config.wireguard)

start_all()

ada.systemctl("start network-online.target")
bob.systemctl("start network-online.target")
ada.systemctl("start daisywayQkdSimulator.service")

ada.wait_for_unit("network-online.target")
bob.wait_for_unit("network-online.target")
ada.wait_for_unit("daisywayQkdSimulator.service")
ada.succeed("ip a 1>&2")
bob.succeed("ip a 1>&2")

# Basic network connectivity
ada.succeed("ping -c 1 -W 1 bob 1>&2")
bob.succeed("ping -c 1 -W 1 ada 1>&2")
ada.succeed(f"nmap {config.qkdSimulator.host} -T5 -p {config.qkdSimulator.port} 1>&2");
bob.succeed(f"nmap {config.qkdSimulator.host} -T5 -p {config.qkdSimulator.port} 1>&2");

# WireGuard connectivity
ada.succeed(f"ip link add {config.wireguard.interface} type wireguard && wg set {config.wireguard.interface} listen-port {config.wireguard.port} private-key /etc/daisyway/ada.wg.sk peer $(cat /etc/daisyway/bob.wg.pk) endpoint bob:{config.wireguard.port} allowed-ips fe80::/64 && ip link set {config.wireguard.interface} up && ip addr add fe80::1/64 dev {config.wireguard.interface}")
bob.succeed(f"ip link add {config.wireguard.interface} type wireguard && wg set {config.wireguard.interface} listen-port {config.wireguard.port} private-key /etc/daisyway/bob.wg.sk peer $(cat /etc/daisyway/ada.wg.pk) endpoint ada:{config.wireguard.port} allowed-ips fe80::/64 && ip link set {config.wireguard.interface} up && ip addr add fe80::2/64 dev {config.wireguard.interface}")
ada.succeed("wg show all 1>&2 && wg show all preshared-keys 1>&2")
bob.succeed("wg show all 1>&2 && wg show all preshared-keys 1>&2")
ada.succeed("ip a 1>&2")
bob.succeed("ip a 1>&2")
ada.succeed(f"ping -c 1 fe80::2%{config.wireguard.interface} 1>&2")
bob.succeed(f"ping -c 1 fe80::1%{config.wireguard.interface} 1>&2")

# Disconnect WireGuard interfaces
ada.succeed(f"ip link del {config.wireguard.interface} && wg genpsk > /etc/daisyway/garbage.psk && ip link add {config.wireguard.interface} type wireguard && wg set {config.wireguard.interface} listen-port {config.wireguard.port} private-key /etc/daisyway/ada.wg.sk peer $(cat /etc/daisyway/bob.wg.pk) preshared-key /etc/daisyway/garbage.psk endpoint bob:{config.wireguard.port} allowed-ips fe80::/64 && ip link set {config.wireguard.interface} up && ip addr add fe80::1/64 dev {config.wireguard.interface}")
bob.succeed(f"ip link del {config.wireguard.interface} && wg genpsk > /etc/daisyway/garbage.psk && ip link add {config.wireguard.interface} type wireguard && wg set {config.wireguard.interface} listen-port {config.wireguard.port} private-key /etc/daisyway/bob.wg.sk peer $(cat /etc/daisyway/ada.wg.pk) preshared-key /etc/daisyway/garbage.psk endpoint ada:{config.wireguard.port} allowed-ips fe80::/64 && ip link set {config.wireguard.interface} up && ip addr add fe80::2/64 dev {config.wireguard.interface}")
ada.fail(f"ping -c 1 -W 1 fe80::2%{config.wireguard.interface} 1>&2")
bob.fail(f"ping -c 1 -W 1 fe80::1%{config.wireguard.interface} 1>&2")

# Start Daisyway
ada.systemctl("start daisyway.service")
bob.systemctl("start daisyway.service")
ada.wait_for_unit("daisyway.service")
bob.wait_for_unit("daisyway.service")
ada.succeed(f"nmap bob -T5 -p {config.daisyway.port} 1>&2");
bob.succeed(f"nmap ada -T5 -p {config.daisyway.port} 1>&2");
ada.succeed("wg show all 1>&2 && wg show all preshared-keys 1>&2")
bob.succeed("wg show all 1>&2 && wg show all preshared-keys 1>&2")
ada.succeed("ip a 1>&2")
bob.succeed("ip a 1>&2")
ada.succeed(f"ping -c 1 -W 5 fe80::2%{config.wireguard.interface} 1>&2")
bob.succeed(f"ping -c 1 -W 5 fe80::1%{config.wireguard.interface} 1>&2")
