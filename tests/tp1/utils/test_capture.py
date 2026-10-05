from unittest.mock import patch

import pytest
from scapy.all import ARP, IP, TCP, Ether

from src.tp1.utils.capture import Alert, Capture

# initiate consts for tests
TARGET_IP = "192.168.1.200"
SCANNER_IP = "192.168.1.67"
SCANNER_MAC = "22:11:22:33:44:55"
CLIENT_IP = "192.168.1.20"
THRESHOLD = 10
# packets for test arp
arp_normal1 = Ether() / ARP(op=2, psrc=CLIENT_IP, hwsrc="00:11:22:33:44:55")
arp_normal2 = Ether() / ARP(op=2, psrc="192.168.1.21", hwsrc="11:11:22:33:44:55")
arp_normal3 = Ether() / ARP(op=2, psrc="192.168.1.1", hwsrc="aa:11:22:33:44:55")
sameIPDiffMac = Ether() / ARP(op=2, psrc=CLIENT_IP, hwsrc=SCANNER_MAC)
diffIPDiffMac = Ether() / ARP(op=2, psrc="192.168.1.1", hwsrc=SCANNER_MAC)

# packets for test port scan

tcp_normal1 = Ether() / IP(src=CLIENT_IP, dst=TARGET_IP) / TCP(sport=4525, dport=80, flags="S")
tcp_normal2 = Ether() / IP(src=CLIENT_IP, dst=TARGET_IP) / TCP(sport=7824, dport=443)
tcp_normal3 = Ether() / IP(src=SCANNER_IP, dst=TARGET_IP) / TCP(sport=6742, dport=22)

tcp_scan = [
    Ether(src=SCANNER_MAC) / IP(src=SCANNER_IP, dst=TARGET_IP) / TCP(sport=54148, dport=3000 + i, flags="S")
    for i in range(THRESHOLD)
]
alerts = list[Alert]


def test_capture_init():
    # When
    capture = Capture()

    # Then
    assert capture.interface == "eth0"
    assert capture.summary == ""


def test_given_capture_when_capture_traffic_then_interface_is_set():
    # Given
    capture = Capture()

    # When
    capture.capture_traffic()

    # Then
    # This is a minimal test since the method doesn't do much yet
    assert capture.interface == "eth0"


def test_sort_network_protocols():
    # Given
    capture = Capture()

    # When
    result = capture.sort_network_protocols()

    # Then
    assert result == ""  # Method currently returns None


def test_get_all_protocols():
    # Given
    capture = Capture()

    # When
    result = capture.get_all_protocols()

    # Then
    assert result == ""  # Method currently returns None


@pytest.mark.parametrize(
    "packets, theoricalAlerts",
    [
        ([arp_normal1, arp_normal2], []),  # shoulkd return 0 alerts
        (
            [arp_normal1, sameIPDiffMac],
            [
                Alert(
                    attack_type="ARP Spoofing",
                    protocol="ARP",
                    src_ip=CLIENT_IP,
                    src_mac=SCANNER_MAC,
                    details=f"IP {CLIENT_IP} is being spoofed by MAC {SCANNER_MAC}",
                )
            ],
        ),  # should return 1 alert
        (
            [arp_normal1, arp_normal2, sameIPDiffMac, sameIPDiffMac],
            [
                Alert(
                    attack_type="ARP Spoofing",
                    protocol="ARP",
                    src_ip=CLIENT_IP,
                    src_mac=SCANNER_MAC,
                    details=f"IP {CLIENT_IP} is being spoofed by MAC {SCANNER_MAC}",
                )
            ],
        ),  # should return 1 alert ( test is same alert is not reported twice)
        (
            [arp_normal1, arp_normal2, arp_normal3, sameIPDiffMac, sameIPDiffMac, diffIPDiffMac],
            [
                Alert(
                    attack_type="ARP Spoofing",
                    protocol="ARP",
                    src_ip=CLIENT_IP,
                    src_mac=SCANNER_MAC,
                    details=f"IP {CLIENT_IP} is being spoofed by MAC {SCANNER_MAC}",
                ),
                Alert(
                    attack_type="ARP Spoofing",
                    protocol="ARP",
                    src_ip="192.168.1.1",
                    src_mac=SCANNER_MAC,
                    details=f"IP 192.168.1.1 is being spoofed by MAC {SCANNER_MAC}",
                ),
            ],
        ),  # should return 2 alerts
    ],
    ids=["normal", "alert1", "alert2", "alert3"],
)
def test_detect_arp_spoofing(packets, theoricalAlerts):
    # Given
    capture = Capture()

    # When
    with patch("src.tp1.utils.capture.rdpcap", return_value=packets):
        capture.packets = packets
        capture.detect_arp_spoofing()
    assert capture.alerts == theoricalAlerts


def test_detect_port_scan(packets, theoricalAlerts):
    # Given
    capture = Capture()

    # When
    with patch("src.tp1.utils.capture.rdpcap", return_value=packets):
        capture.packets = packets
        capture.detect_arp_spoofing()
    assert capture.alerts == theoricalAlerts


def test_get_summary():
    # Given
    capture = Capture()
    capture.summary = "Test summary"

    # When
    result = capture.get_summary()

    # Then
    assert result == "Test summary"


def test_gen_summary():
    # Given
    capture = Capture()

    # When
    result = capture._gen_summary()

    # Then
    assert result == ""  # Method currently returns empty string
