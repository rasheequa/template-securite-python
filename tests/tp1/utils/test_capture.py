from unittest.mock import patch

import pytest
from scapy.all import ARP, Ether

from src.tp1.utils.capture import Alert, Capture

normal1 = Ether() / ARP(op=2, psrc="192.168.1.20", hwsrc="00:11:22:33:44:55")
normal2 = Ether() / ARP(op=2, psrc="192.168.1.21", hwsrc="11:11:22:33:44:55")
normal3 = Ether() / ARP(op=2, psrc="192.168.1.1", hwsrc="aa:11:22:33:44:55")
sameIPDiffMac = Ether() / ARP(op=2, psrc="192.168.1.20", hwsrc="22:11:22:33:44:55")
diffIPDiffMac = Ether() / ARP(op=2, psrc="192.168.1.1", hwsrc="22:11:22:33:44:55")

alerts = list[Alert]


def test_capture_init():
    # When
    capture = Capture()

    # Then
    assert capture.interface == ""
    assert capture.summary == ""


def test_given_capture_when_capture_traffic_then_interface_is_set():
    # Given
    capture = Capture()

    # When
    capture.capture_traffic()

    # Then
    # This is a minimal test since the method doesn't do much yet
    assert capture.interface == ""


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
        ([normal1, normal2], []),  # shoulkd return 0 alerts
        (
            [normal1, sameIPDiffMac],
            [
                Alert(
                    attack_type="ARP Spoofing",
                    protocol="ARP",
                    src_ip="192.168.1.20",
                    src_mac="22:11:22:33:44:55",
                    details="IP 192.168.1.20 is being spoofed by MAC 22:11:22:33:44:55",
                )
            ],
        ),  # should return 1 alert
        (
            [normal1, normal2, sameIPDiffMac, sameIPDiffMac],
            [
                Alert(
                    attack_type="ARP Spoofing",
                    protocol="ARP",
                    src_ip="192.168.1.20",
                    src_mac="22:11:22:33:44:55",
                    details="IP 192.168.1.20 is being spoofed by MAC 22:11:22:33:44:55",
                )
            ],
        ),  # should return 1 alert
        (
            [normal1, normal2, sameIPDiffMac, sameIPDiffMac, diffIPDiffMac],
            [
                Alert(
                    attack_type="ARP Spoofing",
                    protocol="ARP",
                    src_ip="192.168.1.20",
                    src_mac="22:11:22:33:44:55",
                    details="IP 192.168.1.20 is being spoofed by MAC 22:11:22:33:44:55",
                ),
                Alert(
                    attack_type="ARP Spoofing",
                    protocol="ARP",
                    src_ip="192.168.1.1",
                    src_mac="22:11:22:33:44:55",
                    details="IP 192.168.1.1 is being spoofed by MAC 22:11:22:33:44:55",
                ),
            ],
        ),  # should return 2 alerts
    ],
    ids=["normal", "alert1", "alert2", "alert3"],
)
def test_analyse(packets, theoricalAlerts):
    # Given
    capture = Capture()

    # When
    with patch("src.tp1.utils.capture.rdpcap", return_value=packets):
        capture.packets = packets
        capture.detect_arp_spoofing()
        capture.detect_sport_scan()
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
