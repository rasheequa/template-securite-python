from dataclasses import dataclass

from scapy.all import ARP, IP, TCP, rdpcap

from tp1.utils.config import logger

THRESHOLD = 10


class AttackType:
    ARP_SPOOFING = "ARP Spoofing"
    SQL_INJECTION = "SQL Injection"
    PORT_SCAN = "Port Scan"


@dataclass
class Alert:
    attack_type: AttackType
    protocol: str
    src_ip: str
    src_mac: str
    details: str


class Capture:
    def __init__(self) -> None:
        # self.interface = choose_interface()
        self.interface = "eth0"
        self.summary = ""
        self.packets = []
        self.alerts: list[Alert] = []
        self.summary = ""

    def capture_traffic(self) -> None:
        """
        Capture network traffic from an interface
        """
        interface = self.interface
        logger.info(f"Capture traffic from interface {interface}")

    def sort_network_protocols(self) -> str:
        """
        Sort and return all captured network protocols
        """
        return ""

    def get_all_protocols(self) -> str:
        """
        Return all protocols captured with total packets number
        """
        return ""

    def analyse(self, protocols: str) -> None:
        """
        Analyse all captured data and return statement
        Si un tra c est illégitime (exemple : Injection SQL, ARP
        Spoo ng, etc)
        a Noter la tentative d'attaque.
        b Relever le protocole ainsi que l'adresse réseau/physique
        de l'attaquant.
        c (FACULTATIF) Opérer le blocage de la machine
        attaquante.
        Sinon afficher que tout va bien
        """
        # all_protocols = self.get_all_protocols()
        # sort = self.sort_network_protocols()
        # logger.debug(f"All protocols: {all_protocols}")
        # logger.debug(f"Sorted protocols: {sort}")

        self.packets = rdpcap("file.pcap")
        logger.info(f"Captured {len(self.packets)} packets")
        logger.info(f"Captured packets: {self.packets.show()}")

        self.detect_arp_spoofing()
        self.detect_sql_injection()
        self.detect_port_scan()

        self.summary = self._gen_summary()

    def get_summary(self) -> str:
        """
        Return summary
        :return:
        """
        print(self.summary)

    def _gen_summary(self) -> str:
        """
        Generate summary
        """
        if not self.alerts:
            return "No alerts detected."
        else:
            return self.alerts

    def detect_arp_spoofing(self) -> None:
        """
        Detect ARP spoofing
        """
        logger.info("Detect ARP spoofing")
        pkts = self.packets
        ip_mac_mapping = {}
        for pkt in pkts:
            if not (pkt.haslayer(ARP) and pkt[ARP].op == 2):
                continue

            if not (pkt[ARP].psrc in ip_mac_mapping and ip_mac_mapping[pkt[ARP].psrc] != pkt[ARP].hwsrc):
                ip_mac_mapping[pkt[ARP].psrc] = pkt[ARP].hwsrc
                continue

            if (pkt[ARP].psrc, pkt[ARP].hwsrc) not in [(a.src_ip, a.src_mac) for a in self.alerts]:
                self.alerts.append(
                    Alert(
                        attack_type=AttackType.ARP_SPOOFING,
                        protocol="ARP",
                        src_ip=pkt[ARP].psrc,
                        src_mac=pkt[ARP].hwsrc,
                        details=f"IP {pkt[ARP].psrc} is being spoofed by MAC {pkt[ARP].hwsrc}",
                    )
                )

    def detect_sql_injection(self) -> None:
        """
        Detect SQL injection
        """
        logger.info("Detect SQL injection")

    def detect_port_scan(self) -> None:
        """
        Detect PORT scan
        """
        logger.info("Detect PORT scan")

        pkts = self.packets
        ip_src_dst_port_couple = {}
        for pkt in pkts:
            if not (pkt.haslayer(TCP) and pkt[TCP].flags == "S"):
                continue

            pair = (pkt[IP].src, pkt[IP].dst)

            if pair not in ip_src_dst_port_couple:
                ip_src_dst_port_couple[pair] = []

            if pkt[TCP].dport not in ip_src_dst_port_couple[pair]:
                ip_src_dst_port_couple[pair].append(pkt[TCP].dport)

                if len(ip_src_dst_port_couple[pair]) == THRESHOLD:
                    self.alerts.append(
                        Alert(
                            attack_type=AttackType.PORT_SCAN,
                            protocol="TCP",
                            src_ip=pkt[IP].src,
                            src_mac="",
                            details=f"IP {pkt[IP].src} is scanning ports on IP {pkt[IP].dst}",
                        )
                    )
