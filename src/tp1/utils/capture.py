from dataclasses import dataclass

from scapy.all import ARP, rdpcap

from tp1.utils.config import logger


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
        self.detect_arp_spoofing()
        self.detect_sql_injection()

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
            if pkt.haslayer(ARP) and pkt[ARP].op == 2:
                if pkt[ARP].psrc in ip_mac_mapping and ip_mac_mapping[pkt[ARP].psrc] != pkt[ARP].hwsrc:
                    if pkt[ARP].psrc not in [alert.src_ip for alert in self.alerts] and pkt[
                        ARP
                    ].hwsrc not in [alert.src_mac for alert in self.alerts]:
                        self.alerts.append(
                            Alert(
                                attack_type=AttackType.ARP_SPOOFING,
                                protocol="ARP",
                                src_ip=pkt[ARP].psrc,
                                src_mac=pkt[ARP].hwsrc,
                                details=f"IP {pkt[ARP].psrc} is being spoofed by MAC {pkt[ARP].hwsrc}",
                            )
                        )
                else:
                    ip_mac_mapping[pkt[ARP].psrc] = pkt[ARP].hwsrc

    def detect_sql_injection(self) -> None:
        """
        Detect SQL injection
        """
        logger.info("Detect SQL injection")

    def detect_sport_scan(self) -> None:
        """
        Detect PORT scan
        """
        logger.info("Detect PORT scan")
