"""
Packet capture module for real-time network traffic analysis.
Supports live capture and PCAP file replay.
"""
import asyncio
import logging
from typing import AsyncGenerator, Optional, Dict, Any
from datetime import datetime
import socket

try:
    from scapy.all import AsyncSniffer, Packet, IP, TCP, UDP, ICMP, Raw
    from scapy.layers.l2 import Ether
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logging.warning("Scapy not installed. Packet capture functionality will be limited.")

try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    PYSHARK_AVAILABLE = False
    logging.warning("Pyshark not installed. Some capture features may be unavailable.")


class PacketCapture:
    """Handles packet capture from live interfaces or PCAP files."""

    def __init__(self, interface: str = None, pcap_file: str = None, bpf_filter: str = ""):
        """
        Initialize packet capture.

        Args:
            interface: Network interface to listen on (e.g., 'eth0', 'Wi-Fi'). If None, uses default.
            pcap_file: Path to PCAP file for replay mode. If None, uses live capture.
            bpf_filter: Berkeley Packet Filter string (e.g., 'tcp port 80').
        """
        self.interface = interface
        self.pcap_file = pcap_file
        self.bpf_filter = bpf_filter
        self.logger = logging.getLogger(__name__)
        self._sniffer = None
        self._is_running = False

        if not SCAPY_AVAILABLE and not PYSHARK_AVAILABLE:
            raise RuntimeError("Neither Scapy nor Pyshark is available. Install one for packet capture.")

    async def start_live_capture(self) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Asynchronously capture packets from live interface.

        Yields:
            Dict containing packet information.
        """
        if self.pcap_file:
            raise ValueError("Cannot start live capture when pcap_file is set. Use start_pcap_replay instead.")

        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is required for live capture.")

        self.logger.info(f"Starting live capture on interface {self.interface or 'default'} with filter '{self.bpf_filter}'")

        def packet_callback(packet):
            """Callback to process each captured packet."""
            try:
                packet_info = self._extract_packet_info(packet)
                if packet_info:
                    asyncio.create_task(self._packet_queue.put(packet_info))
            except Exception as e:
                self.logger.error(f"Error processing packet: {e}")

        # We'll use a queue to bridge between scapy's callback and async generator
        self._packet_queue = asyncio.Queue()

        # Start the sniffer in a separate thread
        self._sniffer = AsyncSniffer(
            iface=self.interface,
            filter=self.bpf_filter,
            prn=packet_callback,
            store=False
        )
        self._sniffer.start()
        self._is_running = True

        try:
            while self._is_running:
                # Wait for packet with timeout to allow checking self._is_running
                try:
                    packet_info = await asyncio.wait_for(self._packet_queue.get(), timeout=1.0)
                    yield packet_info
                except asyncio.TimeoutError:
                    continue
        finally:
            self.stop()

    async def start_pcap_replay(self) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Asynchronously read packets from a PCAP file.

        Yields:
            Dict containing packet information.
        """
        if not self.pcap_file:
            raise ValueError("PCAP file not specified for replay mode.")

        self.logger.info(f"Starting PCAP replay from {self.pcap_file}")

        if PYSHARK_AVAILABLE:
            # Use pyshark for better PCAP reading
            cap = pyshark.FileCapture(self.pcap_file, display_filter=self.bpf_filter)
            try:
                for packet in cap:
                    if not self._is_running:
                        break
                    packet_info = self._extract_pyshark_packet_info(packet)
                    if packet_info:
                        yield packet_info
            finally:
                cap.close()
        elif SCAPY_AVAILABLE:
            # Fallback to scapy
            from scapy.all import PcapReader
            for packet in PcapReader(self.pcap_file):
                if not self._is_running:
                    break
                packet_info = self._extract_packet_info(packet)
                if packet_info:
                    yield packet_info
        else:
            raise RuntimeError("No packet capture library available.")

        self._is_running = False

    def stop(self):
        """Stop the packet capture."""
        self._is_running = False
        if self._sniffer:
            self._sniffer.stop()
            self._sniffer = None
        self.logger.info("Packet capture stopped.")

    def _extract_packet_info(self, packet) -> Optional[Dict[str, Any]]:
        """
        Extract relevant information from a scapy packet.

        Args:
            packet: Scapy packet object.

        Returns:
            Dictionary with packet information or None if extraction fails.
        """
        try:
            info = {
                'timestamp': datetime.fromtimestamp(float(packet.time)),
                'length': len(packet),
                'protocol': None,
                'src_ip': None,
                'dst_ip': None,
                'src_port': None,
                'dst_port': None,
                'payload_size': 0,
                'tcp_flags': None,
                'icmp_type': None,
                'icmp_code': None,
            }

            # Ethernet layer
            if packet.haslayer(Ether):
                ether = packet.getlayer(Ether)
                info['src_mac'] = ether.src
                info['dst_mac'] = ether.dst

            # IP layer
            if packet.haslayer(IP):
                ip = packet.getlayer(IP)
                info['src_ip'] = ip.src
                info['dst_ip'] = ip.dst
                info['protocol'] = ip.proto

                # TCP layer
                if packet.haslayer(TCP):
                    tcp = packet.getlayer(TCP)
                    info['src_port'] = tcp.sport
                    info['dst_port'] = tcp.dport
                    info['tcp_flags'] = tcp.flags
                    info['payload_size'] = len(tcp.payload) if tcp.payload else 0

                # UDP layer
                elif packet.haslayer(UDP):
                    udp = packet.getlayer(UDP)
                    info['src_port'] = udp.sport
                    info['dst_port'] = udp.dport
                    info['payload_size'] = len(udp.payload) if udp.payload else 0

                # ICMP layer
                elif packet.haslayer(ICMP):
                    icmp = packet.getlayer(ICMP)
                    info['icmp_type'] = icmp.type
                    info['icmp_code'] = icmp.code
                    info['payload_size'] = len(icmp.payload) if icmp.payload else 0

                # If no transport layer, still count IP payload
                else:
                    info['payload_size'] = len(ip.payload) if ip.payload else 0

            return info

        except Exception as e:
            self.logger.debug(f"Failed to extract packet info: {e}")
            return None

    def _extract_pyshark_packet_info(self, packet) -> Optional[Dict[str, Any]]:
        """
        Extract relevant information from a pyshark packet.

        Args:
            packet: Pyshark packet object.

        Returns:
            Dictionary with packet information or None if extraction fails.
        """
        try:
            info = {
                'timestamp': datetime.fromtimestamp(float(packet.sniff_timestamp)),
                'length': int(packet.length),
                'protocol': None,
                'src_ip': None,
                'dst_ip': None,
                'src_port': None,
                'dst_port': None,
                'payload_size': 0,
                'tcp_flags': None,
                'icmp_type': None,
                'icmp_code': None,
            }

            # IP layer
            if hasattr(packet, 'ip'):
                info['src_ip'] = packet.ip.src
                info['dst_ip'] = packet.ip.dst
                info['protocol'] = packet.ip.proto

                # TCP
                if hasattr(packet, 'tcp'):
                    info['src_port'] = packet.tcp.srcport
                    info['dst_port'] = packet.tcp.dstport
                    info['tcp_flags'] = packet.tcp.flags
                    info['payload_size'] = int(getattr(packet.tcp, 'len', 0))

                # UDP
                elif hasattr(packet, 'udp'):
                    info['src_port'] = packet.udp.srcport
                    info['dst_port'] = packet.udp.dstport
                    info['payload_size'] = int(getattr(packet.udp, 'len', 0))

                # ICMP
                elif hasattr(packet, 'icmp'):
                    info['icmp_type'] = packet.icmp.type
                    info['icmp_code'] = packet.icmp.code
                    info['payload_size'] = int(getattr(packet.icmp, 'len', 0))

            return info

        except Exception as e:
            self.logger.debug(f"Failed to extract pyshark packet info: {e}")
            return None


# Example usage (for testing)
if __name__ == "__main__":
    import asyncio

    async def test_live():
        capture = PacketCapture(interface="Wi-Fi", bpf_filter="tcp port 80")
        async for pkt in capture.start_live_capture():
            print(pkt)
            break  # Just for demo

    async def test_replay():
        capture = PacketCapture(pcap_file="sample.pcap")
        async for pkt in capture.start_pcap_replay():
            print(pkt)
            break

    # Uncomment to test
    # asyncio.run(test_live())
    # asyncio.run(test_replay())