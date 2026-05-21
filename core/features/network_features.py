"""
Network feature extraction module.
Extracts features from network packets for ML models.
"""
import logging
import numpy as np
import pandas as pd
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict, deque
import hashlib
from datetime import datetime, timedelta
import math

try:
    from scipy import stats
    SCIPY_AVAILABLE = True
except ImportError:
    SCIPY_AVAILABLE = False
    logging.warning("SciPy not installed. Some statistical features will be limited.")

logger = logging.getLogger(__name__)


class NetworkFeatureExtractor:
    """Extracts network-based features from packet streams."""

    def __init__(self, window_sizes: List[int] = [60, 300, 900]):  # 1min, 5min, 15min in seconds
        """
        Initialize network feature extractor.

        Args:
            window_sizes: List of time windows in seconds for rolling statistics.
        """
        self.logger = logging.getLogger(__name__)
        self.window_sizes = window_sizes

        # Data structures for storing packet information
        self.packets = deque(maxlen=10000)  # Store recent packets for feature calculation
        self.flows = defaultdict(list)  # Flow-based tracking
        self.flow_timeout = 300  # 5 minutes flow timeout

        # Statistical tracking
        self.feature_stats = {}  # Running statistics for normalization

    def extract_features(self, packet_info: Dict[str, Any]) -> Dict[str, float]:
        """
        Extract features from a single packet.

        Args:
            packet_info: Dictionary containing packet information from packet capture.

        Returns:
            Dictionary of extracted features.
        """
        # Add packet to our storage
        self.packets.append({
            'timestamp': packet_info.get('timestamp', datetime.now()),
            'length': packet_info.get('length', 0),
            'src_ip': packet_info.get('src_ip'),
            'dst_ip': packet_info.get('dst_ip'),
            'src_port': packet_info.get('src_port'),
            'dst_port': packet_info.get('dst_port'),
            'protocol': packet_info.get('protocol'),
            'payload_size': packet_info.get('payload_size', 0),
            'tcp_flags': packet_info.get('tcp_flags'),
        })

        # Update flow tracking
        self._update_flows(packet_info)

        # Extract various feature categories
        features = {}

        # Basic packet features
        features.update(self._extract_basic_packet_features(packet_info))

        # Flow-based features
        features.update(self._extract_flow_features(packet_info))

        # Statistical features (rolling windows)
        features.update(self._extract_statistical_features())

        # Payload/features
        features.update(self._extract_payload_features(packet_info))

        # Connection rate features
        features.update(self._extract_connection_rate_features())

        return features

    def _extract_basic_packet_features(self, packet_info: Dict[str, Any]) -> Dict[str, float]:
        """Extract basic features from a single packet."""
        features = {}

        # Packet size features
        features['packet_size'] = float(packet_info.get('length', 0))
        features['payload_size'] = float(packet_info.get('payload_size', 0))
        features['header_size'] = features['packet_size'] - features['payload_size']

        # Protocol features (one-hot encoded)
        protocol = packet_info.get('protocol', 0)
        features['protocol_tcp'] = 1.0 if protocol == 6 else 0.0
        features['protocol_udp'] = 1.0 if protocol == 17 else 0.0
        features['protocol_icmp'] = 1.0 if protocol == 1 else 0.0
        features['protocol_other'] = 1.0 if protocol not in [1, 6, 17] else 0.0

        # TCP flags features
        tcp_flags = packet_info.get('tcp_flags', 0)
        if tcp_flags:
            features['tcp_flag_fin'] = 1.0 if tcp_flags & 0x01 else 0.0
            features['tcp_flag_syn'] = 1.0 if tcp_flags & 0x02 else 0.0
            features['tcp_flag_rst'] = 1.0 if tcp_flags & 0x04 else 0.0
            features['tcp_flag_psh'] = 1.0 if tcp_flags & 0x08 else 0.0
            features['tcp_flag_ack'] = 1.0 if tcp_flags & 0x10 else 0.0
            features['tcp_flag_urg'] = 1.0 if tcp_flags & 0x20 else 0.0
            features['tcp_flag_ece'] = 1.0 if tcp_flags & 0x40 else 0.0
            features['tcp_flag_cwr'] = 1.0 if tcp_flags & 0x80 else 0.0
        else:
            # Default to zero for non-TCP packets
            for flag in ['fin', 'syn', 'rst', 'psh', 'ack', 'urg', 'ece', 'cwr']:
                features[f'tcp_flag_{flag}'] = 0.0

        # Port features
        src_port = packet_info.get('src_port', 0) or 0
        dst_port = packet_info.get('dst_port', 0) or 0
        features['src_port'] = float(src_port)
        features['dst_port'] = float(dst_port)
        features['src_port_high'] = 1.0 if src_port > 1024 else 0.0  # Ephemeral port
        features['dst_port_high'] = 1.0 if dst_port > 1024 else 0.0
        features['dst_port_well_known'] = 1.0 if dst_port <= 1023 else 0.0  # Well-known port

        # Common service ports
        common_ports = {80: 'http', 443: 'https', 22: 'ssh', 21: 'ftp', 25: 'smtp', 53: 'dns'}
        for port, service in common_ports.items():
            features[f'dst_port_{service}'] = 1.0 if dst_port == port else 0.0
            features[f'src_port_{service}'] = 1.0 if src_port == port else 0.0

        return features

    def _update_flows(self, packet_info: Dict[str, Any]):
        """Update flow tracking with new packet."""
        src_ip = packet_info.get('src_ip')
        dst_ip = packet_info.get('dst_ip')
        src_port = packet_info.get('src_port')
        dst_port = packet_info.get('dst_port')
        protocol = packet_info.get('protocol')

        if not all([src_ip, dst_ip, src_port is not None, dst_port is not None]):
            return

        # Create flow identifier (bidirectional)
        flow_id = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)])) + (protocol,)
        reverse_flow_id = tuple(sorted([(dst_ip, dst_port), (src_ip, src_port)])) + (protocol,)

        # Use the flow_id that exists or create new one
        if flow_id in self.flows:
            active_flow_id = flow_id
        elif reverse_flow_id in self.flows:
            active_flow_id = reverse_flow_id
        else:
            active_flow_id = flow_id

        # Add packet to flow
        self.flows[active_flow_id].append({
            'timestamp': packet_info.get('timestamp', datetime.now()),
            'length': packet_info.get('length', 0),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'direction': 0 if (src_ip, src_port) == active_flow_id[0] else 1,  # 0=original, 1=reverse
        })

        # Clean old flows
        self._clean_old_flows()

    def _clean_old_flows(self):
        """Remove flows older than flow_timeout."""
        cutoff_time = datetime.now() - timedelta(seconds=self.flow_timeout)
        flows_to_delete = []

        for flow_id, packets in self.flows.items():
            if packets and packets[-1]['timestamp'] < cutoff_time:
                flows_to_delete.append(flow_id)

        for flow_id in flows_to_delete:
            del self.flows[flow_id]

    def _extract_flow_features(self, packet_info: Dict[str, Any]) -> Dict[str, float]:
        """Extract flow-based features."""
        features = {}

        src_ip = packet_info.get('src_ip')
        dst_ip = packet_info.get('dst_ip')
        src_port = packet_info.get('src_port')
        dst_port = packet_info.get('dst_port')
        protocol = packet_info.get('protocol')

        if not all([src_ip, dst_ip, src_port is not None, dst_port is not None]):
            return features

        # Find the flow
        flow_id = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)])) + (protocol,)
        reverse_flow_id = tuple(sorted([(dst_ip, dst_port), (src_ip, src_port)])) + (protocol,)

        flow_packets = None
        flow_id_used = None

        if flow_id in self.flows:
            flow_packets = self.flows[flow_id]
            flow_id_used = flow_id
        elif reverse_flow_id in self.flows:
            flow_packets = self.flows[reverse_flow_id]
            flow_id_used = reverse_flow_id

        if not flow_packets or len(flow_packets) < 2:
            # Not enough packets for flow features
            features.update({
                'flow_duration': 0.0,
                'flow_packet_count': 0.0,
                'flow_byte_count': 0.0,
                'flow_bytes_per_second': 0.0,
                'flow_packets_per_second': 0.0,
                'flow_avg_packet_size': 0.0,
                'flow_std_packet_size': 0.0,
                'flow_inter_arrival_mean': 0.0,
                'flow_inter_arrival_std': 0.0,
                'flow_syn_count': 0.0,
                'flow_ack_count': 0.0,
                'flow_fin_count': 0.0,
                'flow_rst_count': 0.0,
                'flow_psh_count': 0.0,
                'flow_urg_count': 0.0,
            })
            return features

        # Calculate flow features
        timestamps = [p['timestamp'] for p in flow_packets]
        lengths = [p['length'] for p in flow_packets]

        # Duration
        if len(timestamps) >= 2:
            duration = (max(timestamps) - min(timestamps)).total_seconds()
            features['flow_duration'] = max(duration, 0.001)  # Avoid division by zero
        else:
            features['flow_duration'] = 0.0

        features['flow_packet_count'] = float(len(flow_packets))
        features['flow_byte_count'] = float(sum(lengths))

        if features['flow_duration'] > 0:
            features['flow_bytes_per_second'] = features['flow_byte_count'] / features['flow_duration']
            features['flow_packets_per_second'] = features['flow_packet_count'] / features['flow_duration']
        else:
            features['flow_bytes_per_second'] = 0.0
            features['flow_packets_per_second'] = 0.0

        if lengths:
            features['flow_avg_packet_size'] = float(np.mean(lengths))
            features['flow_std_packet_size'] = float(np.std(lengths)) if len(lengths) > 1 else 0.0
        else:
            features['flow_avg_packet_size'] = 0.0
            features['flow_std_packet_size'] = 0.0

        # Inter-arrival times
        if len(timestamps) >= 2:
            inter_arrivals = []
            for i in range(1, len(timestamps)):
                delta = (timestamps[i] - timestamps[i-1]).total_seconds()
                inter_arrivals.append(delta)

            if inter_arrivals:
                features['flow_inter_arrival_mean'] = float(np.mean(inter_arrivals))
                features['flow_inter_arrival_std'] = float(np.std(inter_arrivals)) if len(inter_arrivals) > 1 else 0.0
            else:
                features['flow_inter_arrival_mean'] = 0.0
                features['flow_inter_arrival_std'] = 0.0
        else:
            features['flow_inter_arrival_mean'] = 0.0
            features['flow_inter_arrival_std'] = 0.0

        # TCP flag counts in flow (would need to store flags with packets)
        # For simplicity, we'll set these to zero - would need to enhance packet storage
        for flag in ['syn', 'ack', 'fin', 'rst', 'psh', 'urg']:
            features[f'flow_{flag}_count'] = 0.0

        return features

    def _extract_statistical_features(self) -> Dict[str, float]:
        """Extract statistical features over rolling windows."""
        features = {}

        if len(self.packets) < 2:
            # Not enough data for statistical features
            for window in self.window_sizes:
                features.update({
                    f'packet_size_mean_{window}s': 0.0,
                    f'packet_size_std_{window}s': 0.0,
                    f'packet_size_median_{window}s': 0.0,
                    f'packet_size_p95_{window}s': 0.0,
                    f'packet_rate_{window}s': 0.0,
                    f'byte_rate_{window}s': 0.0,
                })
            return features

        # Get packets within each window
        now = datetime.now()

        for window in self.window_sizes:
            cutoff = now - timedelta(seconds=window)
            window_packets = [p for p in self.packets if p['timestamp'] >= cutoff]

            if len(window_packets) == 0:
                features.update({
                    f'packet_size_mean_{window}s': 0.0,
                    f'packet_size_std_{window}s': 0.0,
                    f'packet_size_median_{window}s': 0.0,
                    f'packet_size_p95_{window}s': 0.0,
                    f'packet_rate_{window}s': 0.0,
                    f'byte_rate_{window}s': 0.0,
                })
                continue

            sizes = [p['length'] for p in window_packets]
            timestamps = [p['timestamp'] for p in window_packets]

            # Size statistics
            features[f'packet_size_mean_{window}s'] = float(np.mean(sizes))
            features[f'packet_size_std_{window}s'] = float(np.std(sizes)) if len(sizes) > 1 else 0.0
            features[f'packet_size_median_{window}s'] = float(np.median(sizes))

            if SCIPY_AVAILABLE and len(sizes) > 0:
                features[f'packet_size_p95_{window}s'] = float(stats.scoreatpercentile(sizes, 95))
            else:
                # Approximate percentile
                sorted_sizes = sorted(sizes)
                idx = int(0.95 * len(sorted_sizes))
                features[f'packet_size_p95_{window}s'] = float(sorted_sizes[min(idx, len(sorted_sizes)-1)])

            # Rate statistics
            if len(timestamps) >= 2:
                duration = (max(timestamps) - min(timestamps)).total_seconds()
                if duration > 0:
                    features[f'packet_rate_{window}s'] = len(window_packets) / duration
                    features[f'byte_rate_{window}s'] = sum(sizes) / duration
                else:
                    features[f'packet_rate_{window}s'] = float(len(window_packets))
                    features[f'byte_rate_{window}s'] = float(sum(sizes))
            else:
                features[f'packet_rate_{window}s'] = float(len(window_packets))
                features[f'byte_rate_{window}s'] = float(sum(sizes))

        return features

    def _extract_payload_features(self, packet_info: Dict[str, Any]) -> Dict[str, float]:
        """Extract payload-based features (entropy, etc.)."""
        features = {}

        # In a real implementation, we would have access to actual payload data
        # For now, we'll use payload size as a proxy and add some placeholder entropy features
        payload_size = packet_info.get('payload_size', 0)

        features['payload_size'] = float(payload_size)
        features['has_payload'] = 1.0 if payload_size > 0 else 0.0

        # Placeholder for entropy calculation (would need actual payload data)
        features['payload_entropy'] = 0.0  # Would calculate Shannon entropy of payload
        features['payload_printable_ratio'] = 0.0  # Would calculate ratio of printable chars

        # Binary vs text heuristic based on common ports/protocols
        dst_port = packet_info.get('dst_port', 0) or 0
        protocol = packet_info.get('protocol', 0)

        # Likely text-based protocols
        text_ports = {80, 443, 22, 21, 25, 110, 143, 993, 995}  # HTTP, HTTPS, SSH, FTP, SMTP, IMAP/POP3
        features['likely_text_traffic'] = 1.0 if dst_port in text_ports or protocol == 6 and dst_port in text_ports else 0.0
        features['likely_binary_traffic'] = 1.0 - features['likely_text_traffic']

        return features

    def _extract_connection_rate_features(self) -> Dict[str, float]:
        """Extract connection-based rate features."""
        features = {}

        now = datetime.now()

        # Count unique connections in different time windows
        for window_name, window_seconds in [('1m', 60), ('5m', 300), ('15m', 900)]:
            cutoff = now - timedelta(seconds=window_seconds)

            # Unique source IPs
            unique_src_ips = set()
            unique_dst_ips = set()
            unique_connections = set()  # (src_ip, dst_ip, src_port, dst_port)

            for pkt in self.packets:
                if pkt['timestamp'] >= cutoff:
                    src_ip = pkt.get('src_ip')
                    dst_ip = pkt.get('dst_ip')
                    src_port = pkt.get('src_port')
                    dst_port = pkt.get('dst_port')

                    if src_ip:
                        unique_src_ips.add(src_ip)
                    if dst_ip:
                        unique_dst_ips.add(dst_ip)
                    if all([src_ip, dst_ip, src_port is not None, dst_port is not None]):
                        unique_connections.add((src_ip, dst_ip, src_port, dst_port))

            features[f'unique_src_ips_{window_name}'] = float(len(unique_src_ips))
            features[f'unique_dst_ips_{window_name}'] = float(len(unique_dst_ips))
            features[f'unique_connections_{window_name}'] = float(len(unique_connections))

            # Connection rates
            if window_seconds > 0:
                features[f'connection_rate_{window_name}'] = len(unique_connections) / window_seconds
                features[f'src_ip_rate_{window_name}'] = len(unique_src_ips) / window_seconds
                features[f'dst_ip_rate_{window_name}'] = len(unique_dst_ips) / window_seconds
            else:
                features[f'connection_rate_{window_name}'] = 0.0
                features[f'src_ip_rate_{window_name}'] = 0.0
                features[f'dst_ip_rate_{window_name}'] = 0.0

        return features

    def get_feature_names(self) -> List[str]:
        """Get list of all possible feature names."""
        # This would return all possible features that could be extracted
        # For now, return a representative sample
        basic_features = [
            'packet_size', 'payload_size', 'header_size',
            'protocol_tcp', 'protocol_udp', 'protocol_icmp', 'protocol_other',
            'tcp_flag_fin', 'tcp_flag_syn', 'tcp_flag_rst', 'tcp_flag_psh',
            'tcp_flag_ack', 'tcp_flag_urg', 'tcp_flag_ece', 'tcp_flag_cwr',
            'src_port', 'dst_port', 'src_port_high', 'dst_port_high',
            'dst_port_well_known'
        ]

        # Add common port features
        common_services = ['http', 'https', 'ssh', 'ftp', 'smtp', 'dns']
        for service in common_services:
            basic_features.extend([f'src_port_{service}', f'dst_port_{service}'])

        flow_features = [
            'flow_duration', 'flow_packet_count', 'flow_byte_count',
            'flow_bytes_per_second', 'flow_packets_per_second',
            'flow_avg_packet_size', 'flow_std_packet_size',
            'flow_inter_arrival_mean', 'flow_inter_arrival_std',
            'flow_syn_count', 'flow_ack_count', 'flow_fin_count',
            'flow_rst_count', 'flow_psh_count', 'flow_urg_count'
        ]

        statistical_features = []
        for window in [60, 300, 900]:
            statistical_features.extend([
                f'packet_size_mean_{window}s', f'packet_size_std_{window}s',
                f'packet_size_median_{window}s', f'packet_size_p95_{window}s',
                f'packet_rate_{window}s', f'byte_rate_{window}s'
            ])

        payload_features = [
            'payload_size', 'has_payload', 'payload_entropy', 'payload_printable_ratio',
            'likely_text_traffic', 'likely_binary_traffic'
        ]

        connection_features = []
        for window_name in ['1m', '5m', '15m']:
            connection_features.extend([
                f'unique_src_ips_{window_name}', f'unique_dst_ips_{window_name}',
                f'unique_connections_{window_name}', f'connection_rate_{window_name}',
                f'src_ip_rate_{window_name}', f'dst_ip_rate_{window_name}'
            ])

        all_features = basic_features + flow_features + statistical_features + payload_features + connection_features
        return list(set(all_features))  # Remove duplicates


# Example usage and testing
if __name__ == "__main__":
    import asyncio
    from datetime import datetime, timedelta

    def test_feature_extraction():
        extractor = NetworkFeatureExtractor(window_sizes=[60, 300, 900])

        # Simulate some packets
        base_time = datetime.now()

        test_packets = [
            {
                'timestamp': base_time,
                'length': 100,
                'src_ip': '192.168.1.100',
                'dst_ip': '10.0.0.1',
                'src_port': 54321,
                'dst_port': 80,
                'protocol': 6,  # TCP
                'payload_size': 80,
                'tcp_flags': 0x18,  # PSH+ACK
            },
            {
                'timestamp': base_time + timedelta(milliseconds=50),
                'length': 120,
                'src_ip': '10.0.0.1',
                'dst_ip': '192.168.1.100',
                'src_port': 80,
                'dst_port': 54321,
                'protocol': 6,  # TCP
                'payload_size': 100,
                'tcp_flags': 0x10,  # ACK
            },
            {
                'timestamp': base_time + timedelta(milliseconds=100),
                'length': 64,
                'src_ip': '192.168.1.100',
                'dst_ip': '10.0.0.2',
                'src_port': 54322,
                'dst_port': 443,
                'protocol': 6,  # TCP
                'payload_size': 44,
                'tcp_flags': 0x02,  # SYN
            }
        ]

        print("Extracting features from test packets:")
        for i, packet in enumerate(test_packets):
            features = extractor.extract_features(packet)
            print(f"\nPacket {i+1}:")
            # Print just a few key features for brevity
            key_features = {k: v for k, v in features.items() if k in [
                'packet_size', 'flow_duration', 'flow_packet_count',
                'payload_size', 'dst_port_http', 'dst_port_https'
            ]}
            for key, value in key_features.items():
                print(f"  {key}: {value}")

        print(f"\nTotal features extracted: {len(features)}")
        print(f"Feature names: {sorted(list(features.keys()))[:10]}...")  # First 10

    # Uncomment to run test
    # test_feature_extraction()