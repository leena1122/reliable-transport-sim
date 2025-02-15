# do not import anything else from loss_socket besides LossyUDP
from lossy_socket import LossyUDP
# do not import anything else from socket except INADDR_ANY
from socket import INADDR_ANY
import struct
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
import time
import hashlib 


class Streamer:
    def __init__(self, dst_ip, dst_port,
                 src_ip=INADDR_ANY, src_port=0):
        """Default values listen on all network interfaces, chooses a random source port,
           and does not introduce any simulated packet loss."""
        self.socket = LossyUDP()
        self.socket.bind((src_ip, src_port))
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        # maximum udp payload size to be able to fit 1472 byte limit
        self.max_size = 1400 # leave room for header
        
        # sequence number management
        self.send_base = 0
        self.next_seq_num = 0
        self.receive_seq_num = 0
        self.window_size = 5
        self.send_buffer = {}
        self.receive_buffer = defaultdict(bytes)

        # header format: sequence number (I), packet type (B), and hash (32s)
        self.header_form = "!IB32s"  # Added B for packet type, 32s for MD5 hash
        self.header_size = struct.calcsize(self.header_form)
        
        # thread stuff
        self.closed = False
        self.executor = ThreadPoolExecutor(max_workers=1)
        self.executor.submit(self.listener)
        
        # ACK and connection management
        self.ack_received = False
        self.waiting_for_seq = None
        self.ACK_TIMEOUT = 0.1  # faster retransmission
        self.fin_received = False
        self.fin_acked = False
        self.fin_sent = False
        self.all_data_acked = False

        self.last_retransmit = 0
        self.RETRANSMIT_INTERVAL = 0.1  # more retransmission
        
        # packet types
        self.DATA_PACKET = 0
        self.ACK_PACKET = 1
        self.FIN_PACKET = 2
        
        self.MAX_RETRANSMIT_ATTEMPTS = 50
        self.retransmit_attempts = 0

    def compute_hash(self, seq_num: int, packet_type: int, data: bytes) -> bytes:
        header_without_md5 = struct.pack("!IB", seq_num, packet_type)
        return hashlib.md5(header_without_md5 + data).hexdigest().encode('ascii')

    def handle_timeout(self):
        """Retransmit all unacked packets in the window"""
        current_time = time.time()
        if current_time - self.last_retransmit >= self.RETRANSMIT_INTERVAL:
            self.retransmit_attempts += 1
            
            # Only retransmit packets that are actually in our buffer
            window_start = self.send_base
            window_end = min(self.next_seq_num, self.send_base + self.window_size)
            
            # Safety check to ensure window bounds are valid
            if window_start > window_end:
                window_start = max(0, window_end - self.window_size)
            
            # Retransmit packets within the current window that exist in our buffer
            for seq_num in range(window_start, window_end):
                if seq_num in self.send_buffer:
                    # Send multiple times based on how long we've been retransmitting
                    retransmit_count = min(3, self.retransmit_attempts)
                    for _ in range(retransmit_count):
                        try:
                            self.socket.sendto(self.send_buffer[seq_num], 
                                             (self.dst_ip, self.dst_port))
                        except Exception as e:
                            print(f"Error retransmitting packet {seq_num}: {e}")
            
            self.last_retransmit = current_time
            
            # Adjust window size if we're having trouble
            if self.retransmit_attempts > 10:
                self.window_size = max(2, self.window_size - 1)  # Reduce window size if having issues
            elif self.retransmit_attempts > 20:
                # Reset everything if we're really stuck
                self.window_size = 2
                self.send_base = min(self.send_buffer.keys()) if self.send_buffer else self.next_seq_num
                self.retransmit_attempts = 0

    def listener(self):
        while not self.closed:
            try:
                segment, addr = self.socket.recvfrom()
                if len(segment) < self.header_size:
                    continue

                header = segment[:self.header_size]
                data = segment[self.header_size:]
                seq_num, packet_type, received_hash = struct.unpack(self.header_form, header)
                
                if packet_type == self.DATA_PACKET:
                    computed_hash = self.compute_hash(seq_num, packet_type, data)
                    if computed_hash != received_hash:
                        continue
                    
                    self.receive_buffer[seq_num] = data
                    # Send ACK multiple times for reliability
                    hashed_val = self.compute_hash(seq_num, self.ACK_PACKET, b'')
                    ack_header = struct.pack(self.header_form, seq_num, self.ACK_PACKET, hashed_val)
                    for _ in range(3):
                        self.socket.sendto(ack_header, (self.dst_ip, self.dst_port))
                
                elif packet_type == self.ACK_PACKET:
                    if seq_num >= self.send_base:
                        # Update window more aggressively
                        old_base = self.send_base
                        self.send_base = max(seq_num + 1, self.send_base)
                        self.retransmit_attempts = 0
                        
                        # Clean up acknowledged packets
                        for k in list(self.send_buffer.keys()):
                            if k < self.send_base:
                                del self.send_buffer[k]
                        
                        if self.fin_sent and seq_num == self.next_seq_num - 1:
                            self.fin_acked = True
                        if self.send_base == self.next_seq_num:
                            self.all_data_acked = True
                            
                        # If window moved significantly, reset window size
                        if self.send_base - old_base > 2:
                            self.window_size = 5
            finally:
                pass

    def send(self, data_bytes: bytes) -> None:
        offset = 0
        while offset < len(data_bytes):
            max_data = self.max_size - self.header_size
            end = min(offset + max_data, len(data_bytes))
            chunk = data_bytes[offset:end]
            
            # More aggressive window management
            retry_count = 0
            while self.next_seq_num >= self.send_base + self.window_size:
                self.handle_timeout()
                time.sleep(0.01)
                retry_count += 1
                if retry_count > 100:  # If stuck too long
                    # Force window movement
                    self.send_base = self.next_seq_num - self.window_size + 1
                    retry_count = 0
            
            hashed_val = self.compute_hash(self.next_seq_num, self.DATA_PACKET, chunk)
            header = struct.pack(self.header_form, self.next_seq_num, self.DATA_PACKET, hashed_val)
            segment = header + chunk
            
            # Send multiple times initially
            for _ in range(3):
                self.socket.sendto(segment, (self.dst_ip, self.dst_port))
            
            self.send_buffer[self.next_seq_num] = segment
            self.next_seq_num += 1
            offset = end
            
            # More frequent timeout checks
            if self.next_seq_num % 2 == 0:
                self.handle_timeout()

    def recv(self) -> bytes:
        while True:
            if self.receive_seq_num in self.receive_buffer:
                data = self.receive_buffer[self.receive_seq_num]
                del self.receive_buffer[self.receive_seq_num]
                self.receive_seq_num += 1
                return data
            
            if self.fin_received and not self.receive_buffer:
                return b''
            
            time.sleep(0.01)

    def close(self) -> None:
        # wait for all data to be ACKed
        close_start_time = time.time()
        while self.send_base < self.next_seq_num:
            if time.time() - close_start_time > 5.0:  # 5 seconds
                break
            self.handle_timeout()
            time.sleep(0.01)
        
        # send FIN
        self.fin_sent = True
        fin_seq = self.next_seq_num
        hashed_val = self.compute_hash(fin_seq, self.FIN_PACKET, b'')
        fin_packet = struct.pack(self.header_form, fin_seq, self.FIN_PACKET, hashed_val)
        self.next_seq_num += 1
        
        # keep sending FIN until ACK ed
        fin_start_time = time.time()
        while not self.fin_acked:
            if time.time() - fin_start_time > 5.0:  # 5 seconds
                break
            # send FIN mroe times
            for _ in range(3):
                self.socket.sendto(fin_packet, (self.dst_ip, self.dst_port))
            time.sleep(self.ACK_TIMEOUT)
        
        # wait for FIN from other side
        wait_start = time.time()
        while not self.fin_received and time.time() - wait_start < 2.0:
            time.sleep(0.01)
        
        # clean up
        time.sleep(0.2)  # wait 2 seconds
        self.closed = True
        self.socket.stoprecv()
        self.executor.shutdown(wait=True)