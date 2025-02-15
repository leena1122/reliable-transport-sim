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
            for seq_num in range(self.send_base, self.next_seq_num):
                if seq_num in self.send_buffer:
                    self.socket.sendto(self.send_buffer[seq_num], 
                                       (self.dst_ip, self.dst_port))
            self.last_retransmit = current_time

    def listener(self):
        while not self.closed:
            try:
                segment, addr = self.socket.recvfrom()
                if len(segment) < self.header_size:
                    continue  # ignore malformed

                # parse out the header
                header = segment[:self.header_size]
                data = segment[self.header_size:]
                seq_num, packet_type, received_hash = struct.unpack(self.header_form, header)

                # for the packets, check that the hash is right before processing
                if packet_type == self.DATA_PACKET:
                    # handle data packet
                    computed_hash = self.compute_hash(seq_num, packet_type, data)
                    if computed_hash != received_hash:
                        # has doesn't match, the packet is corrupted and will be disacrded
                        continue  # skip the packet, it will be retransmitted

                    # if correct, store and ACK
                    self.receive_buffer[seq_num] = data
                    hashed_val = self.compute_hash(seq_num, self.ACK_PACKET, b'')  # no data
                    ack_header = struct.pack(self.header_form, seq_num, self.ACK_PACKET, hashed_val)
                    self.socket.sendto(ack_header, (self.dst_ip, self.dst_port))
                
                elif packet_type == self.ACK_PACKET:  
                    # handle received ACK
                    if seq_num >= self.send_base:  # update send window
                        self.send_base = seq_num + 1
                        self.retransmit_attempts = 0  # reset the attempts on the case of asuccessful ACK
                        keys_to_remove = [k for k in self.send_buffer.keys() if k <= seq_num]
                        for k in keys_to_remove:
                            del self.send_buffer[k]

                        if self.fin_sent and seq_num == self.next_seq_num - 1:
                            self.fin_acked = True
                        if self.send_base == self.next_seq_num:
                            self.all_data_acked = True
                
                elif packet_type == self.FIN_PACKET:
                    # handle received FIN
                    self.fin_received = True
                    # send ACK for FIN
                    for _ in range(5):  # send more ACKs for FIN
                        hashed_val = self.compute_hash(seq_num, self.ACK_PACKET, b'')
                        ack_packet = struct.pack(self.header_form, seq_num, self.ACK_PACKET, hashed_val)
                        self.socket.sendto(ack_packet, (self.dst_ip, self.dst_port))

                else: # unknown type, discard
                    continue

            except Exception as e:
                if not self.closed:
                    print("listener died!")
                    print(e)

    def send(self, data_bytes: bytes) -> None:
        """Note that data_bytes can be larger than one packet."""
        # breaking the data into chunks and sending each chunk
        offset = 0
        while offset < len(data_bytes):
            # get the next chunk of data
            max_data = self.max_size - self.header_size
            end = min(offset + max_data, len(data_bytes))
            chunk = data_bytes[offset:end]
            
            # wait if window is full
            while self.next_seq_num >= self.send_base + self.window_size: ##
                self.handle_timeout() ##
                time.sleep(0.01) ##
            
            # send the packet
            hashed_val = self.compute_hash(self.next_seq_num, self.DATA_PACKET, chunk)
            header = struct.pack(self.header_form, self.next_seq_num, self.DATA_PACKET, hashed_val)
            segment = header + chunk
            self.socket.sendto(segment, (self.dst_ip, self.dst_port))
      
            # store in send buffer and update sequence number
            self.send_buffer[self.next_seq_num] = segment
            self.next_seq_num += 1
            offset = end
            
            # check for timeouts
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