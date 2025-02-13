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
        
        # Sequence number management
        self.send_base = 0  # first unacked packet
        self.next_seq_num = 0  # next sequence number to use
        self.receive_seq_num = 0
        self.window_size = 5  # number of packets that can be in flight
        self.send_buffer = {}  # store packets that might need retransmission
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
        self.ACK_TIMEOUT = 0.25
        self.fin_received = False
        self.fin_acked = False

        self.last_retransmit = 0
        self.RETRANSMIT_INTERVAL = 0.25

        # packet types
        self.DATA_PACKET = 0
        self.ACK_PACKET = 1
        self.FIN_PACKET = 2

    def compute_hash(self, seq_num: int, packet_type: int, data: bytes) -> bytes:
        header_without_md5 = struct.pack("!IB", seq_num, packet_type)
        return hashlib.md5(header_without_md5 + data).hexdigest().encode('ascii')

    def create_packet(self, seq_num: int, packet_type: int, data: bytes) -> bytes:
        hashed_val = self.compute_hash(seq_num, packet_type, data)
        header = struct.pack(self.header_form, seq_num, packet_type, hashed_val)
        return header + data

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
                        # Remove acknowledged packets from buffer
                        keys_to_remove = [k for k in self.send_buffer.keys() if k <= seq_num]
                        for k in keys_to_remove:
                            del self.send_buffer[k]
                
                elif packet_type == self.FIN_PACKET:
                    # handle received FIN
                    self.fin_received = True
                    # send ACK for FIN
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
            self.send_buffer[self.next_seq_num] = header
            self.next_seq_num += 1
            offset = end
            
            # check for timeouts
            self.handle_timeout()

    def recv(self) -> bytes:
        """Blocks (waits) if no data is ready to be read from the connection."""
        while True:
            # check if its the correct sequential seq number in buffer
            # if its the next packet in the buffer, return it
            if self.receive_seq_num in self.receive_buffer:
                data = self.receive_buffer[self.receive_seq_num]
                del self.receive_buffer[self.receive_seq_num]
                self.receive_seq_num += 1
                return data
            
            if self.fin_received and not self.receive_buffer:
                return b''
            
            # otherwise wait a bit and check again
            time.sleep(0.01)

    def close(self) -> None:
        """Cleans up. It should block (wait) until the Streamer is done with all
           the necessary ACKs and retransmissions"""
        # wait for all data to be ACK ed
        while self.send_base < self.next_seq_num:
            self.handle_timeout()
            time.sleep(0.01)
        
        # send FIN packet, let it be ACK ed
        fin_seq = self.next_seq_num
        while not self.fin_acked:
            fin_packet = self.create_packet(fin_seq, self.FIN_PACKET, b'')
            self.socket.sendto(fin_packet, (self.dst_ip, self.dst_port))
            
            # Wait for ACK with timeout
            start_time = time.time()
            while time.time() - start_time < self.ACK_TIMEOUT:
                if self.send_base > fin_seq:
                    self.fin_acked = True
                    break
                time.sleep(0.01)
            
            if self.fin_acked:
                break
        
        # wait for FIN from other side
        wait_start = time.time()
        while not self.fin_received and time.time() - wait_start < 2.0:
            time.sleep(0.01)

        # wait 2 seconds
        time.sleep(2.0)

        # clean up
        self.closed = True
        self.socket.stoprecv()
        self.executor.shutdown(wait=True)