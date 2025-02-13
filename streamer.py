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

        self.send_seq_num = 0 
        self.receive_seq_num = 0
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

        # packet types
        self.DATA_PACKET = 0
        self.ACK_PACKET = 1
        self.FIN_PACKET = 2

    def compute_hash(self, seq_num: int, packet_type: int, data: bytes) -> bytes:
        header_without_md5 = struct.pack("!IB", seq_num, packet_type)
        return hashlib.md5(header_without_md5 + data).hexdigest().encode('ascii')

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
                    ack_header = self.make_header(seq_num, self.ACK_PACKET, b'')  # no data
                    self.socket.sendto(ack_header, (self.dst_ip, self.dst_port))

                elif packet_type == self.ACK_PACKET:
                    # handle received ACK
                    if seq_num == self.waiting_for_seq:
                        self.ack_received = True

                elif packet_type == self.FIN_PACKET:
                    # handle received FIN
                    self.fin_received = True
                    # send ACK for FIN
                    ack_header = self.make_header(seq_num, self.ACK_PACKET, b'')
                    #ack_header = struct.pack(self.header_form, seq_num, self.ACK_PACKET)
                    self.socket.sendto(ack_header, (self.dst_ip, self.dst_port))

                else: # unknown type, discard
                    continue

            except Exception as e:
                if not self.closed:
                    print("listener died!")
                    print(e)

    def make_header(self, seq_num: int, packet_type: int, data: bytes) -> bytes:
        """Build a header with an MD5 that covers (seq_num, packet_type, data)."""
        md5_val = self.compute_hash(seq_num, packet_type, data)
        return struct.pack(self.header_form, seq_num, packet_type, md5_val)

    def send(self, data_bytes: bytes) -> None:
        """Note that data_bytes can be larger than one packet."""
        # breaking the data into chunks and sending each chunk
        offset = 0
        while offset < len(data_bytes):
            # get the next chunk of data
            max_data = self.max_size - self.header_size
            end = min(offset + max_data, len(data_bytes))
            chunk = data_bytes[offset:end]

            # keep trying until ACK received
            while True:
                # segment w seq number, packet type, and chunk
                header = self.make_header(self.send_seq_num, self.DATA_PACKET, chunk)
                #header = struct.pack(self.header_form, self.send_seq_num, self.DATA_PACKET) #, chunk)
                # segment w seq number and packet type
                segment = header + chunk

                # send the chunk
                self.socket.sendto(segment, (self.dst_ip, self.dst_port))

                # Wait for ACK with timeout
                self.waiting_for_seq = self.send_seq_num
                self.ack_received = False
                start_time = time.time()

                while time.time() - start_time < self.ACK_TIMEOUT:
                    if self.ack_received:
                        break
                    time.sleep(0.01)

                if self.ack_received:
                    break
                # if no ACK received, retry the send

            # move to next chunk + update seq number
            self.send_seq_num += 1
            offset = end

    def recv(self) -> bytes:
        """Blocks (waits) if no data is ready to be read from the connection."""
        while True:
            # check if its the correct sequential seq number in buffer
            # if its the next packet in the buffer, return it
            current_seq = self.receive_seq_num
            if current_seq in self.receive_buffer:
                data = self.receive_buffer[current_seq]
                del self.receive_buffer[current_seq]
                self.receive_seq_num += 1
                return data
            
            if self.fin_received and not self.receive_buffer:
                return b''
            
            # otherwise wait a bit and check again
            time.sleep(0.01)

    def close(self) -> None:
        """Cleans up. It should block (wait) until the Streamer is done with all
           the necessary ACKs and retransmissions"""
        # send FIN until ACKed
        while not self.fin_acked:
            # send FIN packet
            fin_header = self.make_header(self.send_seq_num, self.FIN_PACKET, b'')
            #fin_header = struct.pack(self.header_form, self.send_seq_num, self.FIN_PACKET)
            self.socket.sendto(fin_header, (self.dst_ip, self.dst_port))

            # wait for ACK
            self.waiting_for_seq = self.send_seq_num
            self.ack_received = False
            start_time = time.time()

            while time.time() - start_time < self.ACK_TIMEOUT:
                if self.ack_received:
                    self.fin_acked = True
                    break
                time.sleep(0.01)

            if self.fin_acked: ##
                break ##

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