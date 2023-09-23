import argparse
import hashlib
import logging
import json
import struct
import queue
import sys
import socket
import socketserver
import threading
import time
import requests
import collections


port = 8088

# parse arguments
# accepts one argument and four options
parser = argparse.ArgumentParser()
parser.add_argument("netid", help="Your NetID.")
parser.add_argument(
    "torrent_file", help="The torrent file for the file you want to download."
)
parser.add_argument(
    "-p", "--port", type=int, help="The port to receive peer connections from."
)
parser.add_argument("-d", "--dest", help="The folder to download to and seed from.")
parser.add_argument(
    "-v", "--verbose", action="store_true", help="Turn on debugging messages."
)
args = parser.parse_args()

# set verbosity
if args.verbose:
    logging.basicConfig(level=logging.DEBUG)
    logging.info("Verbosity turned on")
else:
    logging.basicConfig(level=logging.CRITICAL)
# set port
if args.port:
    if args.port > 65535 or args.port < 1:
        logging.error("Port must be between 1 and 65535")
        sys.exit("Invalid port number")
    port = args.port

# parse json file
f = open(args.torrent_file)
torrent = json.load(f)
torrent_id = bytes.fromhex(torrent["torrent_id"])
tracker_url = torrent["tracker_url"]
file_size = int(torrent["file_size"])
file_name = torrent["file_name"]
piece_size = int(torrent["piece_size"])
pieces = torrent["pieces"]
f.close()
logging.debug("JSON file parsed")

# create a bitfield of all zeros to track what we have (pad to nearest byte)
num_pieces = int(file_size / piece_size) + 1  # FIXME
my_bitfield = [False] * (num_pieces + (8 - (num_pieces % 8)) % 8)

# create an array to hold all info we have
piece_array = [0] * num_pieces

# get private ip address
IP_addres = socket.gethostbyname(socket.gethostname())

# make a queue of peers to upload to and download from
peers = queue.Queue(maxsize=5)

# Description:
#   int object to bytes object
# Args:
#   x: and int object to tranform to bytes
# Returns a bytes object of input int value
def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, "big")


# Description:
#   bytes object to int object
# Args:
#   xbytes: and bytes object to tranform to int
# Returns an int object of input bytes value
def int_from_bytes(xbytes: bytes) -> int:
    return int.from_bytes(xbytes, "big")


# Description:
#   create message complicit with outlined protocol: 8 bit verison (always 1),
#   8 bit message type, 16 bit message length, variable lenght payload
# Args:
#   message_type: type of message to send
#       0x01: hello request
#       0x02: hello response
#       0x03: piece request
#       0x04: piece response
#       0x05: error
#   payload: variable length bytes object payload to send in message
# Returns a formatted bytes object message to send
def create_message(message_type, payload):
    version = 0x01 << 24
    message_type = message_type << 16
    header = version + message_type + len(payload)
    return int_to_bytes(header) + payload


# Description:
#   downloads all bytes info in global "piece_array" to folder specified in CLI
#   file name will be name found in torrent file
def download_file():
    destination = args.dest + "/" + file_name
    with open(destination, "wb") as f:
        for p in piece_array:
            f.write(p)
    logging.info(f"File saved to {destination}")


# Description
#   make request to tracker_url and update queue of peers
def contact_tracker():
    global peers
    while True:
        payload = {
            "peer_id": ("-ECEN426-" + args.netid),
            "ip": IP_addres,
            "port": port,
            "torrent_id": torrent["torrent_id"],
        }
        r = requests.get(tracker_url, params=payload)

        # parse response
        response = json.loads(r.text)
        interval = response["interval"]
        logging.debug(f"Interval: {interval}")
        for p in response["peers"]:
            logging.debug(f"Peer: {p}")
            peers.put(p)
        logging.info("Queue updated")
        time.sleep(interval)


# Description:
#   connect to a peer, respond to requests, send data we have; serves forever
def upload_to_peer():
    logging.info("Uploader running")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("", port))
    server_socket.listen(1)
    logging.info("Ready to receive requests from other peers")
    while True:
        upload_socket, upload_addr = server_socket.accept()
        while True:
            # receive 32 bits for header and parse info
            received_header = upload_socket.recv(4)
            print(received_header)
            received_version = received_header[:1]
            print(received_version)
            received_type = received_header[1:2]
            print(received_type)
            received_length = received_header[2:4]
            received_payload = upload_socket.recv(int_from_bytes(received_length))

            # if there are no more requests, break
            if not received_header:
                logging.warning("Peer disconnected...")
                break
            if received_version != int_to_bytes(0x01):
                logging.error("Incorrcet version number, cannot support")
                break
            if received_type == int_to_bytes(0x01):
                # send hello response
                bitfield_as_int = int("".join(map(str, map(int, my_bitfield))), 2)

                hello_response = create_message(0x02, int_to_bytes(bitfield_as_int))
                logging.info("Sending hello response")
                server_socket.sendall(hello_response)
            elif received_type == int_to_bytes(0x03):
                # send piece response based on index seen in payload
                if received_payload < len(piece_array):
                    piece_response = create_message(0x04, piece_array[received_payload])
                    server_socket.sendall(piece_response)
                    logging.info("Sending piece response")
                else:
                    error_response = create_message(
                        0x05, ("Piece index out of range").encode()
                    )
                    server_socket.sendall(error_response)
                    logging.info("Sending error message")
            else:
                error_response = create_message(0x05, ("Bad message type").encode())
                server_socket.sendall(error_response)
                logging.info("Sending error message")
    return


# Description:
#   connect to a peer, send NibbleTorrent request, request and save piece of file
# Args:
#   peer_queue: a Queue structure of peers that is populated by contacting the trakcer
def download_from_peer(peer_queue):
    logging.info("Downloader running")
    while True:
        current_peer = peer_queue.get()
        while True:
            peer_ip_port = current_peer[0]
            peer_netid = current_peer[1]
            # switch comments here to test with only bot, so as to not rely on other peers
            # if peer_netid != "-ECEN426-botuploader":
            if peer_netid == "-ECEN426-" + args.netid:
                break

            # start TCP connection
            [peer_ip, peer_port] = peer_ip_port.split(":")
            peer_port = int(peer_port)
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((peer_ip, peer_port))
            logging.info("Connected to peer.")
            logging.debug(f"IP: {peer_ip} Port: {peer_port} NetID: {peer_netid}")

            # send hello request
            hello_request = create_message(0x01, torrent_id)
            client_socket.sendall(hello_request)
            logging.debug("Sending hello request")

            # recv hello response and get bitfield of pieces peer has
            hello_response = client_socket.recv(65540)
            hello_response_bitfield = hello_response[4:]
            hello_response_bitfield = "".join(
                format(byte, "08b") for byte in hello_response_bitfield
            )

            # select piece of file to download and check that peer has it
            piece_index = 0
            for b in my_bitfield:
                if (b is False) and (hello_response_bitfield[piece_index] == "1"):
                    break
                piece_index += 1

            if piece_index == len(piece_array):
                # peer did not have any piece that we did not have
                logging.warning("Peer did not have a piece we did not have")
                break

            # request piece
            piece_request = create_message(0x03, int_to_bytes(piece_index))
            client_socket.sendall(piece_request)
            logging.debug("Sending piece request")
            piece_response = client_socket.recv(65540)
            piece_payload = piece_response[4:]

            # compare hashes
            if hashlib.sha1(piece_payload).hexdigest() != pieces[piece_index]:
                logging.error("Mismatched hash, piece not saved")
                continue

            # save piece of file
            piece_array[piece_index] = piece_payload
            logging.info("Piece saved to array")
            my_bitfield[piece_index] = 1

            # check if we have full file and can stop
            pieces_held = 0
            for p in piece_array:
                if p == 0:
                    # not done
                    break
                pieces_held += 1

            # quit if we have a full file
            if pieces_held == num_pieces:
                logging.info("We have a full file!")
                download_file()
                return


try:
    thread_array = []
    # tracker thread to constantly connect to tracker
    tracker_thread = threading.Thread(
        target=contact_tracker,
        args=(),
    )
    # start thread and add it to the working array
    tracker_thread.start()
    thread_array.append(tracker_thread)
    logging.debug(f"Adding thread: {tracker_thread.name}")

    # make an upload thread to listen for other peers
    upload_thread = threading.Thread(
        target=upload_to_peer,
        args=(),
    )
    # start thread and add it to the working array
    upload_thread.start()
    thread_array.append(upload_thread)
    logging.debug(f"Adding thread: {upload_thread.name}")

    # download thread to take a peer from queue populated by tracker
    download_thread = threading.Thread(
        target=download_from_peer,
        args=(peers,),
    )
    # start thread and add it to the working array
    download_thread.start()
    thread_array.append(download_thread)
    logging.debug(f"Adding thread: {download_thread.name}")

except KeyboardInterrupt:
    logging.warning("Program Terminated")
    for t in thread_array:
        t.join()

except:
    logging.error("Network failure")
    for t in thread_array:
        t.join()
