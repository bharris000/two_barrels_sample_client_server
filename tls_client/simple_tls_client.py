import argparse
import logging
import sys
import socket
import cryptography
import secrets
import crypto_utils
import message
import struct

# default values
server_port = 8087
server_host = "localhost"

# parse arguments
# accepts one argument and four options
parser = argparse.ArgumentParser()
parser.add_argument(
    "file",
    help="The file name to save to. It must be a PNG file extension. Use - for stdout",
)
parser.add_argument("-p", "--port", type=int, help="Port to connect to")
parser.add_argument("--host", help="Hostname to connect to")
parser.add_argument(
    "-v", "--verbose", action="store_true", help="Turn on debugging output"
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
    server_port = args.port
# set host
if args.host:
    server_host = args.host

logging.info(f"Port: {server_port}")
logging.info(f"Host: {server_host}")

try:
    # create a socket and connect to server
    logging.info("Opening a socket")
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_host, server_port))
    logging.info("Socket connected successfully")

except:
    sys.exit("Error occurred while opeining a socket")

# send an initial hello message with no data
client_hello_message = message.Message(message.MessageType.HELLO)
logging.info("Sending hello message to server")
client_socket.sendall(client_hello_message.to_bytes())

# receive nonce + certificate, first 32 bytes will be nonce
server_certificate_message = message.Message.from_socket(client_socket)
logging.info("Received server certificate message")
server_nonce = server_certificate_message.data[:32]
server_certificate = server_certificate_message.data[32:]

# verify certificate
verified_certificate = crypto_utils.load_certificate(server_certificate)
if verified_certificate is None:
    logging.error("Certificate verification failed, exiting")
    sys.exit("WE ARE UNDER ATTACK")
logging.info("Server certificate verified")

# generate nonce
client_nonce = secrets.token_bytes(32)

# encrypt nonce
server_public_key = verified_certificate.public_key()
encyrpted_nonce = crypto_utils.encrypt_with_public_key(server_public_key, client_nonce)
logging.info("Client nonce encrypted")

# send encrypted nonce
client_nonce_message = message.Message(message.MessageType.NONCE, encyrpted_nonce)
client_socket.sendall(client_nonce_message.to_bytes())
logging.info("Sending client nonce message")

# generate master secret
(
    server_encrypt_key,
    server_data_key,
    client_encrypt_key,
    client_data_key,
) = crypto_utils.generate_keys(client_nonce, server_nonce)
logging.info("Keys generated")

# receive server hash
server_hash_message = message.Message.from_socket(client_socket)
logging.info("Received server hash message")

# verify server hash
data_to_hash = (
    client_hello_message.to_bytes()
    + server_certificate_message.to_bytes()
    + client_nonce_message.to_bytes()
)
expected_server_hash = crypto_utils.mac(data_to_hash, server_data_key)
if server_hash_message.data != expected_server_hash:
    logging.error("Server hash verification failed, exiting")
    sys.exit("WE ARE UNDER ATTACK")
logging.info("Server hash verified")

# send client hash
client_hash = crypto_utils.mac(data_to_hash, client_data_key)
client_hash_message = message.Message(message.MessageType.HASH, client_hash)
client_socket.sendall(client_hash_message.to_bytes())
logging.info("Sending client hash message")

sequence_number = 0
image = bytes(0)
while True:
    # receive encrypted data
    data_message = message.Message.from_socket(client_socket)
    if data_message is None:
        break
    logging.info("Received encrypted data from server")

    # decrypt using server encryption key
    decrypted_payload = crypto_utils.decrypt(data_message.data, server_encrypt_key)
    received_sequence_num = struct.unpack(">L", decrypted_payload[:4])[0]
    received_chunk = decrypted_payload[4:-32]
    received_mac = decrypted_payload[-32:]

    # verify sequence number
    logging.debug(f"Expected sequence number: {sequence_number}")
    logging.debug(f"Server sequence number: {received_sequence_num}")
    if received_sequence_num != sequence_number:
        logging.error("Sequence verification failed, exiting")
        sys.exit("WE ARE UNDER ATTACK")
    sequence_number += 1

    # caculate MAC on chunk using server data key
    calculated_mac = crypto_utils.mac(received_chunk, server_data_key)

    # verify MAC
    if received_mac != calculated_mac:
        logging.error("MAC verification failed, exiting")
        sys.exit("WE ARE UNDER ATTACK")

    logging.info("Sequence and MAC verified")
    image += received_chunk

# save data into file stream
if args.file == "-":
    # print to stdout
    sys.stdout.buffer.write(image)
    logging.info("Image bytes written to stdout")
else:
    # save to file
    with open(args.file, "wb") as f:
        f.write(image)
    logging.info("Image saved")
