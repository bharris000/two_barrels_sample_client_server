# An http server to connect to and service requests from a client
import logging
from re import T
import signal
import socket
import argparse
import sys
import time
import threading
import multiprocessing
from typing import List, Tuple
from pathlib import Path

# global array to hold threads/processes
concurrency_array = []

# Description:
#   creates an HTTP 1.1 status line for a response
# Args:
#   status_code: HTTP status code, 200 by default
def get_status_line(status_code: int = 200):
    code = str(status_code).encode()
    # codes used: 200, 400, 404, 405
    status = ""
    if status_code == 200:
        status = "OK"
    elif status_code == 400:
        status = "BAD_REQUEST"
    elif status_code == 404:
        status = "NOT_FOUND"
    elif status_code == 405:
        status = "METHOD_NOT_ALLOWED"
    else:
        status_code = 500
        status = "INTERNAL_SERVER_ERROR"
    return b"HTTP/1.1 " + code + b" " + status.encode() + b"\r\n"


# Description:
#   creates a HTTP header line for a response
# Args:
#   headers: array of tuples containing header type and value
def get_headers(headers: List[Tuple[bytes, bytes]]):
    return b"".join([key + b": " + value + b"\r\n" for key, value in headers])


# Description:
#   creates a full HTTP response containing status code, header, and body
# Args:
#   headers: array of tuples containing header type and value
#   status_code: HTTP status code, 200 OK by default
#   body: bytes data to be sent as body of response
def get_response(
    headers: List[Tuple[bytes, bytes]],
    status_code: int = 200,
    body: bytes = b"",
):
    if headers is None:
        headers = []
    if body:
        # as of now, only add Content-Length header
        headers.append((b"Content-Length", str(len(body)).encode("utf-8")))
    content = [
        get_status_line(status_code),
        get_headers(headers),
        b"\r\n" if body else b"",
        body,
    ]
    return b"".join(content)


# Description:
#   parses a received http request, creates a response with requested body
#   data, sends the response, closes socket; big thanks to resource below
#   for helping understand http flow and message parsing:
#   https://mleue.com/posts/simple-python-tcp-server/
# Args:
#   connectionSocket: socket descriptor obtained from socket.accept()
#   addr: address Tuple obtained from socket.accept()
def serve(connectionSocket, addr: Tuple[str, int]):
    # variables accessed by nested functions
    buffer = b""
    send_complete = False
    headers = []
    http_method = b""
    path_url = b""
    http_version = b""
    request_line_parsed = False
    header_line_parsed = False
    expected_body_length = 0
    malformed_request = False

    # Description:
    #   nested function to pop off the data buffer based on a delimiter
    # Args:
    #   separator: delimiter to pop from when seen
    # Returns the body before the delimiter
    def pop(separator: bytes):
        nonlocal buffer
        body, *remianing = buffer.split(separator, maxsplit=1)
        if not remianing:
            return None
        else:
            buffer = separator.join(remianing)
            return body

    # Description:
    #   nested function to clear a buffer and get a new temp version
    # Returns what was originally in the buffer
    def flush():
        nonlocal buffer
        temp = buffer
        buffer = b""
        return temp

    # Description:
    #   nested function to create an HTTP response once we have a full request.
    #   check to make sure request is a GET message then get file info and create
    #   response headers, then send repsonse
    def send_response():
        logging.info(f"METHOD:{http_method}")
        logging.info(f"URL:{serverFolder + path_url.decode()}")

        # client sent a malformed request, no body required
        if malformed_request:
            body = b""
            response = get_response(status_code=400, headers=[], body=body)
            if args.delay:
                logging.info("Waiting 5 seconds")
                time.sleep(5)
            connectionSocket.sendall(response)

        # not servicing anything but GET
        elif not http_method == b"GET":
            body = b"<html><body>not servicing anything but GET</body></html>"
            response = get_response(status_code=405, headers=[], body=body)
            if args.delay:
                logging.info("Waiting 5 seconds")
                time.sleep(5)
            connectionSocket.sendall(response)

        # if client sent GET and gave no url, show index
        elif path_url.decode() == "/":
            body = b""
            with open("www/index.jpg", "rb") as f:
                for chunk in read_in_chunks(f):
                    body += chunk
                response = get_response(status_code=200, headers=[], body=body)
            if args.delay:
                logging.info("Waiting 5 seconds")
                time.sleep(5)
            connectionSocket.sendall(response)

        # if it is a GET, we can service it
        else:
            body = b""
            path = Path(serverFolder + path_url.decode())
            # if file exists, read in file and make repsonse
            if path.is_file():
                with open(path, "rb") as f:
                    for chunk in read_in_chunks(f):
                        body += chunk
                response = get_response(status_code=200, headers=[], body=body)
            # if file does not exist, send 404 page
            else:
                with open("www/404.html", "rb") as f:
                    for chunk in read_in_chunks(f):
                        body += chunk
                response = get_response(status_code=404, headers=[], body=body)
            if args.delay:
                logging.info("Waiting 5 seconds")
                time.sleep(5)
            connectionSocket.sendall(response)

        logging.info("Response sent.")
        nonlocal send_complete
        send_complete = True

    # Description:
    #   recursive function that will parse all start lines, header lines, and
    #   body data until complete then send a response upon full receipt
    def parse():
        nonlocal expected_body_length, request_line_parsed
        nonlocal header_line_parsed, malformed_request
        try:
            if not request_line_parsed:
                parse_request_line()
            elif not header_line_parsed:
                parse_header_line()
            elif expected_body_length:
                data = flush()
                expected_body_length -= len(data)
                logging.debug(f"Received body: {data}")
                parse()
            else:
                logging.info("Received request completely.")
                send_response()
        except:
            logging.warning("malformed request")
            malformed_request = True

    # Description:
    #   gets method, path url, and version from request startline
    def parse_request_line():
        nonlocal buffer, headers
        line = pop(separator=b"\r\n")
        if line is not None:
            nonlocal http_method, path_url, http_version, request_line_parsed
            http_method, path_url, http_version = line.strip().split()
            request_line_parsed = True
            logging.debug(f"Received path url: {path_url}")
            headers = []
            parse()

    # Description:
    #   gets header field name and value from a single header and calls
    #   helper to store in array
    def parse_header_line():
        nonlocal buffer, header_line_parsed, expected_body_length
        line = pop(separator=b"\r\n")
        if line is not None:
            if line:
                name, value = line.strip().split(b": ", maxsplit=1)
                if name.lower() == b"content-length":
                    expected_body_length = int(value.decode("utf-8"))
                logging.debug(f"Received header: ({name}, {value})")
                headers.append((name, value))
            else:
                header_line_parsed = True
            parse()

    while True:
        if send_complete:
            break
        data = connectionSocket.recv(1024)
        if not data:
            logging.warning("Client disconnected...")
            break
        logging.debug(f"Received {data}")
        buffer += data
        parse()
    connectionSocket.close()  # may have to move this out of function to allow threading?
    logging.debug(f"Socket with {addr} closed.")


# Description:
#   a helper function to read in chunks from a file since pre-3.8 python
#   does not support the walrus operator, courtesy of provided resource
#   https://www.iditect.com/guide/python/python_howto_read_big_file_in_chunks.html
# Args:
#   file: a file that must exist
#   chunk_size: bytes to read at a time, default chunk size: 10k.
def read_in_chunks(file, chunk_size=1024 * 10):
    while True:
        chunk = file.read(chunk_size)
        if chunk:
            yield chunk
        else:
            return


# default values
serverPort = 8085
serverHost = "localhost"
serverFolder = "."
concurrencyMethod = "thread"

# parsing:
# accepts no arguments and four options
parser = argparse.ArgumentParser()
parser.add_argument(
    "-v", "--verbose", action="store_true", help="Turn on debugging output"
)
parser.add_argument(
    "-d",
    "--delay",
    action="store_true",
    help="Add a 5 second delay for debugging purposes",
)
parser.add_argument("-p", "--port", type=int, help="Port to bind to")
parser.add_argument("-f", "--folder", help="Folder from where to serve")
parser.add_argument(
    "-c", "--concurrency", choices=["thread", "process"], help="Concurrency method"
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
    serverPort = args.port
# set reference folder
if args.folder:
    serverFolder = args.folder
# set concurrency method
if args.concurrency:
    concurrencyMethod = args.concurrency
logging.info(f"Concurrency method: {concurrencyMethod}")

try:
    # open a socket and start listening
    logging.info("Opening a socket")
    logging.debug("Server port: %d", serverPort)
    logging.debug("Server host: %s", serverHost)
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serverSocket.bind((serverHost, serverPort))
    serverSocket.listen()
    logging.info("The server is ready to receive")

except:
    sys.exit("Error occurred while opeining a socket")

try:
    # wait to accept then run server, KeyboardInterrupt will terminate
    while True:
        logging.info("Socket is open to accept a client")
        connectionSocket, addr = serverSocket.accept()
        logging.info(f"Socket accepted with {addr}.")
        # run server based on desired concurrency method
        if concurrencyMethod == "thread":
            server_thread = threading.Thread(
                target=serve,
                args=(
                    connectionSocket,
                    addr,
                ),
            )
            # start thread and add it to the working array
            server_thread.start()
            concurrency_array.append(server_thread)
            logging.debug(f"Adding thread: {server_thread.name}")
        elif concurrencyMethod == "process":
            server_process = multiprocessing.Process(
                target=serve,
                args=(
                    connectionSocket,
                    addr,
                ),
            )
            # start process and add it to the working array
            server_process.start()
            concurrency_array.append(server_process)
            logging.debug(f"Adding process: {server_process.name}")

        logging.info("Session complete, connection closed")

except KeyboardInterrupt:
    logging.warning("Program terminated")
    # join all processes/threads
    for t in concurrency_array:
        t.join()

except:
    logging.error("Error occurred during transmission")
