import sys
import argparse
import logging
import time
import threading
from paho.mqtt import client as mqtt_client

# default values
port = 1883
broker = "localhost"

# parsing:
# accepts three arguments and four options
parser = argparse.ArgumentParser()
parser.add_argument("netid")
parser.add_argument("action")
parser.add_argument("message")
parser.add_argument("-p", "--port", type=int)
parser.add_argument("--host")
parser.add_argument("-v", "--verbose", action="store_true")
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
# set host
if args.host:
    broker = args.host

logging.info(f"Port: {port}")
logging.info(f"Host: {broker}")

# set message to publish
publish_topic = args.netid + "/" + args.action + "/request"
subscribe_topic = args.netid + "/" + args.action + "/response"
payload = args.message

logging.info(f"Publish Topic: {publish_topic}")
logging.info(f"Subscribe Topic: {subscribe_topic}")
logging.info(f"Payload: {payload}")

# global to block until we have a message received
recieved = False

# Description:
#   connect to an MQTT broker based on program arguments
# Returns an MQTT client object
def connect_mqtt():
    # Description: nested callback function for output upon established connection
    def on_connect(client, userdata, flags, rc):
        if rc == 0:
            logging.info("Connected to MQTT Broker!")
        else:
            logging.error("Failed to connect, return code %d\n", rc)

    client = mqtt_client.Client(args.netid)
    client.on_connect = on_connect
    client.connect(broker, port)
    return client


# Description:
#   publish a request to a broker with publish_topic and payload based on args
# Args:
#   client: client object with necessary userID info and with connection already
#       established to broker/port
def publish(client):
    result = client.publish(publish_topic, payload)
    # result: [0, 1]
    status = result[0]
    if status == 0:
        logging.debug(f"Sending `{payload}` to topic `{publish_topic}`")
    else:
        logging.error(f"Failed to send message to topic {publish_topic}")


# Description:
#   subscribe to broker and receive message with subscribe_topic based on args
# Args:
#   client: client object with necessary userID info and with connection already
#       established to broker/port
def subscribe(client):
    # Description: nested callback function for output upon receiving message
    def on_message(client, userdata, msg):
        global recieved
        logging.debug(f"Received `{msg.payload.decode()}` from `{msg.topic}` topic")
        print(msg.payload.decode())
        recieved = True

    client.on_message = on_message
    client.subscribe(subscribe_topic)


try:
    # establish a connection
    client = connect_mqtt()
    client.loop_start()
    # subscribe to the response topic
    subscribe(client)
    # publish to the request topic
    publish(client)
    # wait until we have a message from response subscription
    while not recieved:
        time.sleep(0.1)
    client.loop_stop()
    client.disconnect()

except KeyboardInterrupt:
    logging.warning("Program terminated")
    client.disconnect()
except:
    logging.error("Error during transmission")
    client.disconnect()
