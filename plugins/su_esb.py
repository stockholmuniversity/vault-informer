import configparser
import logging
import ssl
import sys
import datetime
import os 

import stomp

from . import MessageBusPlugin

PRODUCER_CONFIGFILE = "conf/consumer_conf.ini"
CHECK_FILE_AGE_FILE = "/local/vault-informer/check_file_age_file"

log = logging.getLogger(__name__)

def touch_file(filename):
    try:
        # Update the modification time
        os.utime(filename, times=(datetime.datetime.now().timestamp(), datetime.datetime.now().timestamp()))
    except FileNotFoundError:
        # Create the file if it doesn't exist
        open(filename, 'a').close()

def load_config():
    cfg = configparser.ConfigParser()
    try:
        cfg.read(PRODUCER_CONFIGFILE)
    except configparser.Error as e:
        logging.error("Failed to read config: %s", e)
        sys.exit(1)

    return {
        "esb_host": cfg.get("esb", "hostname"),
        "esb_user": cfg.get("esb", "username"),
        "esb_password": cfg.get("esb", "password"),
        "esb_queue": cfg.get("esb", "queue"),
    }


# pylint: disable=too-few-public-methods
class ActiveMQ(MessageBusPlugin):
    def produce_msg(self, message):
        config = load_config()
        host = config["esb_host"]
        port = "61612"
        username = config["esb_user"]
        password = config["esb_password"]
        queue_name = config["esb_queue"]

        try:
            conn = stomp.Connection([(host, port)])
            conn.start()
            conn.set_ssl(for_hosts=[(host, port)], ssl_version=ssl.PROTOCOL_TLS)
            conn.connect(username, password, wait=True)
            conn.send(body=message, destination=queue_name)
            conn.disconnect()
            touch_file(CHECK_FILE_AGE_FILE)
        except Exception as e:  # pylint: disable=broad-except
            logging.error("Failed to produce message: %s", e)

        logging.info("Sending log to ActiveMQ: %s", message)
