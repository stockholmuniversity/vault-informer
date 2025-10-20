import datetime
import logging
import os
import ssl

import stomp
from vault_informer.plugins import InformerPlugin

CHECK_FILE_AGE_FILE = "/local/vault-informer/check_file_age_file"

log = logging.getLogger(__name__)


def touch_file(filename):
    try:
        # Update the modification time
        os.utime(
            filename,
            times=(
                datetime.datetime.now().timestamp(),
                datetime.datetime.now().timestamp(),
            ),
        )
    except FileNotFoundError:
        # Create the file if it doesn't exist
        open(filename, "a").close()


# pylint: disable=too-few-public-methods
class Stomp(InformerPlugin):
    def __init__(self, config):
        self.config = config

    def handle_event(self, message):
        host = self.config.get("plugins:stomp", "hostname")
        port = "61612"

        try:
            conn = stomp.Connection(
                [(host, port)],
                heartbeats=(4000, 4000),
                timeout=5,
                auto_content_length=False,
            )
            conn.start()
            conn.set_ssl(for_hosts=[(host, port)], ssl_version=ssl.PROTOCOL_TLS)
            conn.connect(
                self.config.get("plugins:stomp", "username"),
                self.config.get("plugins:stomp", "password"),
                wait=True,
            )
            conn.send(
                body=message, destination=self.config.get("plugins:stomp", "queue")
            )
            conn.disconnect()
            touch_file(CHECK_FILE_AGE_FILE)
        except Exception as ex:  # pylint: disable=broad-except
            log.error("Failed to produce message: %s", ex)

        log.info("Sending log to STOMP: %s", message)
