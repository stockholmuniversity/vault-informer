import argparse
import importlib
import json
import logging
import os
import pkgutil
import sys

import pyinotify

from plugins import MessageBusPlugin

# Default vault audit log file.
VAULT_AUDIT_LOGFILE = "/local/vault/logs/audit.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


class EventHandler(pyinotify.ProcessEvent):
    def __init__(self, file_path, plugin):
        super().__init__()
        self.file_path = file_path
        self.plugin = plugin
        self.reset_state()
        self.initialize_last_position()

    def initialize_last_position(self):
        with open(self.file_path, "r", encoding="utf-8") as f:
            f.seek(0, os.SEEK_END)
            self.last_position = f.tell()

    def reset_state(self):
        self.buffered_line = ""
        self.open_braces = 0
        self.close_braces = 0

    def process_line(self, line):
        self.buffered_line += line.strip()
        self.open_braces += line.count("{")
        self.close_braces += line.count("}")

        if self.open_braces == self.close_braces and self.open_braces > 0:
            try:
                vault_log_entry = json.loads(self.buffered_line)
                logline = read_logline(vault_log_entry)
                if logline is not None:
                    logging.debug("Log line: %s", logline)
                    message = json.dumps(logline)
                    self.plugin.produce_msg(message)
                self.reset_state()
            except json.JSONDecodeError:
                logging.error("Could not decode line: %s", self.buffered_line)
                self.reset_state()

    def handle_file_rotation(self):
        logging.info("Log file rotated or deleted")
        self.reset_state()
        self.initialize_last_position()

    def process_IN_MOVE_SELF(self, event):
        if event.pathname == self.file_path:
            self.handle_file_rotation()

    def process_IN_DELETE(self, event):
        if event.pathname == self.file_path:
            self.handle_file_rotation()

    def process_IN_MODIFY(self, event):
        if event.pathname == self.file_path:
            with open(self.file_path, "r", encoding="utf-8") as f:
                f.seek(self.last_position)
                while True:
                    line = f.readline()
                    if not line:
                        break
                    # pylint: disable=W0201
                    self.last_position = f.tell()
                    self.process_line(line)

    def process_IN_CREATE(self, event):
        if event.pathname == self.file_path:
            logging.info("Log file created")
            self.initialize_last_position()


def discover_plugins():
    plugins = {}
    package_name = "plugins"

    for _, module_name, _ in pkgutil.iter_modules([package_name]):
        module = importlib.import_module("{}.{}".format(package_name, module_name))

        for _, cls in module.__dict__.items():
            if (
                isinstance(cls, type)
                and issubclass(cls, MessageBusPlugin)
                and cls is not MessageBusPlugin
            ):
                plugins[module_name] = cls()

    return plugins


def filter_sensitive_data(data):
    if isinstance(data, str):
        if data.lower().startswith("hmac"):
            return "REDACTED"
        return data

    if isinstance(data, dict):
        return {key: filter_sensitive_data(value) for key, value in data.items()}

    if isinstance(data, list):
        return [filter_sensitive_data(item) for item in data]

    return data


def read_logline(logline):
    try:
        if not isinstance(logline, dict):
            raise ValueError("Input must be a dictionary.")

        if logline["type"] == "request":
            if logline["request"]["operation"] in ["update", "create", "delete"]:
                error_status = logline.get("error", None)
                if error_status is None:
                    logline = filter_sensitive_data(logline)
                    return logline

        return None
    except ValueError as ve:
        logging.error("An error occurred: %s", ve)
        return None
    # pylint: disable=W0703
    except Exception as e:
        logging.error("An unexpected error occurred: %s", e)
        return None


def watch_messages(file_path, plugin):
    file_dir = os.path.dirname(file_path)

    wm = pyinotify.WatchManager()
    handler = EventHandler(file_path, plugin)
    notifier = pyinotify.Notifier(wm, default_proc_fun=handler)

    # pylint: disable=E1101
    mask = (
        pyinotify.IN_MODIFY
        | pyinotify.IN_MOVE_SELF
        | pyinotify.IN_CREATE
        | pyinotify.IN_DELETE
    )

    wm.add_watch(file_dir, mask)

    try:
        notifier.loop()
    finally:
        notifier.stop()


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(description="Process some integers.")
    parser.add_argument(
        "--list-plugins",
        dest="list_plugins",
        action="store_true",
        help="List available plugins and exit.",
    )
    parser.add_argument(
        "-p", "--plugin", dest="plugin", help="Specify the plugin to use."
    )
    parser.add_argument(
        "-f",
        "--filename",
        dest="filename",
        default=VAULT_AUDIT_LOGFILE,
        help="Specify the filename to monitor. Defaults to VAULT_AUDIT_LOGFILE.",
    )

    args = parser.parse_args(argv)

    available_plugins = discover_plugins()

    if args.list_plugins:
        print("Available Plugins:")
        for plugin_name in available_plugins:
            print("  - %s" % plugin_name)
        sys.exit()

    if args.plugin:
        plugin_to_use = args.plugin
        print("Looking for plugin: {}".format(plugin_to_use))
    else:
        parser.print_help()
        sys.exit(2)

    vault_audit_logfile = args.filename
    print("Using audit logfile: {}".format(vault_audit_logfile))

    plugin = available_plugins.get(plugin_to_use)

    if plugin:
        watch_messages(vault_audit_logfile, plugin)
    else:
        print("Plugin {} not found.".format(plugin_to_use))
        sys.exit(2)


if __name__ == "__main__":
    main()
