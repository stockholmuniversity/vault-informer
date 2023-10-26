import getopt
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
    def __init__(self, file_name, plugin):
        super().__init__()
        self.file_name = file_name
        self.plugin = plugin
        self.buffered_line = ""
        self.open_braces = 0
        self.close_braces = 0
        self.last_position = 0

        with open(self.file_name, "r", encoding="utf-8") as f:
            f.seek(0, os.SEEK_END)
            self.last_position = f.tell()

    def process_IN_MOVE_SELF(self, event):
        if event.pathname == self.file_name:
            logging.info("Log file rotated")
            self.last_position = 0
            self.buffered_line = ""
            self.open_braces = 0
            self.close_braces = 0

    def process_IN_MODIFY(self, event):
        if event.pathname == self.file_name:
            with open(self.file_name, "r", encoding="utf-8") as f:
                f.seek(self.last_position)
                while True:
                    line = f.readline()
                    if not line:
                        break
                    self.last_position = f.tell()

                    self.buffered_line += line.strip()
                    self.open_braces += line.count("{")
                    self.close_braces += line.count("}")

                    if self.open_braces == self.close_braces and self.open_braces > 0:
                        try:
                            vault_log_entry = json.loads(self.buffered_line)
                            logline = read_logline(vault_log_entry)
                            if logline is not None:
                                print("Log line: {}".format(logline))
                                message = json.dumps(logline)
                                self.plugin.produce_msg(message)
                            self.buffered_line = ""
                            self.open_braces = 0
                            self.close_braces = 0

                        except json.JSONDecodeError:
                            logging.error(
                                "Could not decode line: %s", self.buffered_line
                            )
                            self.buffered_line = ""
                            self.open_braces = 0
                            self.close_braces = 0


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
        print("An error occurred: {}".format(ve))
        return None
    # pylint: disable=W0703
    except Exception as e:
        print("An unexpected error occurred: {}".format(e))
        return None


def watch_messages(file_path, plugin):
    file_dir = os.path.dirname(file_path)

    wm = pyinotify.WatchManager()
    handler = EventHandler(file_path, plugin)
    notifier = pyinotify.Notifier(wm, default_proc_fun=handler)

    # pylint: disable=E1101
    mask = pyinotify.IN_MODIFY | pyinotify.IN_MOVE_SELF
    wm.add_watch(file_dir, mask)

    try:
        notifier.loop()
    finally:
        notifier.stop()


def main(argv):
    short_options = "hlp:f:"
    long_options = ["help", "list-plugins", "plugin=", "filename="]
    plugin_to_use = None
    vault_audit_logfile = VAULT_AUDIT_LOGFILE

    try:
        arguments, _ = getopt.getopt(argv, short_options, long_options)
    except getopt.error as err:
        print(str(err))
        sys.exit(2)

    # If no arguments are provided, display the help text
    if not arguments:
        print("Usage: python main.py --plugin <plugin_name> [--list-plugins]")
        sys.exit()

    available_plugins = discover_plugins()

    for current_argument, current_value in arguments:
        if current_argument in ("-h", "--help"):
            print(
                "Usage: python main.py --plugin <plugin_name> [--list-plugins] [-f <filename>]"
            )
            sys.exit()
        elif current_argument in ("-l", "--list-plugins"):
            print("Available Plugins:")
            for plugin_name in available_plugins:
                print("  - %s" % plugin_name)
            sys.exit()
        elif current_argument in ("-p", "--plugin"):
            plugin_to_use = current_value
        elif current_argument in ("-f", "--filename"):
            vault_audit_logfile = current_value

    # Debug print for plugin to use
    print("Looking for plugin: {}".format(plugin_to_use))
    print("Using audit logfile: {}".format(vault_audit_logfile))

    plugin = available_plugins.get(plugin_to_use)

    if plugin:
        watch_messages(vault_audit_logfile, plugin)
        return

    print("Plugin {} not found.".format(plugin_to_use))


if __name__ == "__main__":
    main(sys.argv[1:])
