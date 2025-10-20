import argparse
import configparser
import json
import logging
import os
import sys
from importlib.metadata import entry_points

import pyinotify

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)
log = logging.getLogger(__name__)


class EventHandler(pyinotify.ProcessEvent):
    # pylint: disable=attribute-defined-outside-init
    def my_init(self, *, file_path, plugin):  # pylint: disable=arguments-differ
        self.file_path = file_path
        self.plugin = plugin
        self.watch_manager = pyinotify.WatchManager()
        mask = (
            # pylint: disable=no-member
            pyinotify.IN_MODIFY
            | pyinotify.IN_MOVE_SELF
            | pyinotify.IN_ATTRIB
            | pyinotify.IN_DELETE_SELF
        )
        self.watch_manager.add_watch(
            self.file_path.name, mask, rec=False, auto_add=True
        )
        self.open_file()

    def open_file(self):
        try:
            if self.file_path.closed:
                self.file_path = open(self.file_path.name, "r", encoding="utf-8")
            self.file_path.seek(0, os.SEEK_END)
        except FileNotFoundError:
            log.warning("File not found during initialization: %s", self.file_path.name)

    def close_file(self):
        self.file_path.close()

    def process_line(self, line):
        # Attempt to decode the JSON object
        try:
            vault_log_entry = json.loads(line)
            logline = read_logline(vault_log_entry)
            if logline is not None:
                log.debug("Processed log line: %s", logline)
                message = json.dumps(logline)
                log.info("Produced message: %s", message)
                self.plugin.handle_event(message)
        except json.JSONDecodeError as ex:
            log.error(
                "JSON decode error for buffered content: %r. Error: %s",
                line,
                ex,
            )

    def check_for_truncation(self):
        try:
            if os.path.getsize(self.file_path.name) < self.file_path.tell():
                log.info("Log file truncated, resetting read position.")
                self.close_file()
                self.open_file()
        except FileNotFoundError:
            log.warning("File not found: %s", self.file_path)
            self.close_file()
            self.open_file()

    def process_IN_MODIFY(self, event):  # pylint: disable=invalid-name
        if event.pathname == self.file_path.name:
            self.check_for_truncation()

            line = self.file_path.readline().strip()
            if line:
                self.process_line(line)

    def process_default(self, event):
        log.debug("Unhandled event: %s", event.maskname)

    def __del__(self):
        self.close_file()


def watch_messages(file_path, plugin):
    handler = EventHandler(file_path=file_path, plugin=plugin)
    notifier = pyinotify.Notifier(handler.watch_manager, default_proc_fun=handler)

    try:
        notifier.loop()
    finally:
        notifier.stop()


def discover_plugins():
    return entry_points().get("vault_informer.plugins", [])


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
    except ValueError as ex:
        log.error("An error occurred: %s", ex)
        return None
    except Exception as ex:  # pylint: disable=broad-except
        log.error("An unexpected error occurred: %s", ex)
        return None


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(
        description="Tail Vault audit log and send it elsewhere"
    )
    parser.add_argument(
        "--config",
        type=argparse.FileType("r", encoding="utf-8"),
        help="Config file",
        required=True,
    )
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
        type=argparse.FileType("r", encoding="utf-8"),
        default="/var/log/vault_audit.log",
        help="Specify the filename to monitor (default: %(default)s)",
    )

    args = parser.parse_args(argv)

    config = configparser.ConfigParser()
    with args.config as config_file:
        config.read_file(config_file)

    available_plugins = discover_plugins()

    if args.list_plugins:
        print("Available Plugins:")
        for plugin_name in available_plugins:
            print("  - %s" % plugin_name.name)
        sys.exit()

    plugin_name = config.get("vault_informer", "plugin")
    if args.plugin:
        plugin_name = args.plugin
    log.info("Looking for plugin: %s", plugin_name)

    plugin_class_name = next(
        iter(
            [ep for ep in available_plugins if ep.name == plugin_name],
        ),
        None,
    )
    if not plugin_class_name:
        log.fatal(
            "Tried to load plugin %r but failed to find it",
            plugin_name,
        )
        parser.print_help()
        sys.exit(2)

    log.info("Loaded plugin %r", plugin_class_name.name)

    plugin_class = plugin_class_name.load()
    plugin = plugin_class(config)

    log.info("Using audit logfile: %s", args.filename.name)

    watch_messages(args.filename, plugin)


if __name__ == "__main__":
    main()
