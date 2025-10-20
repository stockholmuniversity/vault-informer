import argparse
import importlib
import json
import logging
import os
import pkgutil
import sys

import pyinotify

from vault_informer.plugins import InformerPlugin

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
        self.file_descriptor = None
        self.watch_manager.add_watch(self.file_path, mask, rec=False, auto_add=True)
        self.open_file()
        self.reset_state()

    def open_file(self):
        try:
            self.file_descriptor = open(self.file_path, "r", encoding="utf-8")
            self.file_descriptor.seek(0, os.SEEK_END)
        except FileNotFoundError:
            log.warning("File not found during initialization: %s", self.file_path)

    def close_file(self):
        if self.file_descriptor:
            self.file_descriptor.close()
            self.file_descriptor = None

    def reset_state(self):
        self.buffered_line = ""
        self.open_braces = 0
        self.close_braces = 0

    def process_line(self, line):
        self.buffered_line += line.strip()
        self.open_braces += line.count("{")
        self.close_braces += line.count("}")

        # Try to process the buffered content when the brace counts match
        if self.open_braces == self.close_braces:
            # If brace count matches but is zero, we don't have a JSON to process
            if self.open_braces == 0:
                return

            # Attempt to decode the buffered JSON object
            try:
                vault_log_entry = json.loads(self.buffered_line)
                logline = read_logline(vault_log_entry)
                if logline is not None:
                    log.debug("Processed log line: %s", logline)
                    message = json.dumps(logline)
                    log.info("Produced message: %s", message)
                    self.plugin.handle_event(message)
                self.reset_state()
            except json.JSONDecodeError as ex:
                log.error(
                    "JSON decode error for buffered content: %s. Error: %s",
                    self.buffered_line,
                    ex,
                )
                # reset the state as this indicates that the buffered line will
                # never successfully parse.
                self.reset_state()

    def check_for_truncation(self):
        try:
            if os.path.getsize(self.file_path) < self.file_descriptor.tell():
                log.info("Log file truncated, resetting read position.")
                self.close_file()
                self.open_file()
        except FileNotFoundError:
            log.warning("File not found: %s", self.file_path)
            self.close_file()
            self.open_file()

    def process_IN_MODIFY(self, event):  # pylint: disable=invalid-name
        if event.pathname == self.file_path:
            self.check_for_truncation()

            data = self.file_descriptor.read()
            lines = data.split("\n")
            for line in lines:
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
    plugins = {}
    package_name = "vault_informer.plugins"
    plugin_package = importlib.import_module(package_name)

    for _, module_name, _ in pkgutil.iter_modules(
        plugin_package.__path__, plugin_package.__name__ + "."
    ):
        module = importlib.import_module(module_name)

        for _, cls in module.__dict__.items():
            if (
                isinstance(cls, type)
                and issubclass(cls, InformerPlugin)
                and cls is not InformerPlugin
            ):
                plugins[module_name.split(".")[-1]] = cls()

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
        default="/var/log/vault_audit.log",
        help="Specify the filename to monitor (default: %(default)s)",
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
        log.info("Looking for plugin: %s", plugin_to_use)
    else:
        parser.print_help()
        sys.exit(2)

    vault_audit_logfile = args.filename
    log.info("Using audit logfile: %s", vault_audit_logfile)

    plugin = available_plugins.get(plugin_to_use)

    if plugin:
        watch_messages(vault_audit_logfile, plugin)
    else:
        log.error("Plugin %s not found.", plugin_to_use)
        sys.exit(2)


if __name__ == "__main__":
    main()
