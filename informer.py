#!/usr/bin/env python3
import os
import sys
from optparse import OptionParser
from pathlib import Path

import pyinotify


class TailF:
    def __init__(self, path: Path):
        self.path = path

    def __iter__(self):
        self.a = 1
        return self

    def __next__(self):
        x = self.a
        self.a += 1
        return x


def main():
    parser = OptionParser()
    parser.add_option(
        "--debug", help="print debug messages", action="store_true", dest="debug"
    )
    (options, args) = parser.parse_args()

    myfile = args[0]
    if options.debug:
        print("I am totally opening " + myfile)

    wm = pyinotify.WatchManager()

    # watched events on the directory, and parse $path for file_of_interest:
    dirmask = (
        pyinotify.IN_MODIFY
        | pyinotify.IN_DELETE
        | pyinotify.IN_MOVE_SELF
        | pyinotify.IN_CREATE
    )

    dirmask = pyinotify.ALL_EVENTS

    # open file, skip to end..
    # global fh
    # fh = open(myfile, "r")
    # fh.seek(0, 2)

    import subprocess

    import pyinotify

    def onChange(ev):
        # if not ev.dir and ev.name.startswith("gurken"):
        print("%r" % ev)

    wm = pyinotify.WatchManager()
    wm.add_watch("/home/simlu/scm/vault-informer", dirmask, onChange)
    notifier = pyinotify.Notifier(wm)
    notifier.loop()
    sys.exit(0)

    # the event handlers:
    class PTmp(pyinotify.ProcessEvent):
        def process_ALL_EVENTS(self, event):
            print("ALL: %s" % event.maskname)

        def process_IN_MODIFY(self, event):
            print(event.maskname)
            if myfile not in os.path.join(event.path, event.name):
                return
            else:
                print(fh.readline().rstrip())

        def process_IN_MOVE_SELF(self, event):
            print(event.maskname)
            if options.debug:
                print(
                    "The file moved! Continuing to read from that, until a new one is created.."
                )

        def process_IN_CREATE(self, event):
            print(event.maskname)
            if myfile in os.path.join(event.path, event.name):
                # yay, I exist, umm.. again!
                global fh
                fh.close
                fh = open(myfile, "r")
                # catch up, in case lines were written during the time we were re-opening:
                if options.debug:
                    print(
                        "My file was created! I'm now catching up with lines in the newly created file."
                    )
                for line in fh.readlines():
                    print(line.rstrip())
                # then skip to the end, and wait for more IN_MODIFY events
                fh.seek(0, 2)
            return

    notifier = pyinotify.Notifier(wm, PTmp())

    # watch the directory, so we can get IN_CREATE events and re-open the file when logrotate comes along.
    # if you just watch the file, pyinotify errors when it moves, saying "can't track, can't trust it.. watch
    #  the directory".
    index = myfile.rfind("/")
    wm.add_watch(myfile[:index], dirmask)

    while True:
        try:
            notifier.process_events()
            if notifier.check_events():
                notifier.read_events()
        except KeyboardInterrupt:
            break

    # cleanup: stop the inotify, and close the file handle:
    notifier.stop()
    fh.close()

    sys.exit(0)


if __name__ == "__main__":
    main()
