#!/usr/bin/env python3

import sys

from entrypoint import cli
from entrypoint import log_conf
from entrypoint import orchestrator


def main():
    # initialize the CLI arguments
    args = cli.init(sys.argv[1:])

    # initialize logger
    if args.verbose:
        log_conf.init(enable_verbose=True)
    else:
        log_conf.init(enable_verbose=False)

    # entrypoint to business logic
    ret = orchestrator.execute(args)
    sys.exit(ret)


if __name__ == '__main__':
    main()
