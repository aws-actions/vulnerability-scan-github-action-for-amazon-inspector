import os


def invoke_command(bin, args) -> int:
    # concatenate binary and arguments
    cmd = f"{bin} {' '.join(args)}"

    # we use os.system for real time console output
    # on the GitHub Actions terminal
    return os.system(cmd)
