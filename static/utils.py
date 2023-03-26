import globals

DEBUG = True

def print_verbose(msg, indent=0):
    if globals.verbose:
        print(indent * "\t" + msg)

def is_hex(s):
    if not s or len(s) < 3:
        return False

    return s[:2] == "0x" and all(c.isdigit() or c.lower() in ('a', 'b', 'c', 'd', 'e', 'f') for c in s[2:])

def str2bool(v):
    if isinstance(v, bool):
       return v
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')

def print_debug(s):
    if DEBUG:
        print("[DEBUG] " + s)
