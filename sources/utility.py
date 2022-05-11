import argparse
import os
import sys

def str2bool(v):
    if isinstance(v, bool):
       return v
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')

def print_verbose(text, verbose):
    if verbose:
        print(text)

def print_warn(text):
    sys.stderr.write("WARNING: " +text + "\n")

def print_err(text):
    sys.stderr.write("ERROR: " +text + "\n")

def print_dbg(text):
    sys.stderr.write("DEBUG: " + text + "\n")

def print_buf(str_graph, buf, text):
    if buf is not None:
        buf.append(text)
    str_graph.write(text + "\n")

def createFolder(filename):
    isExist = os.path.exists(filename)
    if not isExist:
        os.makedirs(filename)