"""
Main file of the program.

Parses the input, calls the elf and code analyser and prints the results.
"""

# TODO: check if all these imports are needed
import os
import re
import csv
import lief
import sys
import json
import argparse

import globals

from utils import *
from syscalls import *
from code_analyser import CodeAnalyser
from elf_analyser import get_syscalls_from_symbols
from custom_exception import StaticAnalyserException


CSV = "data.csv"


def main():
    globals.initialize() 

    parser = argparse.ArgumentParser()
    parser.add_argument('--app','-a', help='Path to application',required=True, default=globals.app)
    parser.add_argument('--verbose', '-v', type=str2bool, nargs='?', const=True, help='Verbose mode', default=True)
    parser.add_argument('--display', '-d', type=str2bool, nargs='?', const=True, help='Display syscalls', default=True)
    parser.add_argument('--csv', '-c', type=str2bool, nargs='?', const=True, help='Output csv', default=True)
    args = parser.parse_args()

    globals.verbose = args.verbose
    globals.app = args.app
    binary = lief.parse(globals.app)

    print_verbose("Analysing the ELF file. This may take some times...")

    try:
        syscalls_set = set()
        get_syscalls_from_symbols(binary, syscalls_set)

        # TODO: use entry point instead of start of text section? (not needed?)
        # entry_addr = binary.entrypoint

        code_analyser = CodeAnalyser(binary)

        inv_syscalls_map = get_inverse_syscalls_map()
        code_analyser.get_used_syscalls(syscalls_set, inv_syscalls_map)
    except StaticAnalyserException as e:
        sys.stderr.write(f"[ERROR] {e}\n")
        sys.exit(1)


    if args.display:
        for k,v in syscalls_map.items():
            if k in syscalls_set:
                print_verbose("{} : {}".format(k,v))

    print_verbose("Total number of syscalls: " + str(len(syscalls_set)))

    if args.csv:
        print("# syscall, used")
        for k,v in syscalls_map.items():
            value = "N"
            if k in syscalls_set:
                value = "Y"
            print("{},{}".format(v,value))

if __name__== "__main__":
    main()  
