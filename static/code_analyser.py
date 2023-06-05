"""
Contains the CodeAnalyser class.

Disassembles and analyses the code to detect syscalls.
"""

import sys

import lief
from capstone import *
from capstone.x86_const import (X86_INS_INVALID, X86_INS_DATA16,
                                X86_GRP_BRANCH_RELATIVE)

import utils
import library_analyser
from custom_exception import StaticAnalyserException
from elf_analyser import is_valid_binary, TEXT_SECTION

class CodeAnalyser:
    """CodeAnalyser(path, max_backtrack_insns) -> CodeAnalyser

    Class use to store information about and analyse the binary code to detect
    syscalls.

    This class directly analyse what is inside the `.text` sectin of the ELF
    executable but it also uses `LibraryAnalyser` to (indirectly) analyse
    syscalls used by shared library calls.

    Public Methods
    --------------
    get_used_syscalls_text_section(syscalls_set, inv_syscalls_map)
        Updates the syscall set passed as argument after analysing the `.text`
        of the binary.
    analyse_code(self, insns, syscalls_set, inv_syscalls_map[, funs_called])
        Updates the syscall set passed as argument after analysing the given
        instructions.
    get_text_section(self) -> lief.ELF.Section
        Returns the .text section (as given by the lief library)
    """

    # Used to detect the syscall identifier.
    # The "high byte" (for example 'ah') is not considered. It could be,
    # to be exhaustive, but it would be unlikely to store the syscall id using
    # this identifier (and the code should be modified).
    __registers = {'eax':  {'rax','eax','ax','al'},
                 'ebx':  {'rbx','ebx','bx','bl'},
                 'ecx':  {'rcx','ecx','cx','cl'},
                 'edx':  {'rdx','edx','dx','dl'},
                 'esi':  {'rsi','esi','si','sil'},
                 'edi':  {'rdi','edi','di','dil'},
                 'ebp':  {'rbp','ebp','bp','bpl'},
                 'esp':  {'rsp','esp','sp','spl'},
                 'r8d':  {'r8','r8d','r8w','r8b'},
                 'r9d':  {'r9','r9d','r9w','r9b'},
                 'r10d': {'r10','r10d','r10w','r10b'},
                 'r11d': {'r11','r11d','r11w','r11b'},
                 'r12d': {'r12','r12d','r12w','r12b'},
                 'r13d': {'r13','r13d','r13w','r13b'},
                 'r14d': {'r14','r14d','r14w','r14b'},
                 'r15d': {'r15','r15d','r15w','r15b'}}

    def __init__(self, path, max_backtrack_insns=None):
        self.__path = path
        self.__binary = lief.parse(path)
        self.__has_dyn_libraries = bool(self.__binary.libraries)
        self.__max_backtrack_insns = (max_backtrack_insns
                                      if max_backtrack_insns is not None
                                      else 20)

        if not is_valid_binary(self.__binary):
            raise StaticAnalyserException("The given binary is not a CLASS64 "
                                          "ELF file.")
        try:
            self.__lib_analyser = library_analyser.LibraryAnalyser(
                    self.__binary, self.__max_backtrack_insns)
        except StaticAnalyserException as e:
            sys.stderr.write(f"[ERROR] library analyser of {self.__path} "
                             f"couldn't be created: {e}\n")
            self.__has_dyn_libraries = False

        # only used if `binary` is a library
        self.__address_to_fun_map = None

        self.__md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.__md.detail = True
        # This may lead to errors. So a warning is throwed if indeed data is
        # found.
        self.__md.skipdata = utils.skip_data

    def get_used_syscalls_text_section(self, syscalls_set, inv_syscalls_map):
        """Entry point of the Code Analyser. Updates the syscall set
        passed as argument after analysing the `.text` of the binary.

        Parameters
        ----------
        syscalls_set : set of str
            set of syscalls used by the program analysed
        inv_syscalls_map : dict(int -> str)
            the syscall map defined in syscalls.py but with keys and values
            swapped
        """

        # TODO: adapt the code around the fact that md.disasm may not return the
        # entirety of the requested instructions. (or find a parameter in Cs
        # that enables continuing the analysis in case of error)
        text_section = self.get_text_section()

        self.analyse_code(self.__md.disasm(bytearray(text_section.content),
                                   text_section.virtual_address),
                         syscalls_set, inv_syscalls_map)

    def analyse_code(self, insns, syscalls_set, inv_syscalls_map,
                     funs_called=None):
        """Main function of the Code Analyser. Updates the syscall set and the
        list of functions called after analysing the given instructions.

        Parameters
        ----------
        insns : class generator of capstone
            list of instructions to analyse
        syscalls_set : set of str
            set of syscalls used by the program analysed
        inv_syscalls_map : dict(int -> str)
            the syscall map defined in syscalls.py but with keys and values
            swapped
        funs_called : None or list of LibFunction, optional
            if a list is given, the functions called by the given instructions
            will be added in this list
        """

        if funs_called is not None:
            detect_functions = True
        else:
            detect_functions = False

        list_inst = []
        for i, ins in enumerate(insns):
            b = ins.bytes
            list_inst.append(ins)

            if ins.id in (X86_INS_DATA16, X86_INS_INVALID):
                sys.stderr.write(f"[WARNING] data instruction found in "
                                 f"{self.__path} at address {ins.address}\n")
                continue

            if self.__is_syscall_instruction(ins):
                self.__wrapper_backtrack_syscalls(i, list_inst, syscalls_set,
                                                inv_syscalls_map)
            elif ins.group(CS_GRP_JUMP) or ins.group(CS_GRP_CALL):
                if (self.__has_dyn_libraries
                    and self.__lib_analyser.is_lib_call(ins.op_str)):
                    called_function = self.__lib_analyser.get_function_called(
                                                                    ins.op_str)
                    if detect_functions:
                        for f in called_function:
                            if f not in funs_called:
                                funs_called.append(f)
                    self.__lib_analyser.get_used_syscalls(syscalls_set,
                                                          called_function)
                elif detect_functions and ins.group(CS_GRP_CALL):
                    f = self.__get_function_called(ins.op_str)
                    if f and f not in funs_called:
                        funs_called.append(f)
            # TODO: verify also with REX prefixes
            elif (b[0] == 0xe8 or b[0] == 0xff or b[0] == 0x9a
                  or ins.mnemonic == "syscall"):
                utils.print_debug("a function call or syscall was not "
                                  "detected:")
                utils.print_debug(f"0x{ins.address:x}: {ins.mnemonic} "
                                  f"{ins.op_str}")

    def get_text_section(self):
        """Returns the .text section (as given by the lief library)

        Returns
        -------
        text_section : lief ELF section
            the text section as given by lief

        Raises
        ------
        StaticAnalyserException
            If the .text section is not found.
        """
        text_section = self.__binary.get_section(TEXT_SECTION)
        if text_section is None:
            raise StaticAnalyserException(".text section is not found.")
        return text_section

    def __backtrack_syscalls(self, index, list_ins):
        focus_reg = 'eax'

        last_ins_index = max(0, index-1-self.__max_backtrack_insns)
        for i in range(index-1, last_ins_index, -1):
            if list_ins[i].id in (X86_INS_DATA16, X86_INS_INVALID):
                continue

            utils.log(f"-> {hex(list_ins[i].address)}:{list_ins[i].mnemonic}"
                      f" {list_ins[i].op_str}", "backtrack.log", indent=1)

            op_strings = list_ins[i].op_str.split(",")

            regs_write = list_ins[i].regs_access()[1]
            for r in regs_write:
                if self.__md.reg_name(r) not in self.__registers[focus_reg]:
                    continue
                if len(op_strings) != 2:
                    utils.log("[Operation not supported]",
                              "backtrack.log", indent=2)
                    return -1

                op_strings[1] = op_strings[1].strip()

                if utils.is_hex(op_strings[1]):
                    return int(op_strings[1], 16)
                if op_strings[1].isdigit():
                    return int(op_strings[1])
                if self.__is_reg(op_strings[1]):
                    focus_reg = self.__get_reg_key(op_strings[1])
                    utils.log(f"[Shifting focus to {focus_reg}]",
                              "backtrack.log", indent=2)
                else:
                    # TODO au moins qque instructions les plus utilisées
                    utils.log("[Operation not supported]",
                              "backtrack.log", indent=2)
                    return -1

        return -1

    def __wrapper_backtrack_syscalls(self, i, list_inst, syscalls_set,
                                     inv_syscalls_map):
        utils.print_debug("syscall detected at instruction: "
                          + str(list_inst[-1]))
        nb_syscall = self.__backtrack_syscalls(i, list_inst)
        if nb_syscall != -1 and nb_syscall < len(inv_syscalls_map):
            name = inv_syscalls_map[nb_syscall]
            utils.print_verbose(f"Syscall found: {name}: {nb_syscall}")
            utils.log(f"Found: {name}: {nb_syscall}\n", "backtrack.log")
            syscalls_set.add(name)
        else:
            utils.log(f"Ignore {nb_syscall}\n", "backtrack.log")
            utils.print_verbose(f"Syscall instruction found but ignored: "
                                f"{nb_syscall}")

    def __is_syscall_instruction(self, ins):
        b = ins.bytes
        if b[0] == 0x0f and b[1] == 0x05:
            # Direct syscall SYSCALL
            utils.log(f"DIRECT SYSCALL (x86_64): {hex(ins.address)} "
                      f"{ins.mnemonic} {ins.op_str}", "backtrack.log")
            return True
        if b[0] == 0x0f and b[1] == 0x34:
            # Direct syscall SYSENTER
            utils.log(f"SYSENTER: {hex(ins.address)} {ins.mnemonic} "
                      f"{ins.op_str}", "backtrack.log")
            return True
        if b[0] == 0xcd and b[1] == 0x80:
            # Direct syscall int 0x80
            utils.log(f"DIRECT SYSCALL (x86): {hex(ins.address)} "
                      f"{ins.mnemonic} {ins.op_str}", "backtrack.log")
            return True
        return False

    def __get_function_called(self, operand):
        """Returns the function that would be called by jumping to the address
        given.

        Parameters
        ----------
        operand : str
            operand (address) of the call in hexadecimal

        Returns
        -------
        called_function : LibFunction
            function that would be called
        """

        if utils.is_hex(operand):
            operand = int(operand, 16)

            if self.__address_to_fun_map is None:
                self.__address_to_fun_map = {}
                for item in self.__binary.functions:
                    self.__address_to_fun_map[item.address] = (
                            library_analyser.LibFunction(
                                name=item.name,
                                library_path=self.__path,
                                boundaries=[item.address,
                                            item.address + item.size]
                                )
                            )

            if operand not in self.__address_to_fun_map:
                utils.print_verbose("[WARNING] A function was called but "
                                    "couln't be found. This is probably due "
                                    "to an indirect address call.")
                return None

            return self.__address_to_fun_map[operand]
        else:
            # TODO
            return None

    def __is_reg(self, string):
        """Returns true if the given string is the name of a (x86_64 general
        purpose) register identifier.

        Parameters
        ----------
        string : str
            the string that may contain a register identifier

        Returns
        -------
        is_reg : bool
            True if the string is a register identifier
        """

        for reg_ids in self.__registers.values():
            if string in reg_ids:
                return True

        return False

    def __get_reg_key(self, reg_id):
        """Given a register identifier, returns the key to have access to this
        register in the `__registers` variable.

        Parameters
        ----------
        reg_id : str
            the string contains a register identifier

        Raises
        ------
        StaticAnalyserException
            If the given reg_id is not a register id

        Returns
        -------
        reg_key : str
            the key for this register
        """

        for reg_key, reg_ids in self.__registers.items():
            if reg_id in reg_ids:
                return reg_key

        raise StaticAnalyserException(f"{reg_id}, the given reg_id does not "
                                      f"correspond to a register id.")
