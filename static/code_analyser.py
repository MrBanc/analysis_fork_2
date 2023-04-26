
import utils
from library_analyser import LibraryAnalyser, FunLibInfo
from custom_exception import StaticAnalyserException
from elf_analyser import is_valid_binary, TEXT_SECTION

class CodeAnalyser:
    """
    Class use to store information about and analyse the binary code.

    This class directly analyse what is inside the `.text` sectin of the ELF
    executable but it also uses `LibraryAnalyser` to (indirectly) analyse
    syscalls used by shared library calls.
    """

    def __init__(self, binary):
        if not is_valid_binary(binary):
            raise StaticAnalyserException("The given binary is not a CLASS64 "
                                          "ELF file.")
        self.__binary = binary

        try:
            self.__lib_analyser = LibraryAnalyser(binary)
        except StaticAnalyserException as e:
            raise e

        # only used if `binary` is a library used by the main analyzed binary.
        self.__address_to_fun_map = None

    def get_used_syscalls_text_section(self, syscalls_set, inv_syscalls_map):
        """Entry point of the Code Analyser. Updates the syscall set
        passed as argument after analysing the .text of the binary.

        Parameters
        ----------
        syscalls_set : set of str
            set of syscalls used by the program analyzed
        inv_syscalls_map : dict(int -> str)
            the syscall map defined in syscalls.py but with keys and values
            swapped
        """

        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True

        # TODO: adapt the code around the fact that md.disasm may not return the
        # entirety of the requested instructions. (or find a parameter in Cs
        # that enables continuing the analysis in case of error)
        text_section = self.get_text_section()

        self.disassemble(md.disasm(bytearray(text_section.content),
                                   text_section.virtual_address),
                         syscalls_set, inv_syscalls_map)

    def disassemble(self, insns, syscalls_set, inv_syscalls_map, funs_called=None):
        """Main function of the Code Analyser. Updates the syscall set and the
        list of functions called after analysing the given instructions.

        Parameters
        ----------
        insns : class generator of capstone
            list of instructions to analyse
        syscalls_set : set of str
            set of syscalls used by the program analyzed
        inv_syscalls_map : dict(int -> str)
            the syscall map defined in syscalls.py but with keys and values
            swapped
        funs_called : None or list of FunLibInfo optional
            if a list is given, the functions called by the given instructions
            will be added in this list
        """

        funs_called_set = None
        if funs_called:
            funs_called_set = set(funs_called)

        list_inst = []
        for i, ins in enumerate(insns):
            b = ins.bytes
            list_inst.append(ins)

            if self.__is_syscall_instruction(ins):
                self.__wrapper_backtrack_syscalls(i, list_inst, syscalls_set,
                                                inv_syscalls_map)
            # TODO: be sure to detect all lib calls. This may not be enough. Do some research
            elif self.__is_jmp(ins.mnemonic) or ins.mnemonic == "call":
                if self.__lib_analyser.is_lib_call(ins.op_str):
                    called_function = self.__lib_analyser.get_function_called(
                                                                    ins.op_str)
                    if funs_called_set:
                        funs_called_set.update(called_function)
                    self.__lib_analyser.get_used_syscalls(syscalls_set,
                                                          called_function)
                elif funs_called_set and ins.mnemonic == "call":
                    # TODO: should not be the name of the function but the FunLibInfo
                    f_name = self.__get_function_called(ins.op_str)
                    if f_name:
                        funs_called_set.add(f_name)
            # TODO: verify also with REX prefixes
            elif (b[0] == 0xe8 or b[0] == 0xff or b[0] == 0x9a or ins.mnemonic == "syscall"):
                pass
                utils.print_debug("a function call or syscall was not "
                                  "detected:")
                utils.print_debug(f"0x{ins.address:x}: {ins.mnemonic} "
                                  f"{ins.op_str}")

    def get_text_section(self):
        """Returns the .text section (as given by the lief library)

        Raises
        ------
        StaticAnalyserException
            If the .text section is not found.
        """
        text_section = self.__binary.get_section(TEXT_SECTION)
        if text_section is None:
            raise StaticAnalyserException(".text section is not found.")
        return text_section

    def __backtrack_syscalls(self, index, ins):
        for i in range(index-1, 0, -1):
            b = ins[i].bytes
            utils.print_verbose(f"-> 0x{hex(ins[i].address)}:{ins[i].mnemonic}"
                                f" {ins[i].op_str}", indent=1)
            # MOV in EAX
            if b[0] == 0xb8:
                return int(b[1])

            # Another syscall is called, break
            if b[0] == 0xcd and b[1] == 0x80:
                break
        return -1

    def __wrapper_backtrack_syscalls(self, i, list_inst, syscalls_set, inv_syscalls_map):
        utils.print_debug("syscall detected at instruction: "
                          + str(list_inst[-1]))
        nb_syscall = self.__backtrack_syscalls(i, list_inst)
        if nb_syscall != -1 and nb_syscall < len(inv_syscalls_map):
            name = inv_syscalls_map[nb_syscall]
            utils.print_verbose(f"Found: {name}: {nb_syscall}\n")
            syscalls_set.add(name)
        else:
            utils.print_verbose(f"Ignore {nb_syscall}")

    def __is_syscall_instruction(self, ins):
        b = ins.bytes
        if b[0] == 0x0f and b[1] == 0x05:
            # Direct syscall SYSCALL
            utils.print_verbose(f"DIRECT SYSCALL (x86_64): "
                                f"0x{hex(ins.address)} {ins.mnemonic} "
                                f"{ins.op_str}")
            return True
        if b[0] == 0x0f and b[1] == 0x34:
            # Direct syscall SYSENTER
            utils.print_verbose(f"SYSENTER: 0x{hex(ins.address)} "
                                f"{ins.mnemonic} {ins.op_str}")
            return True
        if b[0] == 0xcd and b[1] == 0x80:
            # Direct syscall int 0x80
            utils.print_verbose(f"DIRECT SYSCALL (x86): "
                                f"0x{hex(ins.address)} {ins.mnemonic} "
                                f"{ins.op_str}")
            return True
        return False

    def __is_jmp(self, mnemonic):
        # TODO: add other types of jump (see
        # /home/ben/Documents/TFE/docs/intel-asd-manual-vol-1-2abcd-3abcd.pdf)
        return mnemonic == "jmp"

    def __get_function_called(self, operand):
        """Returns the function that would be called by jumping to the address
        given.

        Parameters
        ----------
        operand : str
            operand (address) of the call in hexadecimal

        Returns
        -------
        called_function : FunLibInfo
            function that would be called
        """

        operand = int(operand, 16)

        if self.__address_to_fun_map is None:
            self.__address_to_fun_map = {}
            for item in self.__binary.functions:
                self.__address_to_fun_map[item.address] = FunLibInfo(
                        name=item.name, lib_path) # a continuer

        if operand not in self.__address_to_fun_map:
            utils.print_verbose("[ERROR] A function was called but couln't be "
                                "found. This is probably due to an indirect "
                                "address call.")
            return None

        return self.__address_to_fun_map[operand]
