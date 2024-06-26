import os.path

from iced_x86 import *
import re
import subprocess

allowed_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
JUMP_OPERATORS = ['JMP', 'JO', 'JNO', 'JS', 'JNS', 'JE', 'JZ', 'JNE', 'JNZ', 'JB', 'JNAE', 'JC',
                  'JNB', 'JAE', 'JNC','JBE', 'JNA', 'JA', 'JNBE', 'JL', 'JNGE', 'JGE', 'JNL',
                  'JLE', 'JNG', 'JG', 'JNLE', 'JP', 'JPE', 'JNP', 'JPO', 'JCXZ', 'JECXZ']


out_path = "D:\\Projects\\TSRe\\diff\\"
file_name = "Draw_Shape"
assembler_path = "G:\\masm32\\bin\\ml.exe"

asm_file_path = out_path + file_name + ".asm"
object_file_path = out_path + file_name + ".o"

class Instruction:
    def __init__(self, ip: int, opcode: str, operands: list, has_label=False):
        self.ip = ip
        self.opcode = opcode
        self.operands = operands
        self.has_label = has_label

    def __str__(self):
        string = f"\nlabel_{self.ip - function_start:06X}:\n" if self.has_label else ""
        string += f"{self.opcode} {','.join(self.operands)}"
        return string


def hex_0x_to_int(string):
    return int(f"0x{string.replace('h', '')}", 16)


def sanitize_string(string):
    characters = [c if c in allowed_chars else "_" for c in string]
    return "".join(characters)


min_ea = ida_ida.inf_get_min_ea()
max_ea = ida_ida.inf_get_max_ea()


def is_address_in_exe(address):
    return min_ea <= address <= max_ea


address_regex = re.compile("[A-Z0-9]+h(?=[^A-Z0-9]*?)")

function = ida_funcs.get_func(here())
function_start = function.start_ea
function_bytes = ida_bytes.get_bytes(function.start_ea, function.end_ea - function.start_ea)

decoder = Decoder(32, function_bytes, ip=function_start)
formatter = Formatter(FormatterSyntax.MASM)
# formatter.memory_size_options = MemorySizeOptions.ALWAYS

instructions = list()
for instr in decoder:
    disasm = formatter.format(instr)
    start_index = instr.ip - function_start
    bytes_str = function_bytes[start_index:start_index + instr.len].hex().upper()

    parts = disasm.split(" ")
    opcode = parts[0]
    operands = " ".join(parts[1:]).split(",") if len(parts) > 1 else []

    instructions.append(Instruction(instr.ip, opcode, operands))


for instr in instructions:
    if instr.opcode.upper() in JUMP_OPERATORS:
        try:
            jump_address_match = address_regex.search(instr.operands[0])

            if jump_address_match is None:
                continue

            jump_address = jump_address_match.group(0)
            jump_address_int = hex_0x_to_int(jump_address)
            if not is_address_in_exe(jump_address_int):
                continue

            instr.operands[0] = instr.operands[0].replace(jump_address, f"label_{jump_address_int - function_start:06X}")

            for dest_instr in instructions:
                if jump_address_int == dest_instr.ip:
                    dest_instr.has_label = True
                    break

        except:
            print(f"WARNING: Jump address not found. IP: {instr.ip:X}. {str(instr)}")
            continue


calls = list()
for instr in instructions:
    if instr.opcode.upper() == "CALL":
        try:
            call_address_match = address_regex.search(instr.operands[0])

            if call_address_match is None:
                continue

            call_address = call_address_match.group(0)
            call_address_int = hex_0x_to_int(call_address)
            if not is_address_in_exe(call_address_int):
                continue
            func_name = f"func_{call_address_int:X}"
            instr.operands[0] = instr.operands[0].replace(call_address, func_name)

            if func_name not in calls:
                calls.append(func_name)

        except:
            print(f"WARNING: Call address not found. IP: {instr.ip:X}. {str(instr)}")
            continue


global_vars = list()
for instr in instructions:
    if instr.opcode.upper() in JUMP_OPERATORS or instr.opcode.upper() == "CALL":
        continue

    for i in range(len(instr.operands)):
        operand = instr.operands[i]
        address_match = address_regex.search(operand)
        if address_match is None:
            continue

        address_str = address_match.group(0)
        address_int = hex_0x_to_int(address_str)
        if not is_address_in_exe(address_int):
            continue

        global_name = ida_name.get_nice_colored_name(address_int, 3)
        global_name_stripped = sanitize_string(global_name if '+' not in global_name else global_name.split('+')[0])
        if global_name_stripped not in global_vars:
            global_vars.append(global_name_stripped)

        if address_str == operand:
            instr.operands[i] = f"offset {global_name_stripped}"
        else:
            instr.operands[i] = operand.replace(address_str, global_name_stripped)


ASM_HEADER = ".486\n.model flat\n.code _DIFF_SEG\n\n"

append_mode = False
if os.path.isfile(asm_file_path):
    with open(asm_file_path, "r") as f:
        contents = f.read()

    end_index = contents.rfind("END")
    append_mode = end_index != -1 and contents.startswith(ASM_HEADER)

    if append_mode:
        contents = contents[:end_index] + "\n\n"

with open(asm_file_path, "w") as f:
    if append_mode:
        f.write(contents)
    else:
        f.write(".486\n.model flat\n.code _DIFF_SEG\n\n")

    for call in calls:
        f.write(f"externdef {call}:near\n")

    f.write("\n")

    for global_var in global_vars:
        f.write(f"externdef {global_var}:\n")

    f.write("\n")

    f.write(f"func_{function_start:X} PROC\n")

    for instr in instructions:
        f.write(str(instr) + "\n")

    f.write(f"func_{function_start:X} ENDP\n")
    f.write("\nEND\n")

subprocess.call(f"{assembler_path} /c /coff /Fo\"{object_file_path}\" \"{asm_file_path}\"", shell=False)
