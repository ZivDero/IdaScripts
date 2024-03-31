from iced_x86 import *
import re
import subprocess

allowed_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
JUMP_OPERATORS = ['JMP', 'JO', 'JNO', 'JS', 'JNS', 'JE', 'JZ', 'JNE', 'JNZ', 'JB', 'JNAE', 'JC',
                  'JNB', 'JAE', 'JNC','JBE', 'JNA', 'JA', 'JNBE', 'JL', 'JNGE', 'JGE', 'JNL',
                  'JLE', 'JNG', 'JG', 'JNLE', 'JP', 'JPE', 'JNP', 'JPO', 'JCXZ', 'JECXZ']


out_path = "D:\\Projects\\TSRe\\diff\\"
file_name = "Draw_Shape"
assembler_path = "D:\\Projects\\JWasm211bw\\JWASM.EXE"

asm_file_path = out_path + file_name + ".asm"
object_file_path = out_path + file_name + ".o"

class Instruction:
    def __init__(self, ip: str, disasm: str, has_label=False):
        self.ip = ip
        self.disasm = disasm
        self.has_label = has_label

    def __str__(self):
        string = ""
        if self.has_label:
            string += f"\nlabel_{self.ip:X}:\n"
        string += self.disasm
        return string


def hex_to_int(string):
    return int(f"0x{string.replace('h', '')}", 16)


def sanitize_string(string):
    characters = [c if c in allowed_chars else "_" for c in string]
    new_string = ""
    for character in characters:
        new_string += character
    return new_string


function = ida_funcs.get_func(here())
function_start = function.start_ea
function_bytes = ida_bytes.get_bytes(function.start_ea, function.end_ea - function.start_ea)

decoder = Decoder(32, function_bytes, ip=function_start)
formatter = Formatter(FormatterSyntax.MASM)

instructions = list()

address_regex = re.compile("[a-zA-Z0-9]+h$")
address_regex_soft = re.compile("[a-zA-Z0-9]+h(?=[^a-zA-Z0-9]*?)")

for instr in decoder:
    disasm = formatter.format(instr)
    start_index = instr.ip - function_start
    bytes_str = function_bytes[start_index:start_index + instr.len].hex().upper()
    instructions.append(Instruction(instr.ip, disasm))


for instr in instructions:
    name, *operands = re.split("[ ,]", instr.disasm)
    if name.upper() in JUMP_OPERATORS:
        address, *_ = [*filter(address_regex.match, operands), None]
        address_int = hex_to_int(address)
        instr.disasm = instr.disasm.replace(address, f"label_{address_int:X}")

        for instr2 in instructions:
            if address_int == instr2.ip:
                instr2.has_label = True
                break
        else:
            print(f"WARNING: JUMP ADDRESS NOT FOUND {address}")
            exit()

calls = list()
for instr in instructions:
    name, *operands = re.split("[ ,]", instr.disasm)
    if name.upper() == "CALL":
        address, *_ = [*filter(address_regex.match, operands), None]
        if address is not None:
            instr.disasm = instr.disasm.replace(address, f"func_{hex_to_int(address):X}")
            calls.append(f"func_{hex_to_int(address):X}")

globals = list()
for instr in instructions:
    parts = instr.disasm.split(" ")
    name = parts[0]
    operands = " ".join(parts[1:]).split(",") if len(parts) > 1 else []

    if name.upper() in JUMP_OPERATORS or name.upper() == "CALL":
        continue

    raw_addresses = list(set([match.group(0) for match in map(address_regex_soft.search, operands) if match is not None]))
    address_numbers = list((map(hex_to_int, raw_addresses)))
    address_names = dict()

    new_operands = list()
    for address, string in zip(address_numbers, raw_addresses):
        if address < 0x401000:
            continue
        global_name = ida_name.get_nice_colored_name(address, 3)
        global_name_stripped = sanitize_string(global_name if '+' not in global_name else global_name.split('+')[0])
        if global_name_stripped not in globals:
            globals.append(global_name_stripped)

        address_names[string] = global_name_stripped

    for operand in operands:
        for op_name, new_name in address_names.items():
            if op_name in operand:
                if len(op_name) == len(operand):
                    new_operands.append(f"offset {new_name}")
                else:
                    new_operands.append(operand.replace(op_name, new_name))
                break
        else:
            new_operands.append(operand)

    new_disasm = name + " " + ",".join(new_operands)
    instr.disasm = new_disasm

with open(asm_file_path, "w") as f:
    f.write(".486\n.model flat\n.code _DIFF_SEG\n\n")

    for call in calls:
        f.write(f"externdef {call}:near\n")

    f.write("\n")

    for global_ in globals:
        f.write(f"externdef {global_}:dword\n")

    f.write("\n")

    for instr in instructions:
        f.write(str(instr) + "\n")

    f.write("\nEND\n")

subprocess.Popen([assembler_path, f" \"asm_file_path\" /coff -Fo \"{object_file_path}\""])
