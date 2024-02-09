import ida_loader
import ida_kernwin
import idaapi
import idautils
import idc
import os
import tempfile
import subprocess
import time

class MyChooser(idaapi.Choose):
    def __init__(self, title, items):
        idaapi.Choose.__init__(self, title, [["String", 50], ["Length", 10]], width=60, height=20)
        self.items = items
        self.selection = None
    def OnGetSize(self):
        return len(self.items)
    def OnGetLine(self, n):
        return [self.items[n][0], str(self.items[n][1])]
    def OnSelectLine(self, n):
        self.selection = self.items[n]
        print("Selected string: " + self.items[n][0])
        self.Close()

def get_real_address(ea):
    offset = ida_loader.get_fileregion_offset(ea)
    if offset == idaapi.BADADDR:
        raise ValueError(f"No file region corresponds to address {ea:x}")
    return offset

def get_random_temp_filename():
    temp_file = tempfile.NamedTemporaryFile(delete=False)
    file_name = temp_file.name
    temp_file.close()
    return file_name

def get_hex(value):
    if isinstance(value, int):
        return format(value, '02x')
    else:
        # get ascii value of the characters
        return format(ord(value), '02x')
        
        
    
def format_displacement_str(n,target_length=4):
    if n < 0:
        n = n & 0xFFFFFFFF

    n_bytes = n.to_bytes(target_length, 'little')
    hex_str = n_bytes.hex()
    return hex_str

def format_displacement(n,target_length=4):
    if n < 0:
        n = n & 0xFFFFFFFF

    n_bytes = n.to_bytes(target_length, 'little')
    return n_bytes


def build_comparer_assembly(check_last_4_chars=False):
    result = ""
    if check_last_4_chars:
        result += "mov eax, dword [rsi + 12]\n"
    else:
        result += "mov eax, dword [rsi]\n"
    for i in range(len(dlc_list)):
        # get the ascii value of the first 4 characters reversed
        if check_last_4_chars:
            result += f"cmp eax, 0x{get_hex(dlc_list[i][15])}{get_hex(dlc_list[i][14])}{get_hex(dlc_list[i][13])}{get_hex(dlc_list[i][12])}\n"
        else:
            result += f"cmp eax, 0x{get_hex(dlc_list[i][3])}{get_hex(dlc_list[i][2])}{get_hex(dlc_list[i][1])}{get_hex(dlc_list[i][0])}\n"
        result += f"je copy_dlc{i}\n"
    result += "jmp end\n"

    for i in range(len(dlc_list)):
        result += f"copy_dlc{i}:\n"
        result += f"mov eax, 0x002F{get_hex(str(i))}63\n"
        result += f"mov dword [rdx + 8], eax\n"
        # if not last dlc
        if i != len(dlc_list) - 1:
            result += f"jmp copy_common\n"   

    result += "copy_common:\n"
    result += "mov rax, 0x6C642F307070612F\n"
    result += "mov qword [rdx], rax\n"
    result += "xor eax,eax\n"
    result += "mov dword [rdx + 12], eax\n"
    result += "end:\n"
    result += "xor eax, eax\n"
    result += "ret\n"
    return result

def run_command_and_capture_output(command):
    completed_process = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return completed_process.stdout

# test_strings = [["test1 - saakjfbweuoqbxqcNAV",10], ["test2 - saakjfbweuoqbxqcNAV",10], ["test3 - saakjfbweuoqbxqcNAV",10], ["test4 - saakjfbweuoqbxqcNAV",10], ["test5 - saakjfbweuoqbxqcNAV",10], ["test6 - saakjfbweuoqbxqcNAV",10], ["test7 - saakjfbweuoqbxqcNAV",10], ["test8 - saakjfbweuoqbxqcNAV",10], ["test9 - saakjfbweuoqbxqcNAV",10], ["test10 - saakjfbweuoqbxqcNAV",10]]
# chooser = MyChooser("Choose the string to patch",test_strings)
# chooser.Show(True)

# exit()


if not idaapi.auto_is_ok():
    ida_kernwin.warning("Analysis isnt finished, please wait for it to finish before running this script")
    exit()

manually_select_strings = False
button_pressed = idaapi.ask_buttons("Automatic", "Manual", "Cancel", idaapi.ASKBTN_CANCEL, "Do you want to manually or automatically select the strings to use as space for new code?")

if button_pressed == idaapi.ASKBTN_CANCEL:
    print("Exiting")
    exit()
elif button_pressed == idaapi.ASKBTN_NO:
    idaapi.info("Please select the strings that are errors/warnings or otherwise seems safe to overwrite")
    manually_select_strings = True

MAX_SIZE = 1024

dlc_list = ida_kernwin.ask_text(MAX_SIZE, "", "Enter all content ids here (16 char each)")

dlc_list = dlc_list.replace(" ", "")
dlc_list = dlc_list.replace("\n", "")
dlc_list = dlc_list.replace("\r", "")
dlc_list = dlc_list.replace("\t", "")

if len(dlc_list) == 0:
    ida_kernwin.warning("No input")
    exit()

if len(dlc_list) % 16 != 0:
    ida_kernwin.warning("Invalid input length, each content id should be 16 characters long")
    exit()

# split the input into 16 character chunks
dlc_list = [dlc_list[i:i+16] for i in range(0, len(dlc_list), 16)]

if len(dlc_list) > 10:
    ida_kernwin.warning("Too many DLCs, max of 10 is supported")
    exit()

check_last_4_chars = False

# check if any 2 have the same first 4 characters
for i in range(len(dlc_list)):
    for j in range(len(dlc_list)):
        if i == j:
            continue
        if dlc_list[i][0:4] == dlc_list[j][0:4]:
            check_last_4_chars = True
            break

# check if any 2 have the same last 4 characters
if check_last_4_chars:
    for i in range(len(dlc_list)):
        for j in range(len(dlc_list)):
            if i == j:
                continue
            if dlc_list[i][12:16] == dlc_list[j][12:16]:
                ida_kernwin.warning("There are dlcs with the same first 4 and same last 4 characters. this is not supported")
                exit()

mount_handler_asm_raw_text = build_comparer_assembly()

nasm_path = idaapi.ask_file(0, "*.exe", "Choose nasm executable")

if nasm_path is None:
    ida_kernwin.warning("No file selected")
    exit()

mount_handler_asm_file = get_random_temp_filename()
with open(mount_handler_asm_file, "w") as f:
    f.write("BITS 64\n")
    f.write(mount_handler_asm_raw_text)

mount_handler_asm_file_output = get_random_temp_filename()
mount_assemble_result = run_command_and_capture_output(f"{nasm_path} -f bin -o {mount_handler_asm_file_output} {mount_handler_asm_file}")

if mount_assemble_result != "":
    ida_kernwin.warning(mount_assemble_result)
    exit()

with open(mount_handler_asm_file_output, "rb") as f:
    mount_handler_asm_bytes = f.read()

list_handler_asm_len = 53

# get list of strings in the CODE section
all_strings = idautils.Strings()
strings_in_code_segment = [s for s in all_strings if idc.get_segm_name(s.ea) == "CODE"]

if manually_select_strings:
    # filter strings_in_code_segment to strings at least list_handler_asm_len + 2 long
    temp = [s for s in strings_in_code_segment if s.length >= list_handler_asm_len + 2]
    temp.sort(key=lambda s: s.length, reverse=True)
    chooser = MyChooser("Choose the string to patch [1] (list handler)", [(str(s), s.length,s.ea) for s in temp])
    chooser.Show(True)
    list_handler_asm_target_string = next((s for s in strings_in_code_segment if s.ea == chooser.selection[2]), None)
    if list_handler_asm_target_string is None:
        ida_kernwin.warning("No string selected")
        exit()
    
    temp = [s for s in strings_in_code_segment if s.length >= len(mount_handler_asm_bytes) + 2 and s.ea != list_handler_asm_target_string.ea]
    temp.sort(key=lambda s: s.length, reverse=True)
    chooser = MyChooser("Choose the string to patch [2] (mount handler)", [(str(s), s.length,s.ea) for s in temp])
    chooser.Show(True)
    mount_handler_asm_target_string = next((s for s in strings_in_code_segment if s.ea == chooser.selection[2]), None)
    if mount_handler_asm_target_string is None:
        ida_kernwin.warning("No string selected")
        exit()
else:
    # find strings that contain %s %d, these are likely okay to get rid of
    fstrings = [s for s in strings_in_code_segment if "%d" in str(s) or "%s" in str(s)]

    fstrings.sort(key=lambda s: s.length, reverse=True)
    list_handler_asm_target_string = None
    mount_handler_asm_target_string = None
    for i in range(len(fstrings)):
        if list_handler_asm_target_string is None and len(str(fstrings[i])) >= list_handler_asm_len + 2:
            list_handler_asm_target_string = fstrings[i]
        elif len(str(fstrings[i])) >= len(mount_handler_asm_bytes) + 2 and fstrings[i].ea != list_handler_asm_target_string.ea and list_handler_asm_target_string is not None:
            mount_handler_asm_target_string = fstrings[i]
            break

    if list_handler_asm_target_string is None or mount_handler_asm_target_string is None:
        ida_kernwin.warning("Couldn't find the strings needed for the patch. Retry in manual mode")
        exit()

dlc_list_bytes = b""
for dlc in dlc_list:
    # convert dlc to ascii bytes
    dlc_list_bytes += dlc.encode("ascii")
    # append 4 null bytes
    dlc_list_bytes += b"\x00\x00\x00\x00"
    dlc_list_bytes += b"\x04\x00\x00\x00" # status -> 4 = installed | 0 -> no extra data

if manually_select_strings:
    temp = [s for s in all_strings if s.length >= len(dlc_list_bytes) + 2 and s.ea != list_handler_asm_target_string.ea and s.ea != mount_handler_asm_target_string.ea]
    temp.sort(key=lambda s: s.length, reverse=True)
    chooser = MyChooser("Choose the string to patch [3] (dlc list)", [(str(s), s.length,s.ea) for s in temp])
    chooser.Show(True)
    dlc_list_target_string = next((s for s in all_strings if s.ea == chooser.selection[2]), None)
    if dlc_list_target_string is None:
        ida_kernwin.warning("No string selected")
        exit()
else:
    dlc_list_candidates_list = [s for s in all_strings if "%s" in str(s) or "%d" in str(s) or "deprecated" in str(s)]
    dlc_list_candidates_list.sort(key=lambda s: s.length, reverse=True)

    for i in range(len(dlc_list_candidates_list)):
        if dlc_list_candidates_list[i].length >= len(dlc_list_bytes) + 2 and dlc_list_candidates_list[i].ea != list_handler_asm_target_string.ea and dlc_list_candidates_list[i].ea != mount_handler_asm_target_string.ea:
            dlc_list_target_string = dlc_list_candidates_list[i]
            break

    if dlc_list_target_string is None:
        ida_kernwin.warning("Couldn't find the string needed for the patch. Retry in manual mode")
        exit()


# fixed 53 bytes
# rip here is 7 + 9 + list_handler_asm_target_string + 2
rip = 7 + 9 + list_handler_asm_target_string.ea + 2
target = dlc_list_target_string.ea
# why tf do i have to add 6
target += 6
target_offset = target - rip
# list_handler_asm_raw_text = f""" 
#     test rdx, rdx
#     jz handle_null
#     lea rdx, [rip + 0x{hex(target_offset)}]
#     mov rcx, 0x{hex(len(dlc_list) * 24)}
#     shr rcx, 3
# loop:
#         mov rax, qword [rdx]
#         mov qword [rsi], rax
#         add rsi, 8
#         add rdx, 8
#         dec rcx
#         jnz loop
#     jmp end
# handle_null:
#     mov dword [rcx], {len(dlc_list)}
# end:
#     xor eax, eax
#     ret
# """

# preassembled because nasm doesnt support rip relative addressing, this doesnt change much anyways
list_handler_asm_bytes = bytes.fromhex(f"48 85 D2 74 27 48 8D 15 {format_displacement_str(target_offset,4)} 48C7C1 {format_displacement_str(len(dlc_list) * 24,4)} 48C1E903488B024889064883C6084883C20848FFC975EDEB06C701 {format_displacement_str(len(dlc_list),1)} 00000031C0C3")

    
sceAppContentGetAddcontInfoList = idaapi.get_name_ea(idaapi.BADADDR, 'sceAppContentGetAddcontInfoList')

sceAppContentGetAddcontInfoList_patches = []

for xref in idautils.XrefsTo(sceAppContentGetAddcontInfoList, 0):
    if xref.type == idaapi.fl_CF or xref.type == idaapi.fl_CN:
        sceAppContentGetAddcontInfoList_patches.append(xref)


sceAppContentAddcontMount = idaapi.get_name_ea(idaapi.BADADDR, 'sceAppContentAddcontMount')

sceAppContentAddcontMount_patches = []

for xref in idautils.XrefsTo(sceAppContentAddcontMount, 0):
    if xref.type == idaapi.fl_CF or xref.type == idaapi.fl_CN:
        sceAppContentAddcontMount_patches.append(xref)

sceAppContentAddcontUnmount = idaapi.get_name_ea(idaapi.BADADDR, 'sceAppContentAddcontUnmount')

sceAppContentAddcontUnmount_patches = []

for xref in idautils.XrefsTo(sceAppContentAddcontUnmount, 0):
    if xref.type == idaapi.fl_CF or xref.type == idaapi.fl_CN:
        sceAppContentAddcontUnmount_patches.append(xref)


output_file = idaapi.ask_file(1, "eboot_patched.elf", "Save patched eboot (*.txt)")

if output_file is None:
    ida_kernwin.warning("No file selected")
    exit()

input_file = idaapi.get_input_file_path()
# output_file = input_file + ".new"
with open(input_file, "rb") as f:
    with open(output_file, "wb") as g:
        g.write(f.read())

with open(output_file, "r+b") as f:
    f.seek(get_real_address(list_handler_asm_target_string.ea) + 1)
    f.write(b"\x00")
    f.write(list_handler_asm_bytes)

    f.seek(get_real_address(mount_handler_asm_target_string.ea) + 1)
    f.write(b"\x00")
    f.write(mount_handler_asm_bytes)

    f.seek(get_real_address(dlc_list_target_string.ea) + 1)
    f.write(b"\x00")
    f.write(dlc_list_bytes)

    for patch in sceAppContentGetAddcontInfoList_patches:
        f.seek(get_real_address(patch.frm) + 1)
        print(f"patching sceAppContentGetAddcontInfoList {get_real_address(patch.frm) + 1}")
        # if you see this and know where i fucked up the math that i need to subtract 10 please let me know
        f.write(format_displacement(list_handler_asm_target_string.ea + 2 - patch.frm + 5 - 10, 4))

    for patch in sceAppContentAddcontMount_patches:
        f.seek(get_real_address(patch.frm) + 1)
        print(f"patching sceAppContentAddcontMount {get_real_address(patch.frm) + 1}")
        f.write(format_displacement(mount_handler_asm_target_string.ea + 2 - patch.frm + 5 -10,4))

    for patch in sceAppContentAddcontUnmount_patches:
        f.seek(get_real_address(patch.frm))
        print(f"patching sceAppContentAddcontUnmount {get_real_address(patch.frm) + 1}")
        f.write(b'\xb8\x00\x00\x00\x00')

ida_kernwin.info("Patching complete")