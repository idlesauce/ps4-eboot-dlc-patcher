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


def get_mount_handler_asm_bytes():
    # copy in /app0/ then copy in the content id (from rsi), then copy in / and null terminate
    # mov dword ptr [rdx], 0x7070612F
    # mov word ptr [rdx+4], 0x2F30
    # mov rax, qword ptr [rsi]
    # mov qword ptr [rdx+6], rax
    # mov rax, qword ptr [rsi+8] 
    # mov qword ptr [rdx+14], rax
    # mov word ptr [rdx+22], 0x002F
    # xor eax, eax
    # ret
    return bytes(b'\xC7\x02\x2F\x61\x70\x70\x66\xC7\x42\x04\x30\x2F\x48\x8B\x06\x48\x89\x42\x06\x48\x8B\x46\x08\x48\x89\x42\x0E\x66\xC7\x42\x16\x2F\x00\x31\xC0\xC3')

# if not idaapi.auto_is_ok():
#     ida_kernwin.warning("Analysis isnt finished, please wait for it to finish before running this script")
#     exit()

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

mount_handler_asm_bytes = get_mount_handler_asm_bytes()
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

list_handler_asm_bytes = bytes.fromhex(f"48 85 D2 74 27 48 8D 15 {format_displacement_str(target_offset,4)} 48C7C1 {format_displacement_str(len(dlc_list) * 24,4)} 48C1E903488B024889064883C6084883C20848FFC975EDEB06C701 {format_displacement_str(len(dlc_list),1)} 00000031C0C3")

sceAppContentGetAddcontInfoList = idaapi.get_name_ea(idaapi.BADADDR, 'sceAppContentGetAddcontInfoList')

sceAppContentGetAddcontInfoList_patches = []

for xref in idautils.XrefsTo(sceAppContentGetAddcontInfoList, 0):
    if xref.type == idaapi.fl_CF or xref.type == idaapi.fl_CN:
        sceAppContentGetAddcontInfoList_patches.append(xref)

if len(sceAppContentGetAddcontInfoList_patches) == 0:
    ida_kernwin.warning("No references to sceAppContentGetAddcontInfoList found, this likely means something went wrong in the decompilation step, exiting...")
    exit()

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
        f.seek(get_real_address(patch.frm))
        f.write(b'\xE8')
        print(f"patching sceAppContentGetAddcontInfoList ida: {get_hex(patch.frm)} | real: {get_hex(get_real_address(patch.frm))}")
        # if you see this and know where i fucked up the math that i need to subtract 10 please let me know
        f.write(format_displacement(list_handler_asm_target_string.ea + 2 - patch.frm + 5 - 10, 4))

    for patch in sceAppContentAddcontMount_patches:
        f.seek(get_real_address(patch.frm))
        f.write(b'\xE8')
        print(f"patching sceAppContentAddcontMount  ida: {get_hex(patch.frm)} | real: {get_hex(get_real_address(patch.frm))}")
        f.write(format_displacement(mount_handler_asm_target_string.ea + 2 - patch.frm + 5 -10,4))

    for patch in sceAppContentAddcontUnmount_patches:
        f.seek(get_real_address(patch.frm))
        print(f"patching sceAppContentAddcontUnmount ida: {get_hex(patch.frm)} | real: {get_hex(get_real_address(patch.frm))}")
        f.write(b'\xb8\x00\x00\x00\x00')

ida_kernwin.info("Patching complete")