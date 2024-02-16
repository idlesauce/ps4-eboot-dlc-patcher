import ida_loader
import ida_kernwin
import idaapi
import idautils
import idc
import os
import tempfile
import subprocess
import time

class DlcContentIDInputForm(idaapi.Form):
    def __init__(self,extraDataText, noExtraDataText):
        idaapi.Form.__init__(self, r"""STARTITEM NULL
BUTTON YES* OK
BUTTON CANCEL Cancel
Enter content ids (16 char each)
<##DLCs with extra data:{txtLeft}><##DLCs without extra data:{txtRight}>
""", {
        'txtLeft': idaapi.Form.MultiLineTextControl(text=extraDataText, width=40, swidth=40),
        'txtRight': idaapi.Form.MultiLineTextControl(text=noExtraDataText, width=40, swidth=40),
    })

    def show_and_wait(self):
        self.Compile()
        self.Execute()


class StringChooser(idaapi.Choose):
    def __init__(self, title, items):
        idaapi.Choose.__init__(self, title, [["String", 50], [
                               "Length", 10]], width=60, height=20)
        self.items = items
        self.selection = items[self.deflt]

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return [self.items[n][0], str(self.items[n][1])]

    def OnSelectLine(self, n):
        self.selection = self.items[n]
        print("Selected string: " + self.items[n][0])
        self.Close()

    def OnSelectionChange(self, n):
        self.selection = self.items[n]


def get_real_address(ea):
    offset = ida_loader.get_fileregion_offset(ea)
    if offset == idaapi.BADADDR:
        raise Exception(f"No file region corresponds to address {ea:x}")
    return offset


def get_hex(value):
    if isinstance(value, int):
        return format(value, '02x')
    else:
        # get ascii value of the characters
        return format(ord(value), '02x')


def format_displacement_str(n, target_length=4):
    if n < 0:
        n = n & 0xFFFFFFFF

    n_bytes = n.to_bytes(target_length, 'little')
    hex_str = n_bytes.hex()
    return hex_str


def format_displacement(n, target_length=4):
    if n < 0:
        n = n & 0xFFFFFFFF

    n_bytes = n.to_bytes(target_length, 'little')
    return n_bytes


def find_start_index_of_4_differing_chars(list):
    for i in range(16 - 3):
        all_differ = True
        for j in range(len(list)):
            for k in range(len(list)):
                if j == k:
                    continue
                if list[j][i:i+4] == list[k][i:i+4]:
                    all_differ = False
                    break
            if not all_differ:
                break
        if all_differ:
            return i
    return -1


def get_mount_handler_asm_len(dlc_list):
    return len(get_mount_handler_asm_bytes(dlc_list, 0, 0))

# this is a mess but i wanted to do it without needing an assembler
def get_mount_handler_asm_bytes(dlc_list, rip, address_containing_dlc_list):
    dlc_list_cmp_index = find_start_index_of_4_differing_chars([s for s, _ in dlc_list])
    if dlc_list_cmp_index == -1:
        print("Couldn't find 4 consecutive differing characters")
        return get_fallback_mount_handler_asm_bytes(rip, address_containing_dlc_list, len(dlc_list))

    result = b""
    if dlc_list_cmp_index == 0:
        # mov eax, dword ptr [rsi]
        result += b"\x8B\x06"
    else:
        # mov eax, dword ptr [rsi + <dlc_list_cmp_index>]
        result += b"\x8B\x46"
        result += format_displacement(dlc_list_cmp_index, 1)

    dlc_list_cmp_bytes = b""

    for i in range(0, len(dlc_list)):
        # cmp eax, <4 hex bytes of dlc name ascii bytes>
        dlc_list_cmp_bytes += b"\x3D" + \
            dlc_list[i][0][dlc_list_cmp_index: dlc_list_cmp_index +
                        4].encode("ascii")
        # je copy_dlcX
        dlc_list_cmp_bytes += b"\x74"
        # len(dlc_list)*7 - i*7 until the end of this segment type
        # 2 bytes for the jmp end
        # i*8 to get the correct copy segment
        target_offset = ((len(dlc_list)*7 - (i+1)*7) + 2 + i*8)
        if target_offset > 255:
            print("target_offset larger than 1 byte")
            return get_fallback_mount_handler_asm_bytes(rip, address_containing_dlc_list, len(dlc_list))
        dlc_list_cmp_bytes += format_displacement(target_offset, 1)

    result += dlc_list_cmp_bytes

    copy_common_bytes = b""

    # copy_common:
    # mov rax, 0x6C642F307070612F # "/app0/dl"
    copy_common_bytes += b"\x48\xB8\x2F\x61\x70\x70\x30\x2F\x64\x6C"
    # mov qword ptr [rdx], rax
    copy_common_bytes += b"\x48\x89\x02"
    # mov byte ptr [rdx+8], 0x63 # copy in c so its "/app0/dlc"
    copy_common_bytes += b"\xC6\x42\x08\x63"
    # xor eax, eax
    copy_common_bytes += b"\x31\xC0"
    # mov dword ptr [rdx + 11], eax # zero out from 11-15
    copy_common_bytes += b"\x89\x42\x0B"
    # mov word ptr [rdx + 14], ax
    copy_common_bytes += b"\x66\x89\x42\x0E"

    copy_in_dlc_index_bytes = b""

    for i in range(0, len(dlc_list)):
        # copy_dlc<i>:
        # mov WORD PTR [rdx+0x9], <ascii of dlc index as 2 digits>
        copy_in_dlc_index_bytes += b"\x66\xC7\x42\x09"
        copy_in_dlc_index_bytes += "{:02d}".format(i).encode("ascii")

        # if not last element
        if i != len(dlc_list) - 1:
            # jmp copy_common
            copy_in_dlc_index_bytes += b"\x74"
            # one of these mov & jmp segments is 8 bytes
            jmp_target_offset = (len(dlc_list)*8) - ((i+1)*8) - 2
            if jmp_target_offset > 255:
                print("jmp_target_offset larger than 1 byte")
                return get_fallback_mount_handler_asm_bytes(rip, address_containing_dlc_list, len(dlc_list))
            copy_in_dlc_index_bytes += format_displacement(
                jmp_target_offset, 1)

    # jmp end
    # -2 bc the last copy common doesnt have a jmp at the end
    jmp_end_offset = len(copy_in_dlc_index_bytes) + \
        len(copy_common_bytes) + 2 - 2
    if jmp_end_offset > 255:
        print("jmp_end_offset larger than 1 byte")
        return get_fallback_mount_handler_asm_bytes(rip, address_containing_dlc_list, len(dlc_list))
    result += b"\xEB"
    result += format_displacement(jmp_end_offset, 1)

    result += copy_in_dlc_index_bytes

    result += copy_common_bytes

    # end:
    # xor eax,eax
    result += b"\x31\xC0"
    # ret
    result += b"\xC3"

    fallback = get_fallback_mount_handler_asm_bytes(
        rip, address_containing_dlc_list, len(dlc_list))

    if len(result) > len(fallback):
        print("Fallback mount handler is shorter")
        return fallback

    print("Using short mount handler")
    return result


def get_fallback_mount_handler_asm_bytes(rip, address_containing_dlc_list, dlc_list_length):
    print("Using fallback mount handler")
    # xor rax,rax
    # mov qword ptr [rdx], rax
    # mov qword ptr [rdx+8], rax
    # lea rdi, [rip+0x60]
    # mov rax, qword ptr [rsi]
    # mov rbx, qword ptr [rsi+8]
    # xor rcx, rcx

    # loop:
    # cmp qword ptr [rdi], rax
    # jne loop_next
    # cmp qword ptr [rdi+8], rbx
    # jne loop_next
    # jmp match_found

    # loop_next:
    # inc rcx
    # cmp rcx, 3
    # je cleanup_and_ret
    # add rdi, 24
    # jmp loop

    # match_found:
    # mov rax, 0x7070612F
    # mov dword ptr [rdx], 0x7070612F
    # mov dword ptr [rdx+4], 0x6C642F30
    # mov byte ptr [rdx+8], 0x63

    # mov eax, ecx
    # xor edx, edx
    # mov ecx, 10
    # div ecx

    # add al, 0x30
    # mov byte ptr [rdx+9], al
    # add dl, 0x30
    # mov byte ptr [rdx+10], dl

    # cleanup_and_ret:
    # xor eax,eax
    # ret
    lea_call_length = 7
    bytes_before_lea_call = 10
    lea_rip_offset = address_containing_dlc_list - \
        (rip + bytes_before_lea_call + lea_call_length)
    return bytes.fromhex(f"4831C048890248894208488D3D{format_displacement_str(lea_rip_offset,4)}488B06488B5E084831C9483907750848395F087502EB0F48FFC14883F9{format_displacement_str(dlc_list_length,1)}74374883C718EBE448C7C02F617070C7022F617070C74204302F646CC64208634889D789C831D2B90A000000F7F1043088470980C23088570A31C0C3")

if not idaapi.auto_is_ok():
    ida_kernwin.info("Analysis might not be finished, make sure in the bottom left (below the python button) it says idle.")

print("====================================")

manually_select_strings = False
button_pressed = idaapi.ask_buttons("Automatic", "Manual", "Cancel", idaapi.ASKBTN_CANCEL,
                                    "Do you want to manually or automatically select the strings to use as space for new code?")

if button_pressed == idaapi.ASKBTN_CANCEL:
    print("Exiting")
    exit()
elif button_pressed == idaapi.ASKBTN_NO:
    idaapi.info(
        "Please select the strings that are errors/warnings or otherwise seems safe to overwrite")
    manually_select_strings = True

extraDataText = ""
noExtraDataText = ""

f = DlcContentIDInputForm(extraDataText, noExtraDataText)
f.show_and_wait()

extraDataText = f.txtLeft.value.replace(" ", "").replace("\n", "").replace("\r", "").replace("\t", "")
noExtraDataText = f.txtRight.value.replace(" ", "").replace("\n", "").replace("\r", "").replace("\t", "")


if len(extraDataText + noExtraDataText) == 0:
    ida_kernwin.warning("No input")
    exit()

if len(extraDataText) % 16 != 0 or len(noExtraDataText) % 16 != 0:
    ida_kernwin.warning(
        "Invalid input length, each content id should be 16 characters long")
    exit()

dlc_list = []

for i in range(0, len(extraDataText), 16):
    dlc_list.append((extraDataText[i:i+16],True))

for i in range(0, len(noExtraDataText), 16):
    dlc_list.append((noExtraDataText[i:i+16],False))


if len(dlc_list) > 100:
    ida_kernwin.warning("Too many DLCs, max of 100 is supported")
    exit()

mount_handler_asm_len = get_mount_handler_asm_len(dlc_list)
list_handler_asm_len = 43

# get list of strings in the CODE section
all_strings = idautils.Strings()
strings_in_code_segment = [
    s for s in all_strings if idc.get_segm_name(s.ea) == "CODE"]

if manually_select_strings:
    # filter strings_in_code_segment to strings at least list_handler_asm_len + 2 long
    temp = [s for s in strings_in_code_segment if s.length >=
            list_handler_asm_len + 2]
    temp.sort(key=lambda s: s.length, reverse=True)
    chooser = StringChooser("Choose the string to patch [1] (list handler)", [
                        (str(s), s.length, s.ea) for s in temp])
    res = chooser.Show(True)
    if res == -1:
        raise Exception("No string selected")
    
    list_handler_asm_target_string = next(
        (s for s in strings_in_code_segment if s.ea == chooser.items[res-1][2]), None)
    if list_handler_asm_target_string is None:
        raise Exception("No string selected")

    temp = [s for s in strings_in_code_segment if s.length >=
            mount_handler_asm_len + 2 and s.ea != list_handler_asm_target_string.ea]
    temp.sort(key=lambda s: s.length, reverse=True)
    chooser = StringChooser("Choose the string to patch [2] (mount handler)", [
                        (str(s), s.length, s.ea) for s in temp])
    res = chooser.Show(True)
    if res == -1:
        raise Exception("No string selected")

    mount_handler_asm_target_string = next(
        (s for s in strings_in_code_segment if s.ea == chooser.items[res-1][2]), None)
    if mount_handler_asm_target_string is None:
        ida_kernwin.warning("No string selected")
        exit()
else:
    # find strings that contain %s %d, these are likely okay to get rid of
    fstrings = [s for s in strings_in_code_segment if "%d" in str(
        s) or "%s" in str(s)]

    fstrings.sort(key=lambda s: s.length, reverse=True)
    list_handler_asm_target_string = None
    mount_handler_asm_target_string = None
    for i in range(len(fstrings)):
        if list_handler_asm_target_string is None and len(str(fstrings[i])) >= list_handler_asm_len + 2:
            list_handler_asm_target_string = fstrings[i]
        elif len(str(fstrings[i])) >= (mount_handler_asm_len + 2) and fstrings[i].ea != list_handler_asm_target_string.ea and list_handler_asm_target_string is not None:
            mount_handler_asm_target_string = fstrings[i]
            break

    if list_handler_asm_target_string is None or mount_handler_asm_target_string is None:
        ida_kernwin.warning(
            "Couldn't find the strings needed for the patch. Retry in manual mode")
        exit()

print(f"list_handler_asm_target_string ida: {get_hex(list_handler_asm_target_string.ea)} | real: {get_hex(get_real_address(list_handler_asm_target_string.ea))}")
print(f"mount_handler_asm_target_string ida: {get_hex(mount_handler_asm_target_string.ea)} | real: {get_hex(get_real_address(mount_handler_asm_target_string.ea))}")

dlc_list_bytes = b""
for dlc in dlc_list:
    # convert dlc content id to ascii bytes
    dlc_list_bytes += dlc[0].encode("ascii")
    # append 4 null bytes (contentid is 16 bytes long + null terminator + 3 padding)
    dlc_list_bytes += b"\x00\x00\x00\x00"
    # status -> 4 = installed | 0 -> no extra data
    dlc_list_bytes += b"\x04\x00\x00\x00" if dlc[1] else b"\x00\x00\x00\x00"

if manually_select_strings:
    temp = [s for s in all_strings if s.length >= len(
        dlc_list_bytes) + 2 and s.ea != list_handler_asm_target_string.ea and s.ea != mount_handler_asm_target_string.ea]
    temp.sort(key=lambda s: s.length, reverse=True)
    chooser = StringChooser("Choose the string to patch [3] (dlc list)", [
                        (str(s), s.length, s.ea) for s in temp])
    res = chooser.Show(True)
    if res == -1:
        raise Exception("No string selected")
    
    dlc_list_target_string = next(
        (s for s in temp if s.ea == chooser.items[res-1][2]), None)
    if dlc_list_target_string is None:
        ida_kernwin.warning("No string selected")
        exit()
else:
    dlc_list_target_string = None
    dlc_list_candidates_list = [s for s in all_strings if "%s" in str(
        s) or "%d" in str(s) or "deprecated" in str(s)]
    dlc_list_candidates_list.sort(key=lambda s: s.length, reverse=True)

    for i in range(len(dlc_list_candidates_list)):
        if dlc_list_candidates_list[i].length >= len(dlc_list_bytes) + 2 and dlc_list_candidates_list[i].ea != list_handler_asm_target_string.ea and dlc_list_candidates_list[i].ea != mount_handler_asm_target_string.ea:
            dlc_list_target_string = dlc_list_candidates_list[i]
            break

    if dlc_list_target_string is None:
        ida_kernwin.warning(
            "Couldn't find the string needed for the patch. Retry in manual mode")
        exit()

print(f"dlc_list_target_string ida: {get_hex(dlc_list_target_string.ea)} | real: {get_hex(get_real_address(dlc_list_target_string.ea))}")


# new list handler code starts at list_handler_asm_target_string.ea + 2
# there are 6 bytes before the lea instruction
# length of lea instruction is 7 bytes
rip = 7 + 6 + list_handler_asm_target_string.ea + 2
target = dlc_list_target_string.ea + 2
target_offset = target - rip

#     test rdx, rdx
#     jz handle_null
#     push rcx
#     lea rdx, [rip + 0x60]
#     mov ch, 3
# loop:
#         mov rax, qword ptr [rdx]
#         mov qword ptr [rsi], rax
#         add rsi, 8
#         add rdx, 8
#         dec ch
#         jnz loop
#         pop rcx
# handle_null:
#     mov dword ptr [rcx], 1
# end:
#     xor eax, eax
#     ret

list_handler_asm_bytes = bytes.fromhex(
    f"48 85 D2 74 1D 51 48 8D 15 {format_displacement_str(target_offset,4)} B5 {format_displacement_str(len(dlc_list)*3,1)} 488B024889064883C6084883C208FECD75EE59C701 {format_displacement_str(len(dlc_list),4)} 31C0C3")

sceAppContentGetAddcontInfoList = idaapi.get_name_ea(
    idaapi.BADADDR, 'sceAppContentGetAddcontInfoList')

sceAppContentGetAddcontInfoList_patches = []

for xref in idautils.XrefsTo(sceAppContentGetAddcontInfoList, 0):
    if xref.type == idaapi.fl_CF or xref.type == idaapi.fl_CN:
        sceAppContentGetAddcontInfoList_patches.append(xref)

if len(sceAppContentGetAddcontInfoList_patches) == 0:
    ida_kernwin.warning(
        "No references to sceAppContentGetAddcontInfoList found, this likely means something went wrong in the decompilation step or the game is unsupported by this script, exiting...")
    exit()

sceAppContentAddcontMount = idaapi.get_name_ea(
    idaapi.BADADDR, 'sceAppContentAddcontMount')

sceAppContentAddcontMount_patches = []

if len(sceAppContentAddcontMount) == 0:
    ida_kernwin.info(
        "No references to sceAppContentAddcontMount found, this is okay none of the dlcs contain extra data, otherwise this likely means something went wrong in the decompilation step, exiting...")

for xref in idautils.XrefsTo(sceAppContentAddcontMount, 0):
    if xref.type == idaapi.fl_CF or xref.type == idaapi.fl_CN:
        sceAppContentAddcontMount_patches.append(xref)

sceAppContentAddcontUnmount = idaapi.get_name_ea(
    idaapi.BADADDR, 'sceAppContentAddcontUnmount')

sceAppContentAddcontUnmount_patches = []

for xref in idautils.XrefsTo(sceAppContentAddcontUnmount, 0):
    if xref.type == idaapi.fl_CF or xref.type == idaapi.fl_CN:
        sceAppContentAddcontUnmount_patches.append(xref)


output_file = idaapi.ask_file(
    1, "eboot_patched.elf", "Save patched eboot (*.txt)")

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
    mount_handler_asm_bytes = get_mount_handler_asm_bytes(
        dlc_list, mount_handler_asm_target_string.ea+2, dlc_list_target_string.ea+2)
    f.write(b"\x00")
    f.write(mount_handler_asm_bytes)

    f.seek(get_real_address(dlc_list_target_string.ea) + 1)
    f.write(b"\x00")
    f.write(dlc_list_bytes)

    for patch in sceAppContentGetAddcontInfoList_patches:
        f.seek(get_real_address(patch.frm))
        f.write(b'\xE8')
        print(
            f"patching sceAppContentGetAddcontInfoList ida: {get_hex(patch.frm)} | real: {get_hex(get_real_address(patch.frm))}")
        # if you see this and know where i fucked up the math that i need to subtract 10 please let me know
        f.write(format_displacement(
            list_handler_asm_target_string.ea + 2 - patch.frm + 5 - 10, 4))

    for patch in sceAppContentAddcontMount_patches:
        f.seek(get_real_address(patch.frm))
        f.write(b'\xE8')
        print(
            f"patching sceAppContentAddcontMount  ida: {get_hex(patch.frm)} | real: {get_hex(get_real_address(patch.frm))}")
        f.write(format_displacement(
            mount_handler_asm_target_string.ea + 2 - patch.frm + 5 - 10, 4))

    for patch in sceAppContentAddcontUnmount_patches:
        f.seek(get_real_address(patch.frm))
        print(
            f"patching sceAppContentAddcontUnmount ida: {get_hex(patch.frm)} | real: {get_hex(get_real_address(patch.frm))}")
        f.write(b'\xb8\x00\x00\x00\x00')

ida_kernwin.info("Patching complete")
