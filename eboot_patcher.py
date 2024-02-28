import binascii
import ida_loader
import ida_kernwin
import idaapi
import idautils
import idc
import hashlib
import struct
import base64
import gzip


# i wanted to keep it in one single file, especially to avoid confusion because this needs to be customized for each game.
dlcldr_prx_gz_base64 = "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"
dlcldr_prx_dlc_count_offset = 0x108A0
dlcldr_prx_dlc_data_offset = 0x108B0
max_dlc_count = 2500 # this limit is in the official sdk

# from ps4 module loader by socraticbliss
class Binary:
    def __init__(self, f):
        f.seek(0)

        self.EI_MAGIC = struct.unpack('4s', f.read(4))[0]
        self.EI_CLASS = struct.unpack('<B', f.read(1))[0]
        self.EI_DATA = struct.unpack('<B', f.read(1))[0]
        self.EI_VERSION = struct.unpack('<B', f.read(1))[0]
        self.EI_OSABI = struct.unpack('<B', f.read(1))[0]
        self.EI_ABIVERSION = struct.unpack('<B', f.read(1))[0]
        self.EI_PADDING = struct.unpack('6x', f.read(6))
        self.EI_SIZE = struct.unpack('<B', f.read(1))[0]

        # Elf Properties
        self.E_TYPE = struct.unpack('<H', f.read(2))[0]
        self.E_MACHINE = struct.unpack('<H', f.read(2))[0]
        self.E_VERSION = struct.unpack('<I', f.read(4))[0]
        self.E_START_ADDR = struct.unpack('<Q', f.read(8))[0]
        self.E_PHT_OFFSET = struct.unpack('<Q', f.read(8))[0]
        self.E_SHT_OFFSET = struct.unpack('<Q', f.read(8))[0]
        self.E_FLAGS = struct.unpack('<I', f.read(4))[0]
        self.E_SIZE = struct.unpack('<H', f.read(2))[0]
        self.E_PHT_SIZE = struct.unpack('<H', f.read(2))[0]
        self.E_PHT_COUNT = struct.unpack('<H', f.read(2))[0]
        self.E_SHT_SIZE = struct.unpack('<H', f.read(2))[0]
        self.E_SHT_COUNT = struct.unpack('<H', f.read(2))[0]
        self.E_SHT_INDEX = struct.unpack('<H', f.read(2))[0]

        f.seek(self.E_PHT_OFFSET)

        # Elf Program Header Table
        Binary.E_SEGMENTS = [Segment(f) for entry in range(self.E_PHT_COUNT)]


class Segment:
    SEGPERM_EXEC = 1
    SEGPERM_WRITE = 2
    SEGPERM_READ = 4

    def __init__(self, f):
        self.SEGMENT_DESCRIPTOR_OFFSET = f.tell()
        self.SEGMENT_FILE_SIZE_OFFSET = self.SEGMENT_DESCRIPTOR_OFFSET + 32
        self.SEGMENT_MEM_SIZE_OFFSET = self.SEGMENT_DESCRIPTOR_OFFSET + 40
        self.TYPE = struct.unpack('<I', f.read(4))[0]
        self.FLAGS = struct.unpack('<I', f.read(4))[0]
        self.OFFSET = struct.unpack('<Q', f.read(8))[0]
        self.MEM_ADDR = struct.unpack('<Q', f.read(8))[0]
        self.FILE_ADDR = struct.unpack('<Q', f.read(8))[0]
        self.FILE_SIZE = struct.unpack('<Q', f.read(8))[0]
        self.MEM_SIZE = struct.unpack('<Q', f.read(8))[0]
        self.ALIGNMENT = struct.unpack('<Q', f.read(8))[0]

    def flags(self):
        return self.FLAGS & 0xF

    def __eq__(self, __value: object) -> bool:
        return self.FILE_ADDR == __value.FILE_ADDR and self.FILE_SIZE == __value.FILE_SIZE and self.MEM_ADDR == __value.MEM_ADDR and self.MEM_SIZE == __value.MEM_SIZE and self.OFFSET == __value.OFFSET and self.TYPE == __value.TYPE and self.FLAGS == __value.FLAGS and self.ALIGNMENT == __value.ALIGNMENT


class DlcContentIDInputForm(idaapi.Form):
    def __init__(self, extraDataText, noExtraDataText):
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
        self.selection = None
        self.selectedIndex = None

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return [self.items[n][0], str(self.items[n][1])]

    def OnSelectLine(self, n):
        self.selectedIndex = n
        self.selection = self.items[n]
        self.Close()


def get_real_address(ea):
    offset = ida_loader.get_fileregion_offset(ea)
    if offset == idaapi.BADADDR or offset == -1:
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


def get_prx_loader_asm_bytes_length():
    return len(get_prx_loader_asm_bytes(0, 0, 0))


def get_prx_loader_asm_bytes(rip, sceKernelLoadStartModule_addr, prx_path_str_addr):
    # lea rdi, [rip+prx_path_str_addr]
    # xor rsi, rsi
    # xor rdx, rdx
    # xor rcx, rcx
    # xor r8, r8
    # xor r9, r9
    # call sceKernelLoadStartModule
    # xor eax, eax
    # ret
    prx_path_str_addr_offset = prx_path_str_addr - rip - 7
    sceKernelLoadStartModule_call_offset = sceKernelLoadStartModule_addr - rip - 27
    return bytes.fromhex(f"488D3D {format_displacement_str(prx_path_str_addr_offset,4)} 4831F64831D24831C94D31C04D31C9E8 {format_displacement_str(sceKernelLoadStartModule_call_offset,4)} 31C0C3")


# https://github.com/OpenOrbis/create-fself/blob/3dce1170125bf93ebca2b19236691359f8753d2f/pkg/oelf/OELFGenDynlibData.go#L626
def calculateNID(symbolName):
    suffix = bytes.fromhex("518D64A635DED8C1E6B039B1C3E55230")
    symbol = symbolName.encode() + suffix
    hash = hashlib.sha1(symbol).digest()
    hashBytes = struct.pack('>Q', struct.unpack('<Q', hash[:8])[0])
    nidHash = base64.b64encode(hashBytes).decode()[:-1]
    nidHash = nidHash.replace("/", "-")

    return nidHash


class SegmentInfo:
    def __init__(self, start, end, start_of_next, segment_start):
        self.unused_space_start = start
        self.unused_space_end = end
        self.start_of_next = start_of_next
        self.segment_start = segment_start


print("===============================")

function_symbols = [
    # "sceAppContentInitialize", # this is handled explicitly
    "sceAppContentGetAddcontInfo",
    "sceAppContentGetAddcontInfoList",
    "sceAppContentGetEntitlementKey",
    "sceAppContentAddcontMount",
    "sceAppContentAddcontUnmount",
    "sceAppContentAddcontDelete",
    "sceAppContentAppParamGetInt",
    "sceAppContentAddcontEnqueueDownload",
    "sceAppContentTemporaryDataMount2",
    "sceAppContentTemporaryDataUnmount",
    "sceAppContentTemporaryDataFormat",
    "sceAppContentTemporaryDataGetAvailableSpaceKb",
    "sceAppContentDownloadDataFormat",
    "sceAppContentDownloadDataGetAvailableSpaceKb",
    "sceAppContentGetAddcontDownloadProgress",
    "sceAppContentAddcontEnqueueDownloadByEntitlemetId",
    "sceAppContentAddcontEnqueueDownloadSp",
    "sceAppContentAddcontMountByEntitlemetId",
    "sceAppContentAddcontShrink",
    "sceAppContentAppParamGetString",
    "sceAppContentDownload0Expand",
    "sceAppContentDownload0Shrink",
    "sceAppContentDownload1Expand",
    "sceAppContentDownload1Shrink",
    "sceAppContentGetAddcontInfoByEntitlementId",
    "sceAppContentGetAddcontInfoListByIroTag",
    "sceAppContentGetDownloadedStoreCountry",
    "sceAppContentGetPftFlag",
    "sceAppContentGetRegion",
    "sceAppContentRequestPatchInstall",
    "sceAppContentSmallSharedDataFormat",
    "sceAppContentSmallSharedDataGetAvailableSpaceKb",
    "sceAppContentSmallSharedDataMount",
    "sceAppContentSmallSharedDataUnmount",
]

fake_symbol_prefix = "dlcldr_"

function_symbols_with_real_and_fake_nids = []
for symbol in function_symbols:
    real_nid = calculateNID(symbol)
    fake_nid = calculateNID(fake_symbol_prefix + symbol)
    function_symbols_with_real_and_fake_nids.append(
        (symbol, real_nid, fake_nid, False))

prx_path = "/app0/dlcldr.prx"
prx_loader_code_length = get_prx_loader_asm_bytes_length()
no_of_bytes_required_for_patches_in_eboot = 1 + \
    prx_loader_code_length + 1 + len(prx_path) + 1
unused_space_at_end_of_code_segment_bounds = None

segments = idautils.Segments()
t_code_segment = idaapi.get_segm_by_name("CODE")
if t_code_segment is None:
    raise Exception("No code segment found")

t_next_segment = idaapi.get_next_seg(t_code_segment.start_ea)
if t_next_segment is None:
    raise Exception("No next segment found")

# the chance that the align at the end of code has enough space for the prx loader is basically 100%
# we just need 50 bytes (i looked at about 20 games and the smallest ive seen is 800 bytes)

# sometimes the align between the code segment isnt part of the segment
# we can patch this to be able to use that space for new code
# otherwise page fault if that space is used
if t_code_segment.end_ea != t_next_segment.start_ea:
    unused_space_at_end_of_code_segment_bounds = SegmentInfo(
        t_code_segment.end_ea, t_next_segment.start_ea, t_next_segment.start_ea, t_code_segment.start_ea)
    print(
        f"Unused space between code segment and next segment: {get_hex(unused_space_at_end_of_code_segment_bounds.unused_space_start)} - {get_hex(unused_space_at_end_of_code_segment_bounds.unused_space_end)}")

# if this is true then the align is already part of the code segment (ida interprets it as part of the code segment if the align field in the pht is set to 4k?)
# find the offset where the zeroes begin
if unused_space_at_end_of_code_segment_bounds is None or unused_space_at_end_of_code_segment_bounds.unused_space_end - unused_space_at_end_of_code_segment_bounds.unused_space_start < no_of_bytes_required_for_patches_in_eboot:
    code_segment = idaapi.get_segm_by_name("CODE")
    # we already know the start of the next is the same
    code_segment_end = code_segment.end_ea - 1
    zeroes_count = 0
    last_byte = 0
    while last_byte == 0:
        if not idc.is_loaded(code_segment_end - zeroes_count):
            last_byte = 0
        else:
            last_byte = idc.get_wide_byte(code_segment_end - zeroes_count)

        if last_byte == 0:
            zeroes_count += 1

    unused_space_at_end_of_code_segment_bounds = SegmentInfo(
        code_segment_end - zeroes_count + 1, code_segment_end, code_segment_end, code_segment.start_ea)
    print(
        f"Unused space at end of code segment: {get_hex(unused_space_at_end_of_code_segment_bounds.unused_space_start)} - {get_hex(unused_space_at_end_of_code_segment_bounds.unused_space_end)}")

if unused_space_at_end_of_code_segment_bounds is None or unused_space_at_end_of_code_segment_bounds.unused_space_end - unused_space_at_end_of_code_segment_bounds.unused_space_start < no_of_bytes_required_for_patches_in_eboot:
    # set to None so i can easily check if we need to fall back to string patching
    # if there isnt enough space in the align
    unused_space_at_end_of_code_segment_bounds = None
    print("Using string as space for patches because not enough free space at end of code segment")
    raise Exception("String fallback not implemented")


use_sceAppContentInitialize_to_sceKernelLoadStartModule_patch = False
sceKernelLoadStartModule_address = idaapi.get_name_ea(
    idaapi.BADADDR, "sceKernelLoadStartModule")
if sceKernelLoadStartModule_address == idaapi.BADADDR:
    print("sceKernelLoadStartModule not found, using sceAppContentInitialize to sceKernelLoadStartModule patch")
    use_sceAppContentInitialize_to_sceKernelLoadStartModule_patch = True
    sceKernelLoadStartModule_address = idaapi.get_name_ea(
        idaapi.BADADDR, "sceAppContentInitialize")
    if sceKernelLoadStartModule_address == idaapi.BADADDR:
        raise Exception("sceAppContentInitialize function not found")
    sceKernelLoadStartModule_address = idaapi.get_func(
        sceKernelLoadStartModule_address).start_ea
else:
    print("sceKernelLoadStartModule found")
    sceKernelLoadStartModule_address = idaapi.get_func(
        sceKernelLoadStartModule_address).start_ea

prx_loader_bytes_start = unused_space_at_end_of_code_segment_bounds.unused_space_start
prx_loader_bytes = get_prx_loader_asm_bytes(
    prx_loader_bytes_start, sceKernelLoadStartModule_address, prx_loader_bytes_start + prx_loader_code_length)


# find where sceSysmoduleLoadModule with 0xb4 (libSceAppContent) is called
sceSysmoduleLoadModule = idaapi.get_name_ea(
    idaapi.BADADDR, 'sceSysmoduleLoadModule')

refs = sorted(list(idautils.CodeRefsTo(sceSysmoduleLoadModule, 0)))

sceSysmoduleLoadModule_call_to_overwrite = None
found = False

for ref in refs:
    if found:
        break

    prev_head = idc.prev_head(ref)
    count = 0

    while prev_head != idaapi.BADADDR and count < 10:
        mnem = idc.print_insn_mnem(prev_head)
        if mnem == 'mov' and idc.print_operand(prev_head, 0) == 'edi':
            value = idc.get_operand_value(prev_head, 1)
            # 0xB4 is libSceAppContent
            if value == 0xB4:
                print(
                    f"sceSysmoduleLoadModule for libSceAppContent at {get_hex(ref)}")
                sceSysmoduleLoadModule_call_to_overwrite = ref
                found = True
            break
        prev_head = idc.prev_head(prev_head)
        count += 1

if sceSysmoduleLoadModule_call_to_overwrite is None:
    raise Exception("sceSysmoduleLoadModule for libSceAppContent not found")


# patch out sceAppContentInitialize calls, as they arent used, and might be replaced with sceKernelLoadStartModule
sceAppContentInitialize = idaapi.get_name_ea(
    idaapi.BADADDR, 'sceAppContentInitialize')

sceAppContentInitialize_patches = []

for xref in idautils.XrefsTo(sceAppContentInitialize, 0):
    if xref.type == idaapi.fl_CN or xref.type == idaapi.fl_JN:
        # if xref is the function definition, skip it
        if xref.frm == idaapi.get_func(sceAppContentInitialize).start_ea:
            continue

        print(
            f"Found reference to sceAppContentInitialize at {get_hex(xref.frm)} | type: {xref.type}")
        sceAppContentInitialize_patches.append(xref)

if len(sceAppContentInitialize_patches) == 0:
    raise Exception("No references to sceAppContentInitialize found")

input_file = idaapi.get_input_file_path()

replacements = [
    ("libSceAppContentUtil\0".encode("ascii"),
        "dlcldr\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0".encode("ascii"), False),
    ("libSceAppContent\0".encode("ascii"),
        "dlcldr\0\0\0\0\0\0\0\0\0\0\0".encode("ascii"), False),
    ("libSceAppContentBundle\0".encode("ascii"),
        "dlcldr\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0".encode("ascii"), False),
    ("libSceAppContentIro\0".encode("ascii"),
        "dlcldr\0\0\0\0\0\0\0\0\0\0\0\0\0\0".encode("ascii"), False),
    ("libSceAppContentPft\0".encode("ascii"),
        "dlcldr\0\0\0\0\0\0\0\0\0\0\0\0\0\0".encode("ascii"), False),
    ("libSceAppContentSc\0".encode("ascii"),
        "dlcldr\0\0\0\0\0\0\0\0\0\0\0\0\0".encode("ascii"), False),
]

patches = []

# add prx loader bytes & prx path to patches
prx_loader_with_path_and_terminator_bytes = prx_loader_bytes + \
    prx_path.encode("ascii") + b"\x00"


libkernel_nid_suffix = None

libkernel_symbols = [
    "sceKernelRead",
    "sceKernelWrite",
    "sceKernelOpen",
    "sceKernelClose",
    "sceKernelUnlink",
    "sceKernelChmod",
    "sceKernelCheckReachability",
    "sceKernelSync",
    "sceKernelFsync",
    "sceKernelFdatasync",
    "sceKernelFcntl",
    "sceKernelReadv",
    "sceKernelWritev",
    "sceKernelFchmod",
    "sceKernelRename",
    "sceKernelMkdir",
    "sceKernelRmdir",
    "sceKernelUtimes",
    "sceKernelStat",
    "sceKernelFstat",
    "sceKernelFutimes",
    "sceKernelGetdirentries",
    "sceKernelGetdents",
    "sceKernelPreadv",
    "sceKernelPwritev",
    "sceKernelPread",
    "sceKernelPwrite",
    "sceKernelMmap",
    "sceKernelLseek",
    "sceKernelTruncate",
    "sceKernelFtruncate",
    "sceKernelSetCompressionAttribute",
    "sceKernelLwfsSetAttribute",
    "sceKernelLwfsAllocateBlock",
    "sceKernelLwfsTrimBlock",
    "sceKernelLwfsLseek",
    "sceKernelLwfsWrite",
    "sceKernelMlock",
    "sceKernelMunlock",
    "sceKernelMprotect",
    "sceKernelMsync",
    "sceKernelMunmap",
    "sceKernelMlockall",
    "sceKernelMunlockall",
    "sceKernelSleep",
    "sceKernelUsleep",
    "sceKernelNanosleep",
    "sceKernelClockGetres",
    "sceKernelClockGettime",
    "sceKernelGettimeofday",
    "sceKernelGetTscFrequency",
    "sceKernelReadTsc",
    "sceKernelGetProcessTime",
    "sceKernelGetProcessTimeCounter",
    "sceKernelGetProcessTimeCounterFrequen",
    "sceKernelGetCurrentCpu",
    "sceKernelLoadStartModule",
    "sceKernelStopUnloadModule",
    "sceKernelDlsym",
    "sceKernelGetModuleList",
    "sceKernelSetGPO",
    "sceKernelGetGPI",
    "sceKernelSetFsstParam",
    "sceKernelGetCpumode",
    "sceKernelIsNeoMode",
]

libkernel_nids = []

for symbol in libkernel_symbols:
    libkernel_nids.append("\0" + calculateNID(symbol) + "#")

sceAppContentInitialize_nid = f'\0{calculateNID("sceAppContentInitialize")}#'
sceAppContentInitialize_nid_pos = -1
libSceAppContent_nid_suffix = None

with open(input_file, "rb") as f:
    bin = Binary(f)

    SEGPERM_EXEC = 1
    SEGPERM_WRITE = 2
    SEGPERM_READ = 4
    for segment in bin.E_SEGMENTS:
        if segment.flags() == (SEGPERM_EXEC | SEGPERM_READ):  # is code segment
            # check if filesize and memsize need to be increased
            t_new_segment_size = unused_space_at_end_of_code_segment_bounds.unused_space_start + \
                no_of_bytes_required_for_patches_in_eboot - \
                unused_space_at_end_of_code_segment_bounds.segment_start
            if segment.FILE_SIZE < t_new_segment_size:
                print(
                    f"Segment FILE_SIZE needs patching: (filesize){get_hex(segment.FILE_SIZE)} < (new size){get_hex(t_new_segment_size)}")
                patches.append(
                    (segment.SEGMENT_FILE_SIZE_OFFSET, format_displacement(t_new_segment_size, 8), "PHT code seg FILE_SIZE"))
            else:
                print(
                    f"Segment FILE_SIZE does not need patching: (filesize){get_hex(segment.FILE_SIZE)} >= (new size){get_hex(t_new_segment_size)}")
            if segment.MEM_SIZE < t_new_segment_size:
                print(
                    f"Segment MEM_SIZE needs patching: (memsize){get_hex(segment.MEM_SIZE)} < (new size){get_hex(t_new_segment_size)}")
                patches.append(
                    (segment.SEGMENT_MEM_SIZE_OFFSET, format_displacement(t_new_segment_size, 8), "PHT code seg MEM_SIZE"))
            else:
                print(
                    f"Segment MEM_SIZE does not need patching: (memsize){get_hex(segment.MEM_SIZE)} >= (new size){get_hex(t_new_segment_size)}")
            break

    f.seek(0)
    chunk_size = 1024 * 1024
    offset = 0
    while True:
        chunk = f.read(chunk_size)
        if not chunk:
            break

        if use_sceAppContentInitialize_to_sceKernelLoadStartModule_patch:
            if sceAppContentInitialize_nid_pos == -1:
                sceAppContentInitialize_nid_pos = chunk.find(
                    sceAppContentInitialize_nid.encode("ascii"))
                if sceAppContentInitialize_nid_pos != -1:
                    sceAppContentInitialize_nid_pos = offset + \
                        sceAppContentInitialize_nid_pos + 1
                    t_pos = f.tell()
                    f.seek(sceAppContentInitialize_nid_pos + 11)
                    libSceAppContent_nid_suffix = ""
                    while True:
                        t_byte = f.read(1)
                        if t_byte == b"\x00":
                            break
                        libSceAppContent_nid_suffix = libSceAppContent_nid_suffix + t_byte.decode(
                            "ascii")
                    f.seek(t_pos)
                    print(
                        f"Found libSceAppContent nid suffix: {libSceAppContent_nid_suffix}")
                    print(
                        f"Found sceAppContentInitialize nid at offset (real) {get_hex(sceAppContentInitialize_nid_pos)}")

            if libkernel_nid_suffix is None:
                for libkernel_nid in libkernel_nids:
                    index = chunk.find(libkernel_nid.encode("ascii"))
                    if index != -1:
                        t_pos = f.tell()
                        f.seek(offset + index + 12)
                        libkernel_nid_suffix = ""
                        while True:
                            t_byte = f.read(1)
                            if t_byte == b"\x00":
                                break
                            libkernel_nid_suffix = libkernel_nid_suffix + t_byte.decode(
                                "ascii")
                        f.seek(t_pos)
                        print(
                            f"Found libkernel nid suffix: {libkernel_nid_suffix} at offset (real) {get_hex(offset + index + 12)}")
                        break

        for i in range(len(replacements)):
            if replacements[i][2]:
                continue
            replacement = replacements[i]
            index = chunk.find(replacement[0])
            if index != -1:
                patches.append(
                    (offset + index, replacement[1], replacement[0].decode("ascii")))
                replacements[i] = (replacement[0], replacement[1], True)

        # for function_symbol_with_real_and_fake_nid in function_symbols_with_real_and_fake_nids:
        #     if function_symbol_with_real_and_fake_nid[3]:
        #         continue
        #     real_nid = function_symbol_with_real_and_fake_nid[1]
        #     index = chunk.find(real_nid.encode("ascii"))
        #     if index != -1:
        #         patches.append(
        #             (offset + index, function_symbol_with_real_and_fake_nid[2].encode("ascii"), function_symbol_with_real_and_fake_nid[0]))
        #         function_symbol_with_real_and_fake_nid = (
        #             function_symbol_with_real_and_fake_nid[0], function_symbol_with_real_and_fake_nid[1], function_symbol_with_real_and_fake_nid[2], True)

        for i in range(len(function_symbols_with_real_and_fake_nids)):
            if function_symbols_with_real_and_fake_nids[i][3]:
                continue
            real_nid = function_symbols_with_real_and_fake_nids[i][1]
            index = chunk.find(real_nid.encode("ascii"))
            if index != -1:
                patches.append(
                    (offset + index, function_symbols_with_real_and_fake_nids[i][2].encode("ascii"), function_symbols_with_real_and_fake_nids[i][0]))
                function_symbols_with_real_and_fake_nids[i] = (
                    function_symbols_with_real_and_fake_nids[i][0], function_symbols_with_real_and_fake_nids[i][1], function_symbols_with_real_and_fake_nids[i][2], True)

        offset += len(chunk)

# appcontent and appcontentutil are required
if not replacements[0][2] or not replacements[1][2]:
    raise Exception("Not all module/library names found for replacement")

nid_patches_count = sum(bool(x[3])
                        for x in function_symbols_with_real_and_fake_nids)
print(f"Number of nids found for replacement: {nid_patches_count}")

if nid_patches_count == 0:
    raise Exception("No NIDs found for replacement")

if use_sceAppContentInitialize_to_sceKernelLoadStartModule_patch:
    if libkernel_nid_suffix is None:
        raise Exception("libkernel nid suffix not found")

    if sceAppContentInitialize_nid_pos == -1:
        raise Exception("sceAppContentInitialize nid not found")

    if len(libSceAppContent_nid_suffix) != len(libkernel_nid_suffix):
        raise Exception(
            "libSceAppContent nid suffix length != libkernel nid suffix length")

    t_newnid = calculateNID("sceKernelLoadStartModule") + libkernel_nid_suffix
    patches.append(
        (sceAppContentInitialize_nid_pos, t_newnid.encode("ascii"), f"sceAppContentInitialize to sceKernelLoadStartModule nid [{t_newnid}]"))


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

if len(dlc_list) > max_dlc_count:
    raise Exception(f"Too many DLCs, max {max_dlc_count} is supported")

patched_elf_output_path = idaapi.ask_file(
    1, "eboot_patched.elf", "Save patched eboot (*.elf)")

if patched_elf_output_path is None:
    raise Exception("No output file selected")

patched_prx_output_path = idaapi.ask_file(
    1, "dlcldr.prx", "Save patched dlcldr (*.prx)")

if patched_prx_output_path is None:
    raise Exception("No output file selected")


with open(input_file, "rb") as f:
    with open(patched_elf_output_path, "wb") as g:
        g.write(f.read())

with open(patched_elf_output_path, "r+b") as f:
    for patch in patches:
        f.seek(patch[0])
        f.write(patch[1])
        print(
            f"Replaced {patch[2]} at (real) offset {get_hex(patch[0])}")

    t_realaddr = get_real_address(
        unused_space_at_end_of_code_segment_bounds.unused_space_start - 1) + 1

    f.seek(t_realaddr)
    t_sanity_check = f.read(1)
    if t_sanity_check != b'\x00':
        raise Exception("Sanity check failed")
    f.seek(t_realaddr)
    f.write(prx_loader_with_path_and_terminator_bytes)

    f.seek(get_real_address(sceSysmoduleLoadModule_call_to_overwrite))
    f.write(b"\xE8")
    f.write(format_displacement(
        t_realaddr - get_real_address(sceSysmoduleLoadModule_call_to_overwrite) - 5, 4))

    for patch in sceAppContentInitialize_patches:
        f.seek(get_real_address(patch.frm))
        if patch.type is idaapi.fl_JN:
            # read first byte and check if its e9
            # the ff in the function loader is also a jmp near
            f.seek(get_real_address(patch.frm))
            ret = f.read(1)
            if ret != b'\xE9':
                continue
            f.seek(get_real_address(patch.frm))
            # compiler optimization? (putting jmp to a function at the end of a function)
            # i only saw this in dead cells
            # xor eax, eax
            # nop
            # nop
            # ret
            f.write(b'\x31\xC0\x90\x90\xC3')
        else:
            f.write(b'\xB8\x00\x00\x00\x00')
        print(
            f"Patched call to sceAppContentInitialize ida: {get_hex(patch.frm)} | real: {get_hex(get_real_address(patch.frm))}")

with open(patched_prx_output_path, "wb") as f:
    f.seek(0)
    
    decoded_bytes = base64.b64decode(dlcldr_prx_gz_base64)

    decompressed_bytes = gzip.decompress(decoded_bytes)

    f.write(decompressed_bytes)

    f.seek(dlcldr_prx_dlc_count_offset)
    f.write(format_displacement(len(dlc_list), 4))

    f.seek(dlcldr_prx_dlc_data_offset)

    for dlc in dlc_list:
        # typedef struct SceNpUnifiedEntitlementLabel
        # {
        #     char data[SCE_NP_UNIFIED_ENTITLEMENT_LABEL_SIZE];
        #     char padding[3];
        # } SceNpUnifiedEntitlementLabel;
        f.write(dlc[0].encode("ascii")) # 16 bytes
        f.write(b"\x00\x00\x00\x00") # null terminate + 3 padding
        f.write(format_displacement(4 if dlc[1] else 0, 4))



print("Patched file saved.")
ida_kernwin.info("Patching complete")
