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

# some games call sceSysmoduleLoadModule multiple times for libSceAppContent (cusa05332)
sceSysmoduleLoadModule_patches = []

found = False

for ref in refs:
    prev_head = idc.prev_head(ref)
    count = 0

    while prev_head != idaapi.BADADDR and count < 10:
        mnem = idc.print_insn_mnem(prev_head)
        if mnem == 'mov' and idc.print_operand(prev_head, 0) == 'edi':
            value = idc.get_operand_value(prev_head, 1)
            # 0xB4 is libSceAppContent
            if value == 0xB4:
                # if t_sceSysmoduleLoadModule_patches already has a reference to this address, skip it
                # sometimes the next call to sceSysmoduleLoadModule is within 10 instructions
                # so it would recognize the others parameter
                if prev_head in [x[1] for x in sceSysmoduleLoadModule_patches]:
                    # print(
                    #     f"Skipping reference to sceSysmoduleLoadModule for libSceAppContent at {get_hex(ref)}")
                    break

                print(
                    f"sceSysmoduleLoadModule for libSceAppContent at {get_hex(ref)} | mov edi addr: {get_hex(prev_head)}")
                
                sceSysmoduleLoadModule_patches.append([ref,prev_head])
                
        prev_head = idc.prev_head(prev_head)
        count += 1

if len(sceSysmoduleLoadModule_patches) == 0:
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

    for patch in sceSysmoduleLoadModule_patches:
        f.seek(get_real_address(patch[0]))
        f.write(b"\xE8")
        f.write(format_displacement(
            t_realaddr - get_real_address(patch[0]) - 5, 4))
        print(
            f"Patched call to sceSysmoduleLoadModule ida: {get_hex(patch[0])} | real: {get_hex(get_real_address(patch[0]))}")

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
