import binascii
import shutil
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
max_dlc_count = 2500  # this limit is in the official sdk

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

def main():    
    print("===============================")

    if not idaapi.auto_is_ok():
        ida_kernwin.info("Analysis might not be finished, make sure in the bottom left (below the python button) it says idle.")

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

                    sceSysmoduleLoadModule_patches.append([ref, prev_head])

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
        "sceKernelAddCpumodeEvent",
        "sceKernelAddFileEvent",
        "sceKernelAddGpuExceptionEvent",
        "sceKernelAddHRTimerEvent",
        "sceKernelAddReadEvent",
        "sceKernelAddTimerEvent",
        "sceKernelAddUserEvent",
        "sceKernelAddUserEventEdge",
        "sceKernelAddWriteEvent",
        "sceKernelAioCancelRequest",
        "sceKernelAioCancelRequests",
        "sceKernelAioDeleteRequest",
        "sceKernelAioDeleteRequests",
        "sceKernelAioInitializeImpl",
        "sceKernelAioInitializeParam",
        "sceKernelAioPollRequest",
        "sceKernelAioPollRequests",
        "sceKernelAioSetParam",
        "sceKernelAioSubmitReadCommands",
        "sceKernelAioSubmitReadCommandsMultiple",
        "sceKernelAioSubmitWriteCommands",
        "sceKernelAioSubmitWriteCommandsMultiple",
        "sceKernelAioWaitRequest",
        "sceKernelAioWaitRequests",
        "sceKernelAllocateDirectMemory",
        "sceKernelAllocateDirectMemoryForMiniApp",
        "sceKernelAllocateMainDirectMemory",
        "sceKernelAllocateTraceDirectMemory",
        "sceKernelAvailableDirectMemorySize",
        "sceKernelAvailableFlexibleMemorySize",
        "sceKernelBacktraceSelf",
        "sceKernelBatchMap",
        "sceKernelBatchMap2",
        "sceKernelCancelEventFlag",
        "sceKernelCancelSema",
        "sceKernelCheckedReleaseDirectMemory",
        "sceKernelCheckReachability",
        "sceKernelChmod",
        "sceKernelClearBootReqNotifyCount",
        "sceKernelClearEventFlag",
        "sceKernelClearGameDirectMemory",
        "sceKernelClockGetres",
        "sceKernelClockGettime",
        "sceKernelClose",
        "sceKernelCloseEport",
        "sceKernelCloseEventFlag",
        "sceKernelCloseSema",
        "sceKernelConfiguredFlexibleMemorySize",
        "sceKernelConvertLocaltimeToUtc",
        "sceKernelConvertUtcToLocaltime",
        "sceKernelCreateEport",
        "sceKernelCreateEqueue",
        "sceKernelCreateEventFlag",
        "sceKernelCreateSema",
        "sceKernelDebugAcquireAndUpdateDebugRegister",
        "sceKernelDebugGetAppStatus",
        "sceKernelDebugGetPauseCount",
        "sceKernelDebugGpuPaDebugIsInProgress",
        "sceKernelDebugOutText",
        "sceKernelDebugRaiseException",
        "sceKernelDebugRaiseExceptionOnReleaseMode",
        "sceKernelDebugRaiseExceptionWithContext",
        "sceKernelDebugRaiseExceptionWithInfo",
        "sceKernelDebugReleaseDebugContext",
        "sceKernelDeleteCpumodeEvent",
        "sceKernelDeleteEport",
        "sceKernelDeleteEqueue",
        "sceKernelDeleteEventFlag",
        "sceKernelDeleteFileEvent",
        "sceKernelDeleteGpuExceptionEvent",
        "sceKernelDeleteHRTimerEvent",
        "sceKernelDeleteReadEvent",
        "sceKernelDeleteSema",
        "sceKernelDeleteTimerEvent",
        "sceKernelDeleteUserEvent",
        "sceKernelDeleteWriteEvent",
        "sceKernelDirectMemoryQuery",
        "sceKernelDirectMemoryQueryForId",
        "sceKernelDlsym",
        "sceKernelEnableDmemAliasing",
        "sceKernelEnableDmemAliasing2",
        "sceKernelEnablePthreadObjectCheck",
        "sceKernelError",
        "sceKernelEventLogInit",
        "sceKernelEventLogPread",
        "sceKernelEventLogRead",
        "sceKernelEventLogWrite",
        "sceKernelFchmod",
        "sceKernelFcntl",
        "sceKernelFdatasync",
        "sceKernelFlock",
        "sceKernelFstat",
        "sceKernelFsync",
        "sceKernelFtruncate",
        "sceKernelFutimes",
        "sceKernelGetAllowedSdkVersionOnSystem",
        "sceKernelGetAppInfo",
        "sceKernelGetAslrStatus",
        "sceKernelGetBackupRestoreMode",
        "sceKernelGetBackupRestoreModeOfNextBoot",
        "sceKernelGetBasicProductShape",
        "sceKernelGetBetaUpdateTestForRcmgr",
        "sceKernelGetBioUsageAll",
        "sceKernelGetBootReqNotifyCount",
        "sceKernelGetCallRecord",
        "sceKernelGetCompiledSdkVersion",
        "sceKernelGetCompiledSdkVersionByPath",
        "sceKernelGetCompiledSdkVersionByPid",
        "sceKernelGetCpuFrequency",
        "sceKernelGetCpumode",
        "sceKernelGetCpumodeGame",
        "sceKernelGetCpuTemperature",
        "sceKernelGetCpuUsage",
        "sceKernelGetCpuUsageAll",
        "sceKernelGetCpuUsageProc",
        "sceKernelGetCpuUsageProc2",
        "sceKernelGetCpuUsageThread",
        "sceKernelGetCurrentCpu",
        "sceKernelGetDataTransferMode",
        "sceKernelGetDebugMenuMiniModeForRcmgr",
        "sceKernelGetDebugMenuModeForPsmForRcmgr",
        "sceKernelGetDebugMenuModeForRcmgr",
        "sceKernelGetdents",
        "sceKernelGetDirectMemorySize",
        "sceKernelGetDirectMemoryType",
        "sceKernelGetdirentries",
        "sceKernelGetEventData",
        "sceKernelGetEventError",
        "sceKernelGetEventFflags",
        "sceKernelGetEventFilter",
        "sceKernelGetEventId",
        "sceKernelGetEventUserData",
        "sceKernelGetExecutableModuleHandle",
        "sceKernelGetExtLibcHandle",
        "sceKernelGetFakeFinalizeMenuForRcmgr",
        "sceKernelGetFlagedUpdaterForRcmgr",
        "sceKernelGetForceUpdateModeForRcmgr",
        "sceKernelGetFsSandboxRandomWord",
        "sceKernelGetGPI",
        "sceKernelGetGPO",
        "sceKernelGetHwFeatureInfoForDecid",
        "sceKernelGetIdPs",
        "sceKernelGetIdTableCurrentCount",
        "sceKernelGetIpcPath",
        "sceKernelGetLibkernelTextLocation",
        "sceKernelGetMainSocId",
        "sceKernelGetModuleInfo",
        "sceKernelGetModuleInfoForUnwind",
        "sceKernelGetModuleInfoFromAddr",
        "sceKernelGetModuleInfoInternal",
        "sceKernelGetModuleList",
        "sceKernelGetModuleListInternal",
        "sceKernelGetOpenPsIdForSystem",
        "sceKernelGetPageTableStats",
        "sceKernelGetPagingStatsOfAllObjects",
        "sceKernelGetPagingStatsOfAllThreads",
        "sceKernelGetPhysPageSize",
        "sceKernelGetProcessName",
        "sceKernelGetProcessTime",
        "sceKernelGetProcessTimeCounter",
        "sceKernelGetProcessTimeCounterFrequency",
        "sceKernelGetProcessType",
        "sceKernelGetProcParam",
        "sceKernelGetProductCode",
        "sceKernelGetProductStr",
        "sceKernelGetPrtAperture",
        "sceKernelGetPsmIntdevModeForRcmgr",
        "sceKernelGetPsnAccessTraceLogForRcmgr",
        "sceKernelGetQafExpirationTimeNotafterForRcmgr",
        "sceKernelGetQafExpirationTimeNotbeforeForRcmgr",
        "sceKernelGetQafGenerationForRcmgr",
        "sceKernelGetQafNameForRcmgr",
        "sceKernelGetRenderingMode",
        "sceKernelGetResidentCount",
        "sceKernelGetResidentFmemCount",
        "sceKernelGetSafemode",
        "sceKernelGetSanitizerMallocReplace",
        "sceKernelGetSanitizerMallocReplaceExternal",
        "sceKernelGetSanitizerNewReplace",
        "sceKernelGetSanitizerNewReplaceExternal",
        "sceKernelGetSocPowerConsumption",
        "sceKernelGetSocSensorTemperature",
        "sceKernelGetSpecialIForRcmgr",
        "sceKernelGetSubsysId",
        "sceKernelGetSystemExVersion",
        "sceKernelGetSystemLevelDebuggerModeForRcmgr",
        "sceKernelGetSystemSwBeta",
        "sceKernelGetSystemSwVersion",
        "sceKernelGetThreadName",
        "sceKernelGettimeofday",
        "sceKernelGettimezone",
        "sceKernelGetTraceMemoryStats",
        "sceKernelGetTscFrequency",
        "sceKernelGetUtokenDataExecutionForRcmgr",
        "sceKernelGetUtokenExpirationTimeNotafterForRcmgr",
        "sceKernelGetUtokenExpirationTimeNotbeforeForRcmgr",
        "sceKernelGetUtokenFakeSharefactoryForRcmgr",
        "sceKernelGetUtokenFlagedUpdaterForRcmgr",
        "sceKernelGetUtokenNpEnvSwitchingForRcmgr",
        "sceKernelGetUtokenSaveDataRepairForRcmgr",
        "sceKernelGetUtokenStoreModeForRcmgr",
        "sceKernelGetUtokenUseSoftwagnerForAcmgr",
        "sceKernelGetUtokenUseSoftwagnerForRcmgr",
        "sceKernelGetUtokenWeakenedPortRestrictionForRcmgr",
        "sceKernelGetVrCaptureSize",
        "sceKernelHasNeoMode",
        "sceKernelHwHasOpticalOut",
        "sceKernelHwHasWlanBt",
        "sceKernelIccControlBDPowerState",
        "sceKernelIccControlUSBPowerState",
        "sceKernelIccGetBDPowerState",
        "sceKernelIccGetCountTime",
        "sceKernelIccGetCPMode",
        "sceKernelIccGetCpuInfoBit",
        "sceKernelIccGetErrLog",
        "sceKernelIccGetHwInfo",
        "sceKernelIccGetPowerNumberOfBootShutdown",
        "sceKernelIccGetPowerOperatingTime",
        "sceKernelIccGetPowerUpCause",
        "sceKernelIccGetSysEventLog",
        "sceKernelIccGetThermalAlert",
        "sceKernelIccGetUSBPowerState",
        "sceKernelIccIndicatorBootDone",
        "sceKernelIccIndicatorShutdown",
        "sceKernelIccIndicatorStandby",
        "sceKernelIccIndicatorStandbyBoot",
        "sceKernelIccIndicatorStandbyShutdown",
        "sceKernelIccNotifyBootStatus",
        "sceKernelIccNvsFlush",
        "sceKernelIccReadPowerBootMessage",
        "sceKernelIccSetBuzzer",
        "sceKernelIccSetCPMode",
        "sceKernelIccSetCpuInfoBit",
        "sceKernelIccSetDownloadMode",
        "sceKernelInstallExceptionHandler",
        "sceKernelInternalGetKmemStatistics",
        "sceKernelInternalGetMapStatistics",
        "sceKernelInternalHeapPrintBacktraceWithModuleInfo",
        "sceKernelInternalMapDirectMemory",
        "sceKernelInternalMapNamedDirectMemory",
        "sceKernelInternalMemoryGetAvailableSize",
        "sceKernelInternalMemoryGetModuleSegmentInfo",
        "sceKernelInternalResumeDirectMemoryRelease",
        "sceKernelInternalSuspendDirectMemoryRelease",
        "sceKernelIsAddressSanitizerEnabled",
        "sceKernelIsAllowedToSelectDvdRegion",
        "sceKernelIsAuthenticNeo",
        "sceKernelIsCEX",
        "sceKernelIsDebuggerAttached",
        "sceKernelIsDevKit",
        "sceKernelIsExperimentalBeta",
        "sceKernelIsGenuineCEX",
        "sceKernelIsGenuineDevKit",
        "sceKernelIsGenuineKratosCex",
        "sceKernelIsGenuineN",
        "sceKernelIsGenuineTestKit",
        "sceKernelIsInSandbox",
        "sceKernelIsKratos",
        "sceKernelIsMainOnStanbyMode",
        "sceKernelIsMainOnStandbyMode",
        "sceKernelIsNeoMode",
        "sceKernelIsStack",
        "sceKernelIsTestKit",
        "sceKernelJitCreateAliasOfSharedMemory",
        "sceKernelJitCreateSharedMemory",
        "sceKernelJitGetSharedMemoryInfo",
        "sceKernelJitMapSharedMemory",
        "sceKernelKernelHeapUsage",
        "sceKernelLoadStartModule",
        "sceKernelLoadStartModuleForSysmodule",
        "sceKernelLseek",
        "sceKernelLwfsAllocateBlock",
        "sceKernelLwfsLseek",
        "sceKernelLwfsSetAttribute",
        "sceKernelLwfsTrimBlock",
        "sceKernelLwfsWrite",
        "sceKernelMapDirectMemory",
        "sceKernelMapDirectMemory2",
        "sceKernelMapFlexibleMemory",
        "sceKernelMapNamedDirectMemory",
        "sceKernelMapNamedFlexibleMemory",
        "sceKernelMapNamedSystemFlexibleMemory",
        "sceKernelMapSanitizerShadowMemory",
        "sceKernelMapTraceMemory",
        "sceKernelMemoryPoolBatch",
        "sceKernelMemoryPoolCommit",
        "sceKernelMemoryPoolDecommit",
        "sceKernelMemoryPoolExpand",
        "sceKernelMemoryPoolGetBlockStats",
        "sceKernelMemoryPoolMove",
        "sceKernelMemoryPoolReserve",
        "sceKernelMkdir",
        "sceKernelMlock",
        "sceKernelMlockall",
        "sceKernelMmap",
        "sceKernelMprotect",
        "sceKernelMsync",
        "sceKernelMtypeprotect",
        "sceKernelMunlock",
        "sceKernelMunlockall",
        "sceKernelMunmap",
        "sceKernelNanosleep",
        "sceKernelNormalizePath",
        "sceKernelNotifyAppStateChanged",
        "sceKernelNotifySystemSuspendResumeProgress",
        "sceKernelNotifySystemSuspendStart",
        "sceKernelOpen",
        "sceKernelOpenEport",
        "sceKernelOpenEventFlag",
        "sceKernelOpenSema",
        "sceKernelPollEventFlag",
        "sceKernelPollSema",
        "sceKernelPread",
        "sceKernelPreadv",
        "sceKernelPrintBacktraceWithModuleInfo",
        "sceKernelProtectDirectMemory",
        "sceKernelProtectDirectMemoryForPID",
        "sceKernelPwrite",
        "sceKernelPwritev",
        "sceKernelQueryMemoryProtection",
        "sceKernelQueryTraceMemory",
        "sceKernelRaiseException",
        "sceKernelRandomizedPath",
        "sceKernelRdup",
        "sceKernelRead",
        "sceKernelReadTsc",
        "sceKernelReadv",
        "sceKernelReboot",
        "sceKernelReleaseDirectMemory",
        "sceKernelReleaseFlexibleMemory",
        "sceKernelReleaseTraceDirectMemory",
        "sceKernelRemoveExceptionHandler",
        "sceKernelRename",
        "sceKernelReportUnpatchedFunctionCall",
        "sceKernelReserve2mbPage",
        "sceKernelReserveSystemDirectMemory",
        "sceKernelReserveVirtualRange",
        "sceKernelResumeDirectMemoryRelease",
        "sceKernelRmdir",
        "sceKernelRtldControl",
        "sceKernelSandboxPath",
        "sceKernelSendNotificationRequest",
        "sceKernelSetAppInfo",
        "sceKernelSetBackupRestoreMode",
        "sceKernelSetBaseModeClock",
        "sceKernelSetBesteffort",
        "sceKernelSetBootReqNotify",
        "sceKernelSetCallRecord",
        "sceKernelSetCompressionAttribute",
        "sceKernelSetCpumodeGame",
        "sceKernelSetDataTransferMode",
        "sceKernelSetEventFlag",
        "sceKernelSetFsstParam",
        "sceKernelSetGameDirectMemoryLimit",
        "sceKernelSetGPI",
        "sceKernelSetGPO",
        "sceKernelSetGpuCu",
        "sceKernelSetMemoryPstate",
        "sceKernelSetNeoModeClock",
        "sceKernelSetPhysFmemLimit",
        "sceKernelSetProcessName",
        "sceKernelSetProcessProperty",
        "sceKernelSetProcessPropertyString",
        "sceKernelSetPrtAperture",
        "sceKernelSetSafemode",
        "sceKernelSettimeofday",
        "sceKernelSetTimezoneInfo",
        "sceKernelSetVirtualRangeName",
        "sceKernelSetVmContainer",
        "sceKernelSignalSema",
        "sceKernelSleep",
        "sceKernelSlvNotifyError",
        "sceKernelStat",
        "sceKernelStopUnloadModule",
        "sceKernelSuspendDirectMemoryRelease",
        "sceKernelSwitchToBaseMode",
        "sceKernelSwitchToNeoMode",
        "sceKernelSync",
        "sceKernelTerminateSysCore",
        "sceKernelTitleWorkaroundIsEnabled",
        "sceKernelTitleWorkdaroundIsEnabled",
        "sceKernelTraceMemoryTypeProtect",
        "sceKernelTriggerEport",
        "sceKernelTriggerUserEvent",
        "sceKernelTruncate",
        "sceKernelUnlink",
        "sceKernelUsleep",
        "sceKernelUtimes",
        "sceKernelUuidCreate",
        "sceKernelVirtualQuery",
        "sceKernelVirtualQueryAll",
        "sceKernelWaitEqueue",
        "sceKernelWaitEventFlag",
        "sceKernelWaitSema",
        "sceKernelWrite",
        "sceKernelWriteSdkEventLog",
        "sceKernelWritev",
        "sceKernelYieldCpumode",
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

    extraDataText = f.txtLeft.value.replace(" ", "").replace(
        "\n", "").replace("\r", "").replace("\t", "")
    noExtraDataText = f.txtRight.value.replace(" ", "").replace(
        "\n", "").replace("\r", "").replace("\t", "")


    if len(extraDataText + noExtraDataText) == 0:
        raise Exception("No content ids entered")

    if len(extraDataText) % 16 != 0 or len(noExtraDataText) % 16 != 0:
        raise Exception("Invalid input length, each content id should be 16 characters long")

    dlc_list = []

    for i in range(0, len(extraDataText), 16):
        dlc_list.append((extraDataText[i:i+16], True))

    for i in range(0, len(noExtraDataText), 16):
        dlc_list.append((noExtraDataText[i:i+16], False))

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

    shutil.copy(input_file, patched_elf_output_path)

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
            ret = f.read(1)
            if ret not in [b'\xE8', b'\xE9']:
                raise Exception(
                    f"Expected jmp/call at {get_hex(patch[0])}, got opcode {ret.hex()}")

            # dont overwrite opcode (support jmp and call)
            # since we read 1 byte we are after the opcode
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
            f.write(dlc[0].encode("ascii"))  # 16 bytes
            f.write(b"\x00\x00\x00\x00")  # null terminate + 3 padding
            f.write(format_displacement(4 if dlc[1] else 0, 4))


    finish_text = "Patching complete."
    
    dlcs_with_extra_data_list = [dlc[0] for dlc in dlc_list if dlc[1]]
    if len(dlcs_with_extra_data_list) > 0:
        finish_text += "\nCreate folders and copy contents for dlcs with extra data in the order you entered the content ids. eg:\n"
        for i in range(len(dlc_list)):
            if i > 2:
                finish_text += f"... ({len(dlc_list) - i} more)"
                break
            finish_text += f"{dlc_list[i][0]}/Image0/* -> cusaXXXX-patch/Image0/dlc0{i}/\n"
    else:
        finish_text += "\nNo extra data dlcs used, no need to create folders."
    print(finish_text)
    ida_kernwin.info(finish_text)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        ida_kernwin.warning(f"Error: {e}\nExiting...")