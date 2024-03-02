.intel_syntax noprefix
.section ".text"

.extern sceAppContentAppParamGetInt
.extern sceAppContentAddcontEnqueueDownload
.extern sceAppContentTemporaryDataMount2
.extern sceAppContentTemporaryDataUnmount
.extern sceAppContentTemporaryDataFormat
.extern sceAppContentTemporaryDataGetAvailableSpaceKb
.extern sceAppContentDownloadDataFormat
.extern sceAppContentDownloadDataGetAvailableSpaceKb
.extern sceAppContentGetAddcontDownloadProgress
.extern sceAppContentAddcontEnqueueDownloadByEntitlemetId
.extern sceAppContentAddcontMountByEntitlemetId
.extern sceAppContentAddcontShrink
.extern sceAppContentAppParamGetString
.extern sceAppContentDownload0Expand
.extern sceAppContentDownload0Shrink
.extern sceAppContentDownload1Expand
.extern sceAppContentGetAddcontInfoByEntitlementId
.extern sceAppContentGetAddcontInfoListByIroTag
.extern sceAppContentGetDownloadedStoreCountry
.extern sceAppContentGetRegion
.extern sceAppContentRequestPatchInstall
.extern sceAppContentSmallSharedDataFormat
.extern sceAppContentSmallSharedDataGetAvailableSpaceKb
.extern sceAppContentSmallSharedDataMount
.extern sceAppContentSmallSharedDataUnmount

# these three are missing from the open orbis stubs
# .extern sceAppContentAddcontEnqueueDownloadSp
# .extern sceAppContentDownload1Shrink
# .extern sceAppContentGetPftFlag

.globl dlcldr_sceAppContentAppParamGetInt
.globl dlcldr_sceAppContentAddcontEnqueueDownload
.globl dlcldr_sceAppContentTemporaryDataMount2
.globl dlcldr_sceAppContentTemporaryDataUnmount
.globl dlcldr_sceAppContentTemporaryDataFormat
.globl dlcldr_sceAppContentTemporaryDataGetAvailableSpaceKb
.globl dlcldr_sceAppContentDownloadDataFormat
.globl dlcldr_sceAppContentDownloadDataGetAvailableSpaceKb
.globl dlcldr_sceAppContentGetAddcontDownloadProgress
.globl dlcldr_sceAppContentAddcontEnqueueDownloadByEntitlemetId
.globl dlcldr_sceAppContentAddcontEnqueueDownloadSp
.globl dlcldr_sceAppContentAddcontMountByEntitlemetId
.globl dlcldr_sceAppContentAddcontShrink
.globl dlcldr_sceAppContentAppParamGetString
.globl dlcldr_sceAppContentDownload0Expand
.globl dlcldr_sceAppContentDownload0Shrink
.globl dlcldr_sceAppContentDownload1Expand
.globl dlcldr_sceAppContentDownload1Shrink
.globl dlcldr_sceAppContentGetAddcontInfoByEntitlementId
.globl dlcldr_sceAppContentGetAddcontInfoListByIroTag
.globl dlcldr_sceAppContentGetDownloadedStoreCountry
.globl dlcldr_sceAppContentGetRegion
.globl dlcldr_sceAppContentRequestPatchInstall
.globl dlcldr_sceAppContentSmallSharedDataFormat
.globl dlcldr_sceAppContentSmallSharedDataGetAvailableSpaceKb
.globl dlcldr_sceAppContentSmallSharedDataMount
.globl dlcldr_sceAppContentSmallSharedDataUnmount
# .globl dlcldr_sceAppContentGetPftFlag


dlcldr_sceAppContentAppParamGetInt:
    jmp sceAppContentAppParamGetInt

dlcldr_sceAppContentAddcontEnqueueDownload:
    jmp sceAppContentAddcontEnqueueDownload

dlcldr_sceAppContentTemporaryDataMount2:
    jmp sceAppContentTemporaryDataMount2

dlcldr_sceAppContentTemporaryDataUnmount:
    jmp sceAppContentTemporaryDataUnmount

dlcldr_sceAppContentTemporaryDataFormat:
    jmp sceAppContentTemporaryDataFormat

dlcldr_sceAppContentTemporaryDataGetAvailableSpaceKb:
    jmp sceAppContentTemporaryDataGetAvailableSpaceKb

dlcldr_sceAppContentDownloadDataFormat:
    jmp sceAppContentDownloadDataFormat

dlcldr_sceAppContentDownloadDataGetAvailableSpaceKb:
    jmp sceAppContentDownloadDataGetAvailableSpaceKb

dlcldr_sceAppContentGetAddcontDownloadProgress:
    jmp sceAppContentGetAddcontDownloadProgress

dlcldr_sceAppContentAddcontEnqueueDownloadByEntitlemetId:
    jmp sceAppContentAddcontEnqueueDownloadByEntitlemetId


dlcldr_sceAppContentAddcontMountByEntitlemetId:
    jmp sceAppContentAddcontMountByEntitlemetId

dlcldr_sceAppContentAddcontShrink:
    jmp sceAppContentAddcontShrink

dlcldr_sceAppContentAppParamGetString:
    jmp sceAppContentAppParamGetString

dlcldr_sceAppContentDownload0Expand:
    jmp sceAppContentDownload0Expand

dlcldr_sceAppContentDownload0Shrink:
    jmp sceAppContentDownload0Shrink

dlcldr_sceAppContentDownload1Expand:
    jmp sceAppContentDownload1Expand


dlcldr_sceAppContentGetAddcontInfoByEntitlementId:
    jmp sceAppContentGetAddcontInfoByEntitlementId

dlcldr_sceAppContentGetAddcontInfoListByIroTag:
    jmp sceAppContentGetAddcontInfoListByIroTag

dlcldr_sceAppContentGetDownloadedStoreCountry:
    jmp sceAppContentGetDownloadedStoreCountry



dlcldr_sceAppContentGetRegion:
    jmp sceAppContentGetRegion

dlcldr_sceAppContentRequestPatchInstall:
    jmp sceAppContentRequestPatchInstall

dlcldr_sceAppContentSmallSharedDataFormat:
    jmp sceAppContentSmallSharedDataFormat

dlcldr_sceAppContentSmallSharedDataGetAvailableSpaceKb:
    jmp sceAppContentSmallSharedDataGetAvailableSpaceKb

dlcldr_sceAppContentSmallSharedDataMount:
    jmp sceAppContentSmallSharedDataMount

dlcldr_sceAppContentSmallSharedDataUnmount:
    jmp sceAppContentSmallSharedDataUnmount


# these three are missing from the open orbis stubs
dlcldr_sceAppContentDownload1Shrink:
    xor eax, eax
    ret

dlcldr_sceAppContentAddcontEnqueueDownloadSp:
    xor eax, eax
    ret

# ended up handling this better in c
# dlcldr_sceAppContentGetPftFlag:
#     xor eax, eax
#     ret
