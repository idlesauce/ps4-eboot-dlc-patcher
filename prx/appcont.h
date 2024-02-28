#pragma once

#define SCE_KERNEL_O_WRONLY 0x0001
#define SCE_KERNEL_O_CREAT 0x0200
#define SCE_KERNEL_O_APPEND 0x0008

// #define S_IRWXU 0000700 // RWX mask for owner
// #define S_IRUSR 0000400 // R for owner
// #define S_IWUSR 0000200 // W for owner
// #define S_IXUSR 0000100 // X for owner

// #define S_IRWXG 0000070 // RWX mask for group
// #define S_IRGRP 0000040 // R for group
// #define S_IWGRP 0000020 // W for group
// #define S_IXGRP 0000010 // X for group

// #define S_IRWXO 0000007 // RWX mask for other
// #define S_IROTH 0000004 // R for other
// #define S_IWOTH 0000002 // W for other
// #define S_IXOTH 0000001 // X for other

#define SCE_KERNEL_S_IRUSR (S_IRUSR | S_IRGRP | S_IROTH | S_IXUSR | \
							S_IXGRP | S_IXOTH)
#define SCE_KERNEL_S_IWUSR (S_IWUSR | S_IWGRP | S_IWOTH | S_IXUSR | \
							S_IXGRP | S_IXOTH)

#define SCE_KERNEL_S_IRWU (SCE_KERNEL_S_IRUSR | SCE_KERNEL_S_IWUSR)

#define CLOCK_MONOTONIC 4
#define CLOCK_REALTIME 0
#define SCE_KERNEL_CLOCK_REALTIME CLOCK_REALTIME
#define SCE_KERNEL_CLOCK_MONOTONIC CLOCK_MONOTONIC

// struct timespec {
// 	time_t	tv_sec;		// seconds
// 	long	tv_nsec;	// and nanoseconds
// };

typedef struct timespec SceKernelTimespec;

typedef uint32_t SceNpServiceLabel;

#define SCE_NP_UNIFIED_ENTITLEMENT_LABEL_SIZE (17)
typedef struct SceNpUnifiedEntitlementLabel
{
	char data[SCE_NP_UNIFIED_ENTITLEMENT_LABEL_SIZE];
	char padding[3];
} SceNpUnifiedEntitlementLabel;

typedef struct
{
	SceNpUnifiedEntitlementLabel entitlementLabel;
	uint32_t status; // SceAppContentAddcontDownloadStatus
} SceAppContentAddcontInfo;

#define SCE_APP_CONTENT_ERROR_NOT_INITIALIZED -2133262335 // 0x80D90001

#define SCE_APP_CONTENT_ERROR_PARAMETER -2133262334 // 0x80D90002

// Contents already mounted.
#define SCE_APP_CONTENT_ERROR_BUSY -2133262333 // 0x80D90003

// Contents not mounted.
#define SCE_APP_CONTENT_ERROR_NOT_MOUNTED -2133262332 // 0x80D90004

// Contents not found.
#define SCE_APP_CONTENT_ERROR_NOT_FOUND -2133262331 // 0x80D90005

// Reached mount max.
#define SCE_APP_CONTENT_ERROR_MOUNT_FULL -2133262330 // 0x80D90006

// Contents no entitlement.
#define SCE_APP_CONTENT_ERROR_DRM_NO_ENTITLEMENT -2133262329 // 0x80D90007

// Not enough space in HDD.
#define SCE_APP_CONTENT_ERROR_NO_SPACE -2133262328 // 0x80D90008

// Not supported.
#define SCE_APP_CONTENT_ERROR_NOT_SUPPORTED -2133262327 // 0x80D90009

// Internal error.
#define SCE_APP_CONTENT_ERROR_INTERNAL -2133262326 // 0x80D9000A

// Reached the max of download entry.
#define SCE_APP_CONTENT_ERROR_DOWNLOAD_ENTRY_FULL -2133262325 // 0x80D9000B

// Invalid pkg.
#define SCE_APP_CONTENT_ERROR_INVALID_PKG -2133262324 // 0x80D9000C

// Other application pkg.
#define SCE_APP_CONTENT_ERROR_OTHER_APPLICATION_PKG -2133262323 // 0x80D9000D

// Reached create data max.
#define SCE_APP_CONTENT_ERROR_CREATE_FULL -2133262322 // 0x80D9000E

// Contents already mounted by other application.
#define SCE_APP_CONTENT_ERROR_MOUNT_OTHER_APP -2133262321 // 0x80D9000F

// Out of memory.
#define SCE_APP_CONTENT_ERROR_OF_MEMORY -2133262320 // 0x80D90010

// Shrank additional content.
#define SCE_APP_CONTENT_ERROR_ADDCONT_SHRANK -2133262319 // 0x80D90011

// The additional content is not in download queue.
#define SCE_APP_CONTENT_ERROR_ADDCONT_NO_IN_QUEUE -2133262318 // 0x80D90012

// Network error.
#define SCE_APP_CONTENT_ERROR_NETWORK -2133262317 // 0x80D90013

// Called in the signed-out state.
#define SCE_APP_CONTENT_ERROR_SIGNED_OUT -2133262316 // 0x80D90014

// Unsupported compression format.
#define SCE_APP_CONTENT_ERROR_UNSUPPORTED_COMPRESSION_FORMAT -2133262315 // 0x80D90015

// The additional content is broken.k
#define SCE_APP_CONTENT_ERROR_BROKEN -2133262314 // 0x80D90016

// The total size of additional content is over limitation.
#define SCE_APP_CONTENT_ERROR_ADDCONT_NO_SPACE -2133262313 // 0x80D90017

// The total file number of additional content is over limitation.
#define SCE_APP_CONTENT_ERROR_ADDCONT_ENFILE -2133262312 // 0x80D90018

// type of application media
typedef uint32_t SceAppContentMediaType;

// type of boot attribute
typedef uint32_t SceAppContentBootAttribute;

// type of application parameter id
typedef uint32_t SceAppContentAppParamId;

// type of download status
typedef uint32_t SceAppContentAddcontDownloadStatus;

// type of temporary data option
typedef uint32_t SceAppContentTemporaryDataOption;

// application parameter id

// user defined parameter 1
#define SCE_APP_CONTENT_APPPARAM_ID_USER_DEFINED_PARAM_1 (1)
// user defined parameter 2
#define SCE_APP_CONTENT_APPPARAM_ID_USER_DEFINED_PARAM_2 (2)
// user defined parameter 3
#define SCE_APP_CONTENT_APPPARAM_ID_USER_DEFINED_PARAM_3 (3)
// user defined parameter 4
#define SCE_APP_CONTENT_APPPARAM_ID_USER_DEFINED_PARAM_4 (4)

// parameter size

// mount point max size
#define SCE_APP_CONTENT_MOUNTPOINT_DATA_MAXSIZE (16)
// number of simultaneous mounts of additional content
#define SCE_APP_CONTENT_ADDCONT_MOUNT_MAXNUM (64)
// Add Content Info List Max size
#define SCE_APP_CONTENT_INFO_LIST_MAX_SIZE (2500)

// value of package type
#define SCE_NP_ENTITLEMENT_ACCESS_PACKAGE_TYPE_NONE (0)
#define SCE_NP_ENTITLEMENT_ACCESS_PACKAGE_TYPE_PSGD (1)
#define SCE_NP_ENTITLEMENT_ACCESS_PACKAGE_TYPE_PSAC (2)
#define SCE_NP_ENTITLEMENT_ACCESS_PACKAGE_TYPE_PSAL (3)
#define SCE_NP_ENTITLEMENT_ACCESS_PACKAGE_TYPE_PSCONS (4)
#define SCE_NP_ENTITLEMENT_ACCESS_PACKAGE_TYPE_PSVC (5)
#define SCE_NP_ENTITLEMENT_ACCESS_PACKAGE_TYPE_PSSUBS (6)

// temporary data option

// none
#define SCE_APP_CONTENT_TEMPORARY_DATA_OPTION_NONE (0)
// with format
#define SCE_APP_CONTENT_TEMPORARY_DATA_OPTION_FORMAT (1 << 0)

typedef uint32_t SceNpEntitlementAccessPackageType;
typedef uint32_t SceNpEntitlementAccessDownloadStatus;

typedef struct SceNpEntitlementAccessAddcontEntitlementInfo
{
	SceNpUnifiedEntitlementLabel entitlementLabel;
	SceNpEntitlementAccessPackageType packageType;
	SceNpEntitlementAccessDownloadStatus downloadStatus;
} SceNpEntitlementAccessAddcontEntitlementInfo;

// library initialize parameter structure
typedef struct SceAppContentInitParam
{
	char reserved[32];
} SceAppContentInitParam;

// boot parameter structure
typedef struct SceAppContentBootParam
{
	char reserved1[4];
	SceAppContentBootAttribute attr;
	char reserved2[32];
} SceAppContentBootParam;

// mount point structure
typedef struct SceAppContentMountPoint
{
	char data[SCE_APP_CONTENT_MOUNTPOINT_DATA_MAXSIZE];
} SceAppContentMountPoint;

// additional contents download progress structure
typedef struct SceAppContentAddcontDownloadProgress
{
	uint64_t dataSize;
	uint64_t downloadedSize;
} SceAppContentAddcontDownloadProgress;

#define SCE_NP_ENTITLEMENT_ACCESS_ENTITLEMENT_KEY_SIZE (16)
typedef struct SceNpEntitlementAccessEntitlementKey
{
	char data[SCE_NP_ENTITLEMENT_ACCESS_ENTITLEMENT_KEY_SIZE];
} SceNpEntitlementAccessEntitlementKey;

#if !defined(SCE_OK)
#define SCE_OK 0
#endif /* !defined(SCE_OK) */

typedef uint32_t SceAppContentPftFlag;
// No Play First Trial application
#define SCE_APP_CONTENT_PFT_FLAG_OFF (0)
// Play First Trial application
#define SCE_APP_CONTENT_PFT_FLAG_ON (1)

int append_to_log(const char *str);

static uint64_t getNanoTime();
static uint64_t timespec_to_nano(const SceKernelTimespec *timespec);
void intToStr(int num, char *str);
void ptrToHexStr(void *ptr, char *str);

int32_t sceAppContentInitialize(
	SceAppContentInitParam *initParam,
	SceAppContentBootParam *bootParam);
int32_t dlcldr_sceAppContentAppParamGetInt(
	SceAppContentAppParamId paramId,
	int32_t *value);
// int sceAppContentAppParamGetInt();
// int32_t sceAppContentGetAddcontInfoList(
// 	SceNpServiceLabel serviceLabel,
// 	SceAppContentAddcontInfo *list,
// 	uint32_t listNum,
// 	uint32_t *hitNum);
// int32_t sceAppContentGetAddcontInfo(
// 	SceNpServiceLabel serviceLabel,
// 	const SceNpUnifiedEntitlementLabel *entitlementLabel,
// 	SceAppContentAddcontInfo *info);
// int32_t sceAppContentAddcontDelete(
// 	SceNpServiceLabel serviceLabel,
// 	const SceNpUnifiedEntitlementLabel *entitlementLabel);
// int32_t sceAppContentAddcontMount(
// 	SceNpServiceLabel serviceLabel,
// 	const SceNpUnifiedEntitlementLabel *entitlementLabel,
// 	SceAppContentMountPoint *mountPoint);
// int32_t sceAppContentAddcontUnmount(
// 	const SceAppContentMountPoint *mountPoint);
// int32_t sceAppContentGetEntitlementKey();

// int32_t sceAppContentGetPftFlag(
// 	SceAppContentPftFlag *pftFlag
// );

// int32_t sceAppContentAppParamGetInt(
// 	SceAppContentAppParamId paramId,
// 	int32_t *value);
// int32_t sceAppContentAddcontEnqueueDownload(
// 	SceNpServiceLabel serviceLabel,
// 	const SceNpUnifiedEntitlementLabel *entitlementLabel);
// int32_t sceAppContentTemporaryDataMount2(
// 	SceAppContentTemporaryDataOption option,
// 	SceAppContentMountPoint *mountPoint);
// int32_t sceAppContentTemporaryDataUnmount(
// 	const SceAppContentMountPoint *mountPoint);
// int32_t sceAppContentTemporaryDataFormat(
// 	const SceAppContentMountPoint *mountPoint);
// int32_t sceAppContentTemporaryDataGetAvailableSpaceKb(
// 	const SceAppContentMountPoint *mountPoint,
// 	size_t *availableSpaceKb);
// int32_t sceAppContentDownloadDataFormat(
// 	const SceAppContentMountPoint *mountPoint);
// int32_t sceAppContentDownloadDataGetAvailableSpaceKb(
// 	const SceAppContentMountPoint *mountPoint,
// 	size_t *availableSpaceKb);
// int32_t sceAppContentGetAddcontDownloadProgress(
// 	SceNpServiceLabel serviceLabel,
// 	const SceNpUnifiedEntitlementLabel *entitlementLabel,
// 	SceAppContentAddcontDownloadProgress *progress);
// int32_t sceAppContentAddcontEnqueueDownloadByEntitlemetId();
// int32_t sceAppContentAddcontEnqueueDownloadSp();
// int32_t sceAppContentAddcontMountByEntitlemetId();
// int32_t sceAppContentAddcontShrink();
// int32_t sceAppContentAppParamGetString();
// int32_t sceAppContentDownload0Expand();
// int32_t sceAppContentDownload0Shrink();
// int32_t sceAppContentDownload1Expand();
// int32_t sceAppContentDownload1Shrink();
// int32_t sceAppContentGetAddcontInfoByEntitlementId();
// int32_t sceAppContentGetAddcontInfoListByIroTag();
// int32_t sceAppContentGetDownloadedStoreCountry();
// int32_t sceAppContentGetRegion();
// int32_t sceAppContentRequestPatchInstall();
// int32_t sceAppContentSmallSharedDataFormat();
// int32_t sceAppContentSmallSharedDataGetAvailableSpaceKb();
// int32_t sceAppContentSmallSharedDataMount();
// int32_t sceAppContentSmallSharedDataUnmount();

// int32_t sceNpEntitlementAccessGetAddcontEntitlementInfoList(
// 	SceNpServiceLabel serviceLabel,
// 	SceNpEntitlementAccessAddcontEntitlementInfo *list,
// 	uint32_t listNum,
// 	uint32_t *hitNum);

// int32_t sceNpEntitlementAccessGetAddcontEntitlementInfo(
// 	SceNpServiceLabel serviceLabel,
// 	const SceNpUnifiedEntitlementLabel *entitlementLabel,
// 	SceNpEntitlementAccessAddcontEntitlementInfo *info);

// int32_t sceNpEntitlementAccessGetEntitlementKey(
// 	SceNpServiceLabel serviceLabel,
// 	const SceNpUnifiedEntitlementLabel *entitlementLabel,
// 	SceNpEntitlementAccessEntitlementKey *key);