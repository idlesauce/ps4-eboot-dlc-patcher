
#define LIBRARY_IMPL (1)
#include <stdio.h>
#include <orbis/libkernel.h>
#include <orbis/Sysmodule.h>
#include "appcont.h"
#include <string.h>

// from open orbis crtlib.c
extern char __text_start;
void (*__init_array_start[])(void);
void (*__init_array_end[])(void);

// sce_module_param
__asm__(
	".intel_syntax noprefix \n"
	".align 0x8 \n"
	".section \".data.sce_module_param\" \n"
	"_sceProcessParam: \n"
	// size
	"	.quad 	0x18 \n"
	// magic
	"	.quad   0x13C13F4BF \n"
	// SDK version
	"	.quad 	0x1000051 \n"
	".att_syntax prefix \n");

// data globals
__asm__(
	".intel_syntax noprefix \n"
	".align 0x8 \n"
	".data \n"
	"__dso_handle: \n"
	"	.quad 	0 \n"
	"_sceLibc: \n"
	"	.quad 	0 \n"
	".att_syntax prefix \n");

// this does not get called ever?
int module_start(int64_t args, const void *argp)
{
	for (void (**i)(void) = __init_array_start; i != __init_array_end; i++)
	{
		i[0]();
	}

	return 0;
}

int module_stop(int64_t args, const void *argp)
{
	return 0;
}

#define SCE_SYSMODULE_APP_CONTENT 0x00b4

// snprintf crashes if used in init...?
int32_t _init()
{
	// delete previous log
	// sceKernelUnlink("/data/dlcldr.log");

	// append_to_log("init called\n");

	int res = sceSysmoduleLoadModule(SCE_SYSMODULE_APP_CONTENT);

	if (res != SCE_OK)
	{
		// append_to_log("Failed to load libSceAppContent\n");
		return -1;
	}

	// append_to_log("libSceAppContent loaded\n");

	SceAppContentInitParam initParam;
	SceAppContentBootParam bootParam;
	memset(&initParam, 0, sizeof(SceAppContentInitParam));
	memset(&bootParam, 0, sizeof(SceAppContentBootParam));
	res = sceAppContentInitialize(&initParam, &bootParam);

	if (res < 0)
	{
		// append_to_log("sceAppContentInitialize call failed. res: ");
		// char res_str[10];
		// intToStr(res, res_str);
		// append_to_log(res_str);
		// append_to_log("\n");
		return -1;
	}

	// append_to_log("sceAppContentInitialize call success\n");

	// int32_t getint_test_value = 0;

	// int32_t getint_test = dlcldr_sceAppContentAppParamGetInt(SCE_APP_CONTENT_APPPARAM_ID_USER_DEFINED_PARAM_4, &getint_test_value);

	// if (getint_test < 0)
	// {
	// 	append_to_log("dlcldr_sceAppContentAppParamGetInt call failed. res: ");
	// 	char res_str[10];
	// 	intToStr(getint_test, res_str);
	// 	append_to_log(res_str);
	// 	append_to_log("\n");
	// 	return -1;
	// }

	// append_to_log("dlcldr_sceAppContentAppParamGetInt call success (value: ");
	// char getint_test_value_str[10];
	// intToStr(getint_test_value, getint_test_value_str);
	// append_to_log(getint_test_value_str);
	// append_to_log(")\n");

	return 0;
}

int32_t _fini()
{
	return 0;
}

void intToStr(int num, char *str)
{
	int i = 0;
	int isNegative = 0;

	// If the number is negative, make it positive and set the flag
	if (num < 0)
	{
		isNegative = 1;
		num = -num;
	}

	// Handle 0 explicitly, otherwise empty string is printed for 0
	if (num == 0)
	{
		str[i++] = '0';
		str[i] = '\0';
		return;
	}

	// Process individual digits
	while (num != 0)
	{
		int digit = num % 10;
		str[i++] = digit + 0x30; // Convert digit to its ASCII character
		num = num / 10;
	}

	// If the number was negative, append '-'
	if (isNegative)
		str[i++] = '-';

	str[i] = '\0'; // Append string terminator

	// Reverse the string
	int start = 0;
	int end = i - 1;
	while (start < end)
	{
		char temp = str[start];
		str[start] = str[end];
		str[end] = temp;
		start++;
		end--;
	}
}

void ptrToHexStr(void *ptr, char *str)
{
	const char *hexDigits = "0123456789ABCDEF";
	uintptr_t val = (uintptr_t)ptr;

	int numHexDigits = sizeof(val) * 2;

	for (int i = numHexDigits - 1; i >= 0; --i)
	{
		str[i] = hexDigits[val & 0xF];
		val >>= 4;
	}

	str[numHexDigits] = '\0';
}

int append_to_log(const char *str)
{
	int fd = sceKernelOpen("/data/dlcldr.log", SCE_KERNEL_O_WRONLY | SCE_KERNEL_O_CREAT | SCE_KERNEL_O_APPEND, SCE_KERNEL_S_IRWU);

	if (fd <= 0)
	{
		printf("Cannot open file \n");
		return -1;
	}

	size_t len = strlen(str);
	sceKernelWrite(fd, str, len);

	sceKernelClose(fd);

	return 0;
}

int32_t dlcldr_sceAppContentInitialize(
	SceAppContentInitParam *initParam,
	SceAppContentBootParam *bootParam)
{
	// append_to_log("dlcldr_sceAppContentInitialize called\n");
	return 0;
}

int32_t addcont_count = -1;

SceAppContentAddcontInfo addcontInfo[SCE_APP_CONTENT_INFO_LIST_MAX_SIZE] = {
	{{"PREO02AMZN00R0VO"}, 0}};

int32_t dlcldr_sceAppContentGetAddcontInfoList(
	SceNpServiceLabel serviceLabel,
	SceAppContentAddcontInfo *list,
	uint32_t listNum,
	uint32_t *hitNum)
{
	// append_to_log("dlcldr_sceAppContentGetAddcontInfoList called\n");

	if (listNum == 0)
	{
		*hitNum = addcont_count;
		return 0;
	}

	if (list == NULL)
	{
		return 0;
	}

	for (int i = 0; i < listNum; i++)
	{
		if (i < addcont_count)
		{
			strncpy(list[i].entitlementLabel.data, addcontInfo[i].entitlementLabel.data, SCE_NP_UNIFIED_ENTITLEMENT_LABEL_SIZE);
			list[i].status = addcontInfo[i].status;
		}
	}

	if (hitNum != NULL)
	{
		*hitNum = listNum < addcont_count ? listNum : addcont_count;
	}

	return 0;
}

int32_t dlcldr_sceAppContentGetAddcontInfo(
	SceNpServiceLabel serviceLabel,
	const SceNpUnifiedEntitlementLabel *entitlementLabel,
	SceAppContentAddcontInfo *info)
{
	for (int i = 0; i < addcont_count; i++)
	{
		if (strcmp(entitlementLabel->data, addcontInfo[i].entitlementLabel.data) == 0)
		{
			// char log_buf[250];
			// snprintf(log_buf, 250, "Entitlement label match: %s\n", entitlementLabel->data);
			// append_to_log(log_buf);
			strncpy(info->entitlementLabel.data, addcontInfo[i].entitlementLabel.data, SCE_NP_UNIFIED_ENTITLEMENT_LABEL_SIZE);
			info->status = 4;
			return 0;
		}
	}

	// char log_buf[250];
	// snprintf(log_buf, 250, "Entitlement label not found: %s\n", entitlementLabel->data);
	// append_to_log(log_buf);
	return SCE_APP_CONTENT_ERROR_DRM_NO_ENTITLEMENT;
}

int32_t dlcldr_sceNpEntitlementAccessGetAddcontEntitlementInfoList(
	SceNpServiceLabel serviceLabel,
	SceNpEntitlementAccessAddcontEntitlementInfo *list,
	uint32_t listNum,
	uint32_t *hitNum)
{
	if (listNum == 0)
	{
		*hitNum = addcont_count;
		return 0;
	}

	if (list == NULL)
	{
		return 0;
	}

	for (int i = 0; i < listNum; i++)
	{
		if (i < addcont_count)
		{
			strncpy(list[i].entitlementLabel.data, addcontInfo[i].entitlementLabel.data, SCE_NP_UNIFIED_ENTITLEMENT_LABEL_SIZE);
			list[i].downloadStatus = addcontInfo[i].status;
			list[i].packageType = SCE_NP_ENTITLEMENT_ACCESS_PACKAGE_TYPE_PSAC;
		}
	}

	if (hitNum != NULL)
	{
		*hitNum = listNum < addcont_count ? listNum : addcont_count;
	}

	return 0;
}

int32_t dlcldr_sceNpEntitlementAccessGetAddcontEntitlementInfo(
	SceNpServiceLabel serviceLabel,
	const SceNpUnifiedEntitlementLabel *entitlementLabel,
	SceNpEntitlementAccessAddcontEntitlementInfo *info)
{
	for (int i = 0; i < addcont_count; i++)
	{
		if (strcmp(entitlementLabel->data, addcontInfo[i].entitlementLabel.data) == 0)
		{
			strncpy(info->entitlementLabel.data, addcontInfo[i].entitlementLabel.data, SCE_NP_UNIFIED_ENTITLEMENT_LABEL_SIZE);
			info->downloadStatus = addcontInfo[i].status;
			info->packageType = SCE_NP_ENTITLEMENT_ACCESS_PACKAGE_TYPE_PSAC;
			return 0;
		}
	}

	return SCE_APP_CONTENT_ERROR_DRM_NO_ENTITLEMENT;
}

int32_t dlcldr_sceNpEntitlementAccessGetEntitlementKey(
	SceNpServiceLabel serviceLabel,
	const SceNpUnifiedEntitlementLabel *entitlementLabel,
	SceNpEntitlementAccessEntitlementKey *key)
{
	memset(key->data, 0, SCE_NP_ENTITLEMENT_ACCESS_ENTITLEMENT_KEY_SIZE);
	return 0;
}

int32_t dlcldr_sceAppContentGetEntitlementKey(
	SceNpServiceLabel serviceLabel,
	const SceNpUnifiedEntitlementLabel *entitlementLabel,
	SceAppContentEntitlementKey *key)
{
	memset(key->data, 0, SCE_APP_CONTENT_ENTITLEMENT_KEY_SIZE);
	return 0;
}

int32_t dlcldr_sceAppContentAddcontDelete(
	SceNpServiceLabel serviceLabel,
	const SceNpUnifiedEntitlementLabel *entitlementLabel)
{
	return 0;
}

int32_t dlcldr_sceAppContentAddcontMount(
	SceNpServiceLabel serviceLabel,
	const SceNpUnifiedEntitlementLabel *entitlementLabel,
	SceAppContentMountPoint *mountPoint)
{
	for (int i = 0; i < addcont_count; i++)
	{
		if (strcmp(entitlementLabel->data, addcontInfo[i].entitlementLabel.data) == 0)
		{
			// #error "TODO: implement proper folder names in mount"
			// strncpy(mountPoint->data, "/app0/dlc0", sizeof(mountPoint->data) - 1); // Copy string into mountPoint->data
			// mountPoint->data[10] = 0x30 + i;									   // Modify character
			// mountPoint->data[11] = '\0';										   // Null-terminate the string
			char new_mount_point[SCE_APP_CONTENT_MOUNTPOINT_DATA_MAXSIZE];
			// memset(&new_mount_point, 0, SCE_APP_CONTENT_MOUNTPOINT_DATA_MAXSIZE);

			if (i < 10)
			{
				// to avoid changing the naming convention
				snprintf(new_mount_point, SCE_APP_CONTENT_MOUNTPOINT_DATA_MAXSIZE, "/app0/dlc%02d", i);
			}
			else
			{
				snprintf(new_mount_point, SCE_APP_CONTENT_MOUNTPOINT_DATA_MAXSIZE, "/app0/dlc%d", i);
			}

			strncpy(mountPoint->data, new_mount_point, SCE_APP_CONTENT_MOUNTPOINT_DATA_MAXSIZE);

			// char log_buf[250];
			// snprintf(log_buf, 250, "Mount success for %s (path: %s)\n", entitlementLabel->data, mountPoint->data);
			// append_to_log(log_buf);
			return 0;
		}
	}

	return 0;
}

int32_t dlcldr_sceAppContentAddcontUnmount(
	const SceAppContentMountPoint *mountPoint)
{
	return 0;
}

int32_t dlcldr_sceAppContentGetPftFlag(
	SceAppContentPftFlag *pftFlag)
{
	*pftFlag = SCE_APP_CONTENT_PFT_FLAG_OFF;
	return 0;
}

// int32_t dlcldr_sceAppContentAppParamGetInt(
// 	SceAppContentAppParamId paramId,
// 	int32_t *value)
// {
// 	return 0;
// }

// int32_t dlcldr_sceAppContentAddcontEnqueueDownload(
// 	SceNpServiceLabel serviceLabel,
// 	const SceNpUnifiedEntitlementLabel *entitlementLabel)
// {
// 	return 0;
// }

// int32_t dlcldr_sceAppContentTemporaryDataMount2(
// 	SceAppContentTemporaryDataOption option,
// 	SceAppContentMountPoint *mountPoint)
// {
// 	return 0;
// }

// int32_t dlcldr_sceAppContentTemporaryDataUnmount(
// 	const SceAppContentMountPoint *mountPoint)
// {
// 	return 0;
// }

// int32_t dlcldr_sceAppContentTemporaryDataFormat(
// 	const SceAppContentMountPoint *mountPoint)
// {
// 	return 0;
// }

// int32_t dlcldr_sceAppContentTemporaryDataGetAvailableSpaceKb(
// 	const SceAppContentMountPoint *mountPoint,
// 	size_t *availableSpaceKb)
// {
// 	return 0;
// }

// int32_t dlcldr_sceAppContentDownloadDataFormat(
// 	const SceAppContentMountPoint *mountPoint)
// {
// 	return 0;
// }

// int32_t dlcldr_sceAppContentDownloadDataGetAvailableSpaceKb(
// 	const SceAppContentMountPoint *mountPoint,
// 	size_t *availableSpaceKb)
// {
// 	return 0;
// }

// int32_t dlcldr_sceAppContentGetAddcontDownloadProgress(
// 	SceNpServiceLabel serviceLabel,
// 	const SceNpUnifiedEntitlementLabel *entitlementLabel,
// 	SceAppContentAddcontDownloadProgress *progress)
// {
// 	return 0;
// }

// int32_t dlcldr_sceAppContentAddcontEnqueueDownloadByEntitlemetId() { return 0; }
// int32_t dlcldr_sceAppContentAddcontEnqueueDownloadSp() { return 0; }
// int32_t dlcldr_sceAppContentAddcontMountByEntitlemetId() { return 0; }
// int32_t dlcldr_sceAppContentAddcontShrink() { return 0; }
// int32_t dlcldr_sceAppContentAppParamGetString() { return 0; }
// int32_t dlcldr_sceAppContentDownload0Expand() { return 0; }
// int32_t dlcldr_sceAppContentDownload0Shrink() { return 0; }
// int32_t dlcldr_sceAppContentDownload1Expand() { return 0; }
// int32_t dlcldr_sceAppContentDownload1Shrink() { return 0; }
// int32_t dlcldr_sceAppContentGetAddcontInfoByEntitlementId() { return 0; }
// int32_t dlcldr_sceAppContentGetAddcontInfoListByIroTag() { return 0; }
// int32_t dlcldr_sceAppContentGetDownloadedStoreCountry() { return 0; }
// int32_t dlcldr_sceAppContentGetEntitlementKey() { return 0; }
// int32_t dlcldr_sceAppContentGetPftFlag() { return 0; }
// int32_t dlcldr_sceAppContentGetRegion() { return 0; }
// int32_t dlcldr_sceAppContentRequestPatchInstall() { return 0; }
// int32_t dlcldr_sceAppContentSmallSharedDataFormat() { return 0; }
// int32_t dlcldr_sceAppContentSmallSharedDataGetAvailableSpaceKb() { return 0; }
// int32_t dlcldr_sceAppContentSmallSharedDataMount() { return 0; }
// int32_t dlcldr_sceAppContentSmallSharedDataUnmount() { return 0; }
