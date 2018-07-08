# PKG installation from internal HDD

## Overview

A few years ago I've posted this [tweet](https://twitter.com/flat_z/status/795014748861530113). You could use this method from your own code to install a specified package file using an official way which means that it will install all pkg-related files too such as nptitle.dat, npbind.dat, json files, icons, etc. For example, you could copy **.pkg** file to `/user/data/` directory using any *FTP* server and then install it from this folder. It means that you don't need any *USB* drive to copy file there and install it from possibly a slow *USB* device.

And it looked very simple (at least I've thought that it was simple at that time).

To do that you need to change auth id inside **struct ucred**'s auth info to *ShellCore*'s one (**0x3800000000000010**) (see my [PKG/PFS write-up](https://playstationhax.xyz/flatz/) for needed structure), then load and start an additional module: `/system/common/lib/libSceAppInstUtil.sprx`. See my gist for [PRX related funcs](https://gist.github.com/flatz/1055a8d7819c8478db1b464842582c9c).

```cpp
// ...

int (*sceAppInstUtilInitialize)(void);
int (*sceAppInstUtilAppInstallPkg)(const char* file_path, int reserved);
int (*sceAppInstUtilGetTitleIdFromPkg)(const char* pkg_path, char* title_id, int* is_app);
int (*sceAppInstUtilAppPrepareOverwritePkg)(const char* pkg_path);
int (*sceAppInstUtilGetPrimaryAppSlot)(const char* title_id, unsigned int* slot);

// ...

static struct self_auth_info s_old_auth_info;

static void set_privileges_cb(struct self_auth_info* info) {
	// save old auth info to be able to restore it before exiting
	memcpy(&s_old_auth_info, info, sizeof(*info));

	info->paid = UINT64_C(0x3800000000000010); // shellcore
	info->caps[0] |= UINT64_C(1) << 62; // system
}

static void unset_privileges_cb(struct self_auth_info* info) {
	memcpy(info, &s_old_auth_info, sizeof(*info));
}

// ...

// XXX: I have a special syscall to call specified userland's callback function from kernel, so I could use it to change kernel's structure, you could use your own way.
gain_privileges(&set_privileges_cb);

// load & start app installer utility module
module_id_t app_inst_mid = -1;
ret = load_module("/system/common/lib/libSceAppInstUtil.sprx", &app_inst_mid);
if (ret) {
	dprintf("unable to load module: libSceAppInstUtil.sprx");
	goto err;
}
ret = start_module(app_inst_mid, NULL, 0);
if (ret) {
	dprintf("unable to start module: libSceAppInstUtil.sprx", app_inst_mid);
	goto err;
}

#define RESOLVE_EX(mid, func, name) \
	do { \
		func = (void*)lookup_module_symbol((mid), (name)); \
		if (!func) { \
			dprintf("unable to find symbol: %s", (name)); \
			goto err; \
		}
	} while (0)

#define RESOLVE(mid, func) RESOLVE_EX(mid, func, STRINGIFY(func))

#define RESOLVE_NID(mid, func, lib, nid) \
	do { \
		func = (void*)lookup_module_symbol_ex((mid), (nid), (lib), 0x1); \
		if (!func) { \
			dprintf("unable to find nid: %s", (nid)); \
			goto err; \
		}
	} while (0)

// resolve its functions
RESOLVE(app_inst_mid, sceAppInstUtilInitialize);
RESOLVE(app_inst_mid, sceAppInstUtilAppInstallPkg);
RESOLVE(app_inst_mid, sceAppInstUtilGetTitleIdFromPkg);
RESOLVE(app_inst_mid, sceAppInstUtilAppPrepareOverwritePkg);
RESOLVE(app_inst_mid, sceAppInstUtilGetPrimaryAppSlot);

// ...

ret = sceAppInstUtilInitialize();
if (ret) {
	dprintf("sceAppInstUtilInitialize failed: 0x%08X", ret);
	goto err;
}

// TODO: I'll use static path here because it's just a PoC.
const char* pkg_path = "/user/data/my.pkg";
char title_id[16];
int is_app = 0;
ret = sceAppInstUtilGetTitleIdFromPkg(pkg_path, title_id, &is_app);
if (ret) {
	dprintf("sceAppInstUtilGetTitleIdFromPkg failed: 0x%08X", re);
	goto err;
}
dprintf("Title ID: %s (app: %s)", title_id, is_app ? "yes" : "no");

unsigned int slot = -1;
bool overwrite = false;
ret = sceAppInstUtilGetPrimaryAppSlot(title_id, &slot);
if (ret) {
	if (ret == 0x80A3000E) {
		slot = 0;
		ret = 0;
	} else {
		dprintf("sceAppInstUtilGetPrimaryAppSlot failed: 0x%08X", ret);
		goto err;
	}
} else if (is_app) {
	overwrite = true;
}

if (overwrite) {
	ret = sceAppInstUtilAppPrepareOverwritePkg(pkg_path);
	if (ret) {
		dprintf("sceAppInstUtilAppPrepareOverwritePkg failed: 0x%08X", ret);
		goto err;
	}
}

dprintf("Installing package: %s", pkg_path);
ret = sceAppInstUtilAppInstallPkg(pkg_path, 0);
if (ret) {
	dprintf("sceAppInstUtilAppInstallPkg failed: 0x%08X", ret);
	goto err;
}

dprintf("Package installed succcessfully.");

// ...

err:
// TODO: do some cleanup if needed

// XXX: see comment above.
gain_privileges(&unset_privileges_cb);

return ret;
```

**sceAppInstUtilAppInstallPkg** will move package file from source path to `/user/app/<title id>/app.pkg` (if you have external hdd I think it will be moved there, but I haven't tested it because I don't have this kind of hdd on my PS4).

**...But, sadly, this method doesn't work...** Even though package is installed successfully, when we try to launch it, it will just crash and we could see such messages in logs:

```
BUG: unxexpected pbn (-1 for lbn=4108), blks=1 [0]
ufs_block_map_cache_create: failed to add (4108, -1) [95]
ufs_block_map_cache_create: failed to construct a bmap cache (95)
sync_block_map_cache: failed to create block map
lost freezing depth?
sync_block_map_cache: failed to drop block map
```

## The tale of headache

Last year I have spent some time trying to figure out the issue but then just got tired. I did come to conclusion that for **PKG** files (or more exactly, for **PFS**) file sectors should be contiguous physically (not sure, all of them or there are some rules that should be applied) which is not respected when you're doing copy operation over *FTP*, etc. This also explains why some people are getting weird errors related to out of free space on *HDD* when they are trying to install a game and have a free space for it. It's because their hard disk is heavily fragmented and there is no suitable hole with contiguous blocks to put a package file there.

Thus in our case we're having non-contiguous sectors which breaks **UFS** file system (`/user`), but sadly I haven't found any way to tell a kernel that it needs to apply this rule for our file and reversing **ShellCore** was a much pain because **PKG installer** occupies too much code there. I've thought that there are some **IOCTL** calls that are made during normal installation process, my guess was a geom scheduling driver or something similar, which was modified by Sony. So I just preferred to put off this method until these days when I have some free time during my vacation.

So, a few days ago I've remembered that there is some on-screen message that is displayed when your hard disk is fragmented, and I decided to find this error code, which was a hard task too because Google just responds with other errors and it's not related to our problem at all :/. I've tried a lot of different words/phrases with grep on system's prx files and RCO's to find the message but all of these just didn't work... :D Then I did a conversion of system's *.NET* binaries to *C#* code and tried to run grep on them and, bingo, it's worked. :) For some reason it's written as a regular text in the code itself (not in localization files as they usually do):
`/system_ex/app/app/NPXS20001/psm/Application/app/Sce.Vsh.ShellUI.Settings.PkgInstaller/PageExecute.cs`
```c#
private void ShowErrorDialog(int result) {
	// ...
	if (result == 0x80990039)
		text += "Not enough storage space to save the file.";
	else if (result == 0x80990085)
		text += "Not enough storage space to allocate a set of contiguous free area for installation of the specified pkg.";
	else if (result == 0x80A30026)
		text += "Not enough slot space to install the package on the target.";
	else {
		text += this.mPlugin.GetString("msg_error_occurred");
		flag = true;
	}
	// ...
}
```

And **0x80990085** is the code that we need. After that I've started to look into system's elfs to search where is it set, and the final destination was `ShellCore.elf`, obviously (actually there are a few references to it but after doing some reversing I've found an exact function that sets it). There is a function that opens a file for writing, checks available space on `/user` partition, then calls some unknown function from `libSceFsInternalForVsh.sprx` with our file descriptor, then truncates file to zero and calls another unknown function from the same module passing file descriptor to it too. Unfortunately there are no comments/debug logs for this piece of code at all so I decided to start reversing them. And after spending some time on reversing this module and kernel code of them I've seen that I was right a long time ago but only partially. First function use **geom scheduler** driver (`/dev/gsched_is.ctl`) for just setting slot and priority for our file, and second function tells **FFS** (*Fast File System*) that it needs to preallocate file sectors based on the file size you have specified, and the latest one is very important for our task, this is what we wanted to do.

Here's my rewrite of module's code:

```cpp
#define SLOT_CURRENT (-1)
#define MAX_SLOTS 256

#define PRIO_CURRENT (-1)
#define MAX_PRIO 256

int gsched_set_slot_prio(int fd, unsigned int slot, unsigned int prio, unsigned int* status) {
	int fd = -1;
	struct {
		void* data;
		unsigned int slot;
		unsigned int prio;
	} args = { .data = (void*)(uintptr_t)fd, .slot = slot, .prio = prio };
	int cmd = 0xC0209406;
	int ret;

	if (slot == SLOT_CURRENT && slot > MAX_SLOTS) {
		dprintf("invalid slot: %u\n", slot);
		ret = EINVAL;
		goto err;
	}
	if (prio == PRIO_CURRENT && slot != SLOT_CURRENT) {
		dprintf("PRIO_CURRENT without SLOT_CURRENT\n", slot);
		ret = EINVAL;
		goto err;
	} else if (prio > MAX_PRIO) {
		dprintf("invalid prio: %u\n", prio);
		ret = EINVAL;
		goto err;
	}

	ret = fd = open("/dev/gsched_is.ctl", O_RDONLY);
	if (ret < 0) {
		dprintf("open failed: %d (errno: %d)\n", ret, errno);
		goto err;
	}

	dprintf("doing gsched_is_set_prio()...\n");
	ret = ioctl(fd, 0xC0209406, &args);
	if (ret) {
		dprintf("ioctl(%d, 0x%08X) failed: %d (errno: %d)\n", fd, cmd, ret, errno);
		goto err;
	}
	dprintf("gsched_is_set_prio() completed\n");

	if (status)
		*status = ((args.slot << 16) & 0xFF0000) | (args.prio & 0xFF);

	ret = 0;

err:
	if (fd > 0)
		close(fd);

	return ret;
}
```

```cpp
int ffs_allocblocks(int fd, unsigned long size, unsigned int flags, unsigned int alignment) {
	struct {
		unsigned long size;
		unsigned long zero;
		unsigned long flags;
		unsigned long alignment;
	} args = { .size = size, .zero = 0, .flags = flags, .alignment = alignment };
	int cmd = 0xC02066A1;
	int ret;

	if (fd < 0) {
		ret = EINVAL;
		goto err;
	}
	if (size <= 0) {
		ret = EINVAL;
		goto err;
	}

	dprintf("doing ffs_allocblocks()...\n");
	ret = ioctl(fd, cmd, &args);
	if (ret) {
		dprintf("ioctl(%d, 0x%08X) failed: %d (errno: %d)\n", fd, cmd, ret, errno);
		goto err;
	}
	dprintf("ffs_allocblocks() completed\n");

err:
	return ret;
}
```

There is one small thing that should be done too, otherwise you'll get a crash with this annoying message in the log on launch:
```
sceBgftNotifyGameWillStart() ret = 80990019
```
My assumption is that **ShellCore** tries to notify **BGFT** (*Background File Transfer Service*) that we're starting an application that **BGFT** copied before. This is okay for PKG installer because it doesn't use **sceAppInstUtilAppInstallPkg** by itself but starts task with a help of **BGFT** and the latter thing does all copy/premote/install operations. When you install a package file from the PSN (or disc), it gets downloaded/copied to temporary path: `/user/bgft/task/<task id>/app.pkg`. But we're already having our file on internal *HDD*, so we don't need an extra copy (this will require 2x space on *HDD*), this means we can't use **BGFT** for our task if we don't want to waste too much free space (if you're okay with it then it could be done through **BGFT** but with a different method, I've reversed it too but it's not a subject of this write-up). And if we don't use **BGFT** task then it will be a problem for **ShellCore** which will thrown an error because there is no BGFT task for our package. We need to patch **ShellCore** code to ignore this error.

5.01 slide offset for ShellCore.elf: 0x3EA982
It's a call to **sceBgftNotifyGameWillStart**, you could find it easily by string reference that I've posted above. Just patch it with `xor eax, eax` and pad the rest opcode bytes with `nop`. It will introduce one more error related to **BGFT** task that gets printed but just ignore it (or try to find a better or one more patch).

## The actual method

So, how to use that? For example, you have some *FTP* code or socket server to transfer files between your PC and PS4 and you want to implement **PKG installer** on top of it.

When the client requests a **.pkg** file copy you just need to check its magic (it should be `\x7FCNT`) and optionally check other fields of **PKG** to make sure it's real package file, then after opening file for writing, truncate file to zero using `ftruncate`, and before doing actual copy operation, set slot and priority on file descriptor and use final size to preallocate file on *HDD*.

```cpp
	int fd = -1;
	int ret;

	// ...

	ret = fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, S_IRWXU | S_IRWXG);
	if (ret < 0) {
		dprintf("open failed: %d (errno: %d)\n", ret, errno);
		goto err;
	}

	ret = ftruncate(fd, 0);
	if (ret) {
		dprintf("ftruncate failed: %d (errno: %d)\n", ret, errno);
		goto err;
	}

	dprintf("preallocating file sectors...");

	ret = gsched_set_slot_prio(fd, 1, 7, &status);
	if (ret) {
		dprintf("gsched_set_slot_prio failed");
		goto err;
	}

	ret = ffs_allocblocks(fd, final_size, 0x80, 0);
	if (ret) {
		dprintf("ffs_allocblocks failed");
		goto err;
	}

	dprintf("preallocation done")

	//
	// TODO: copy file data
	//

	// ...
```

Also would be nice to check error code of `ffs_alloc_blocks` if we don't have contiguous free space on *HDD*, report about it and go away. But I'm skipping this part here because it's just a proof of concept.

After doing this we need to start downloading and writing file as we did before (it's better to do it by chunks).

Finally, you need to call `sceAppInstUtil*` functions as I've described in the beginning of the document, it will install package on the title screen. Also would be better to create a special application for packages to do everything I've described.
I've tested this code with some game package and it worked like a charm but haven't tried it on patch packages but they should work too I think. Maybe I'll try them a bit later, just need to relax now after a few days of reversing/brainstorming. :)

Good luck.

## Bonus

Here's a bonus code that could be used to initiate **PKG** file extra copying/installation using **BGFT**. You need to create and copy file to temporary directory and then ask **BGFT** to do the rest for you. It will preallocate a new file inside `/user/app/<title id>` and copy your file there. But the original file is left intact so you need to delete it or optionally use **BGFT_TASK_OPTION_DELETE_AFTER_UPLOAD** option (haven't tested).

Use the code below instead of call to **sceAppInstUtilAppInstallPkg()** to make PKG installation using BGFT (requires 2x free space due to extra pkg file copy).

```cpp
enum bgft_task_option_t {
	BGFT_TASK_OPTION_NONE = 0x0,
	BGFT_TASK_OPTION_DELETE_AFTER_UPLOAD = 0x1,
	BGFT_TASK_OPTION_INVISIBLE = 0x2,
	BGFT_TASK_OPTION_ENABLE_PLAYGO = 0x4,
	BGFT_TASK_OPTION_FORCE_UPDATE = 0x8,
	BGFT_TASK_OPTION_REMOTE = 0x10,
	BGFT_TASK_OPTION_COPY_CRASH_REPORT_FILES = 0x20,
	BGFT_TASK_OPTION_DISABLE_INSERT_POPUP = 0x40,
	BGFT_TASK_OPTION_DISABLE_CDN_QUERY_PARAM = 0x10000,
};

struct bgft_download_param {
	int user_id;
	int entitlement_type;
	const char* id;
	const char* content_url;
	const char* content_ex_url;
	const char* content_name;
	const char* icon_path;
	const char* sku_id;
	enum task_option_t option;
	const char* playgo_scenario_id;
	const char* release_date;
	const char* package_type;
	const char* package_sub_type;
	unsigned long package_size;
};

struct bgft_download_param_ex {
	struct bgft_download_param param;
	unsigned int slot;
};

struct bgft_task_progress_internal {
	unsigned int bits;
	int error_result;
	unsigned long length;
	unsigned long transferred;
	unsigned long length_total;
	unsigned long transferred_total;
	unsigned int num_index;
	unsigned int num_total;
	unsigned int rest_sec;
	unsigned int rest_sec_total;
	int preparing_percent;
	int local_copy_percent;
};

#define BGFT_INVALID_TASK_ID (-1)

struct bgft_init_params {
	void* mem;
	unsigned long size;
};

// ...

int (*sceBgftInitialize)(struct bgft_init_params* params);
int (*sceBgftDownloadRegisterTaskByStorageEx)(struct bgft_download_param_ex* params, int* task_id);
int (*sceBgftDownloadStartTask)(int task_id);
int (*sceBgftDownloadGetProgress)(int task_id, struct bgft_task_progress_internal* progress);

// ...

// load & start bgft module
module_id_t bgft_mid = -1;
ret = load_module("/system/common/lib/libSceBgft.sprx", &bgft_mid);
if (ret) {
	dprintf("unable to load module: libSceBgft.sprx");
	goto err;
}
ret = start_module(bgft_mid, NULL, 0);
if (ret) {
	dprintf("unable to start module: libSceBgft.sprx", bgft_mid);
	goto err;
}

// resolve its functions
RESOLVE_NID(bgft_mid, sceBgftInitialize, "libSceBgft", "BZ0olR8Da0g");
RESOLVE_NID(bgft_mid, sceBgftDownloadRegisterTaskByStorageEx, "libSceBgft", "nd+0DEOC68A");
RESOLVE_NID(bgft_mid, sceBgftDownloadStartTask, "libSceBgft", "HRDHLMA9Y7s");
RESOLVE_NID(bgft_mid, sceBgftDownloadGetProgress, "libSceBgft", "5txx+w0HYOs");

// initialize
struct bgft_init_params init_params;
memset(&init_params, 0, sizeof(init_params));
{
	init_params.size = 0x100000;
	init_params.mem = malloc(init_params.size);
	if (!init_params.mem) {
		dprintf("no memory");
		goto err;
	}
	memset(init_params.mem, 0, init_params.size);
}

ret = sceBgftInitialize(&init_params);
if (ret) {
	dprintf("sceBgftInitialize failed: %d (errno: %d)", ret, errno);
	goto err;
}

struct bgft_download_param_ex download_params;
memset(&download_params, 0, sizeof(download_params));
{
	download_params.param.entitlement_type = 5;
	download_params.param.id = "";
	download_params.param.content_url = pkg_path;
	download_params.param.content_name = extract_file_name(pkg_path);
	download_params.param.icon_path = "";
	download_params.param.playgo_scenario_id = "0";
	download_params.param.option = BGFT_TASK_OPTION_DISABLE_CDN_QUERY_PARAM;
	download_params.slot = slot;
}

int task_id = BGFT_INVALID_TASK_ID;
ret = sceBgftDownloadRegisterTaskByStorageEx(&download_params, &task_id);
if (ret) {
	dprintf("sceBgftDownloadRegisterTaskByStorageEx failed: %d (errno: %d)", ret, errno);
	goto err;
}
dprintf("Task ID: 0x%08X", task_id);

// XXX: it seems task started by itself but let's doing it anyway...
ret = sceBgftDownloadStartTask(task_id);
if (ret) {
	dprintf("sceBgftDownloadStartTask failed: %d (errno: %d)", ret, errno);
	goto err;
}

#if 0
// TODO: there is sceBgftDownloadGetProgress() that may be used to get progress information but I didn't have a free
// time to figure out how to use it properly, for me it always returns zeros in size fields so I can't get proper percent.
struct bgft_task_progress_internal progress;
memset(&progress, 0, sizeof(progress));
ret = sceBgftDownloadGetProgress(task_id, &progress);
if (ret) {
	dprintf("sceBgftDownloadGetProgress() failed: %d (errno: %d)", ret, errno);
	goto err;
}
#endif
```
