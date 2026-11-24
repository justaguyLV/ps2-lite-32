// SPDX-FileCopyrightText: 2002-2026 PCSX2 Dev Team
// SPDX-License-Identifier: GPL-3.0+

#include "common/Assertions.h"
#include "common/BitUtils.h"
#include "common/Console.h"
#include "common/CrashHandler.h"
#include "common/Error.h"
#include "common/HostSys.h"

#include <algorithm>
#include <atomic>
#include <string>
#include <cstdio>
#include <csignal>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <limits.h>
#include <mutex>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>
#if defined(__ANDROID__)
#include <android/log.h>
#endif
#ifdef __APPLE__
#include <libkern/OSCacheControl.h>
#include <TargetConditionals.h>
#endif
#ifndef __APPLE__
#include <ucontext.h>
#endif
#if defined(__linux__) && defined(__aarch64__)
#include <asm/sigcontext.h>
#endif

#include "fmt/format.h"

#if defined(__ANDROID__)
#include <sys/syscall.h>
// bionic lacks shm_open until API 30; memfd_create is a libc wrapper only from
// API 30 too, but the raw syscall works from API 26 (our minSdk).
static int memfd_create_wrapper(const char* name, unsigned int flags)
{
	return static_cast<int>(syscall(__NR_memfd_create, name, flags));
}
#endif

#if defined(__FreeBSD__)
#include "cpuinfo.h"
#endif

static __ri uint LinuxProt(const PageProtectionMode& mode)
{
	u32 lnxmode = 0;

	if (mode.CanWrite())
		lnxmode |= PROT_WRITE;
	if (mode.CanRead())
		lnxmode |= PROT_READ;
	if (mode.CanExecute())
		lnxmode |= PROT_EXEC | PROT_READ;

	return lnxmode;
}

void HostSys::MemProtect(void* baseaddr, size_t size, const PageProtectionMode& mode)
{
	pxAssertMsg((size & (__pagesize - 1)) == 0, "Size is page aligned");

	const u32 lnxmode = LinuxProt(mode);

	const int result = mprotect(baseaddr, size, lnxmode);
	if (result != 0)
		pxFail("mprotect() failed");
}

std::string HostSys::GetFileMappingName(const char* prefix)
{
	const unsigned pid = static_cast<unsigned>(getpid());
#if defined(__FreeBSD__)
	// FreeBSD's shm_open(3) requires name to be absolute
	return fmt::format("/tmp/{}_{}", prefix, pid);
#else
	return fmt::format("{}_{}", prefix, pid);
#endif
}

#if defined(__APPLE__) && TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR
static int CreateIOSFileBackedSharedMemory(const char* name, size_t size, int shm_errno)
{
	const char* tmpdir = std::getenv("TMPDIR");
	if (!tmpdir || tmpdir[0] == '\0')
		tmpdir = "/tmp";

	for (int attempt = 0; attempt < 16; attempt++)
	{
		char path[PATH_MAX];
		const int written = std::snprintf(path, sizeof(path), "%s/armsx2_%s_%u_%d.mem",
			tmpdir, name, static_cast<unsigned>(getpid()), attempt);
		if (written <= 0 || static_cast<size_t>(written) >= sizeof(path))
			break;

		const int fd = open(path, O_RDWR | O_CREAT | O_EXCL, 0600);
		if (fd < 0)
		{
			if (errno == EEXIST)
				continue;

			std::fprintf(stderr,
				"@@IOS_SHM_FILE_FALLBACK_FAIL@@ shm_open_errno=%d open_errno=%d path=\"%s\" size=%zu\n",
				shm_errno, errno, path, size);
			return -1;
		}

		if (fcntl(fd, F_SETFD, FD_CLOEXEC) != 0)
			std::fprintf(stderr, "@@IOS_SHM_CLOEXEC_FAIL@@ errno=%d fd=%d\n", errno, fd);

		if (ftruncate(fd, static_cast<off_t>(size)) < 0)
		{
			const int truncate_errno = errno;
			unlink(path);
			close(fd);
			std::fprintf(stderr,
				"@@IOS_SHM_FILE_FALLBACK_FAIL@@ shm_open_errno=%d ftruncate_errno=%d path=\"%s\" size=%zu\n",
				shm_errno, truncate_errno, path, size);
			return -1;
		}

		const int unlink_errno = (unlink(path) != 0) ? errno : 0;
		std::fprintf(stderr,
			"@@IOS_SHM_FILE_FALLBACK@@ shm_open_errno=%d fd=%d size=%zu path=\"%s\" unlink_errno=%d\n",
			shm_errno, fd, size, path, unlink_errno);
		return fd;
	}

	std::fprintf(stderr,
		"@@IOS_SHM_FILE_FALLBACK_FAIL@@ shm_open_errno=%d reason=path_exhausted size=%zu\n",
		shm_errno, size);
	return -1;
}
#endif

void* HostSys::CreateSharedMemory(const char* name, size_t size)
{
#if defined(__ANDROID__)
	// Android: memfd_create available since API 26 (our minSdk), no shm_open until API 30.
	const int fd = memfd_create_wrapper(name, 0);
	if (fd < 0)
	{
		std::fprintf(stderr, "memfd_create failed: %d\n", errno);
		return nullptr;
	}
#else
	const int fd = shm_open(name, O_CREAT | O_EXCL | O_RDWR, 0600);
	if (fd < 0)
	{
		const int shm_errno = errno;
#if defined(__APPLE__) && TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR
		const int file_fd = CreateIOSFileBackedSharedMemory(name, size, shm_errno);
		if (file_fd >= 0)
			return reinterpret_cast<void*>(static_cast<intptr_t>(file_fd));
#endif
		std::fprintf(stderr, "shm_open failed: %d\n", shm_errno);
		return nullptr;
	}

	// we're not going to be opening this mapping in other processes, so remove the file
	shm_unlink(name);
#endif

	// ensure it's the correct size
	if (ftruncate(fd, static_cast<off_t>(size)) < 0)
	{
		std::fprintf(stderr, "ftruncate(%zu) failed: %d\n", size, errno);
		return nullptr;
	}

	return reinterpret_cast<void*>(static_cast<intptr_t>(fd));
}

void HostSys::DestroySharedMemory(void* ptr)
{
	close(static_cast<int>(reinterpret_cast<intptr_t>(ptr)));
}

bool HostSys::DiscardSharedMemory(void* ptr, size_t offset, size_t size)
{
#if defined(__linux__)
	// shm/memfd memory is tmpfs, so a hole reads back as zeros. Partial pages at the ends get zeroed.
	const int fd = static_cast<int>(reinterpret_cast<intptr_t>(ptr));
	return fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, static_cast<off_t>(offset),
			   static_cast<off_t>(size)) == 0;
#else
	return false;
#endif
}

void HostSys::DiscardMemory(void* ptr, size_t size)
{
#if defined(__linux__)
	// MADV_DONTNEED frees whole pages (they read back as zeros); partial pages at the ends get zeroed.
	const uptr begin = reinterpret_cast<uptr>(ptr);
	const uptr end = begin + size;
	const uptr pages_begin = Common::AlignUpPow2(begin, __pagesize);
	const uptr pages_end = Common::AlignDownPow2(end, __pagesize);
	if (pages_begin < pages_end &&
		madvise(reinterpret_cast<void*>(pages_begin), pages_end - pages_begin, MADV_DONTNEED) == 0)
	{
		std::memset(ptr, 0, pages_begin - begin);
		std::memset(reinterpret_cast<void*>(pages_end), 0, end - pages_end);
		return;
	}
#endif
	std::memset(ptr, 0, size);
}

#ifndef __APPLE__

size_t HostSys::GetRuntimePageSize()
{
	int res = sysconf(_SC_PAGESIZE);
	return (res > 0) ? static_cast<size_t>(res) : 0;
}

size_t HostSys::GetRuntimeCacheLineSize()
{
#if defined(__FreeBSD__)
	if (!cpuinfo_initialize())
		return 0;

	u32 max_line_size = 0;
	for (u32 i = 0; i < cpuinfo_get_processors_count(); i++)
	{
		const u32 l1i = cpuinfo_get_processor(i)->cache.l1i->line_size;
		const u32 l1d = cpuinfo_get_processor(i)->cache.l1d->line_size;
		const u32 res = std::max<u32>(l1i, l1d);

		max_line_size = std::max<u32>(max_line_size, res);
	}

	return static_cast<size_t>(max_line_size);
#else
	int l1i = sysconf(_SC_LEVEL1_DCACHE_LINESIZE);
	int l1d = sysconf(_SC_LEVEL1_ICACHE_LINESIZE);
	int res = (l1i > l1d) ? l1i : l1d;
	for (int index = 0; index < 16; index++)
	{
		char buf[128];
		snprintf(buf, sizeof(buf), "/sys/devices/system/cpu/cpu0/cache/index%d/coherency_line_size", index);
		std::FILE* fp = std::fopen(buf, "rb");
		if (!fp)
			break;

		std::fread(buf, sizeof(buf), 1, fp);
		std::fclose(fp);
		int val = std::atoi(buf);
		res = (val > res) ? val : res;
	}

	return (res > 0) ? static_cast<size_t>(res) : 0;
#endif
}

#endif

SharedMemoryMappingArea::SharedMemoryMappingArea(u8* base_ptr, size_t size, size_t num_pages)
	: m_base_ptr(base_ptr)
	, m_size(size)
	, m_num_pages(num_pages)
{
}

SharedMemoryMappingArea::~SharedMemoryMappingArea()
{
	pxAssertRel(m_num_mappings == 0, "No mappings left");

	if (munmap(m_base_ptr, m_size) != 0)
		pxFailRel("Failed to release shared memory area");
}



#if defined(ARCH_ARM32)
// 32-bit processes already have much of the low 2 GB taken (ART heap, libraries, driver
// reservations), so fixed-stride guesses miss. Read the real layout and return the start of
// every free gap below 2 GB that can hold [size] plus a 1 MB safety margin on both sides.
static std::vector<uptr> FindLowAddressGaps(size_t size)
{
	std::vector<uptr> gaps;
	FILE* f = std::fopen("/proc/self/maps", "r");
	if (!f)
		return gaps;

	constexpr uptr kLow = 0x01000000u;
	constexpr uptr kHigh = 0x80000000u;
	constexpr uptr kMargin = 0x100000u;

	char line[512];
	uptr prev_end = kLow;
	while (std::fgets(line, sizeof(line), f))
	{
		unsigned long s = 0, e = 0;
		if (std::sscanf(line, "%lx-%lx", &s, &e) != 2)
			continue;
		if (s > prev_end && s <= kHigh)
		{
			const uptr cand = prev_end + kMargin;
			if (cand + size + kMargin <= s)
				gaps.push_back(cand);
		}
		else if (s > kHigh && prev_end < kHigh)
		{
			const uptr cand = prev_end + kMargin;
			if (cand + size + kMargin <= kHigh)
				gaps.push_back(cand);
		}
		if (e > prev_end)
			prev_end = e;
		if (prev_end >= kHigh)
			break;
	}
	if (prev_end < kHigh)
	{
		const uptr cand = prev_end + kMargin;
		if (cand + size + kMargin <= kHigh)
			gaps.push_back(cand);
	}
	std::fclose(f);
	return gaps;
}

static void LogLowMapsToLogcat(size_t size)
{
#if defined(__ANDROID__)
	__android_log_print(ANDROID_LOG_ERROR, "ARMSX2", "low-2GB reservation of %zu bytes failed; process map follows", size);
	FILE* f = std::fopen("/proc/self/maps", "r");
	if (!f)
		return;
	char line[512];
	int n = 0;
	while (std::fgets(line, sizeof(line), f) && n < 120)
	{
		unsigned long s = 0;
		if (std::sscanf(line, "%lx-", &s) == 1 && s < 0x90000000ul)
		{
			__android_log_print(ANDROID_LOG_ERROR, "ARMSX2", "maps: %s", line);
			n++;
		}
	}
	std::fclose(f);
#else
	(void)size;
#endif
}
#endif

#if defined(ARCH_ARM32)
// Human-readable summary of the free address space below 2 GB, shown in the "failed to map" dialog.
std::string ARMSX2_DescribeLowAddressSpace(size_t need)
{
	FILE* f = std::fopen("/proc/self/maps", "r");
	if (!f)
		return "(cannot read /proc/self/maps)";

	constexpr unsigned long kLow = 0x01000000ul;
	constexpr unsigned long kHigh = 0x80000000ul;
	struct Gap { unsigned long start, size; };
	std::vector<Gap> gaps;
	unsigned long prev_end = kLow;
	unsigned long total_free = 0;
	int maps = 0;
	char line[512];
	while (std::fgets(line, sizeof(line), f))
	{
		unsigned long s = 0, e = 0;
		if (std::sscanf(line, "%lx-%lx", &s, &e) != 2)
			continue;
		maps++;
		const unsigned long cap = (s > kHigh) ? kHigh : s;
		if (cap > prev_end)
		{
			gaps.push_back({prev_end, cap - prev_end});
			total_free += cap - prev_end;
		}
		if (e > prev_end)
			prev_end = e;
		if (prev_end >= kHigh)
			break;
	}
	if (prev_end < kHigh)
	{
		gaps.push_back({prev_end, kHigh - prev_end});
		total_free += kHigh - prev_end;
	}
	std::fclose(f);

	std::sort(gaps.begin(), gaps.end(), [](const Gap& a, const Gap& b) { return a.size > b.size; });
	std::string out = fmt::format("need {} MB; free below 2GB: {} MB in {} gaps; largest:", need >> 20, total_free >> 20, gaps.size());
	for (size_t i = 0; i < gaps.size() && i < 4; i++)
		out += fmt::format(" 0x{:x}+{}MB", gaps[i].start, gaps[i].size >> 20);
	out += fmt::format("; maps={}", maps);
	return out;
}
#endif

std::unique_ptr<SharedMemoryMappingArea> SharedMemoryMappingArea::Create(size_t size, bool jit, uptr fixed_base_hint)
{
	pxAssertRel(Common::IsAlignedPow2(size, __pagesize), "Size is page aligned");

	uint flags = MAP_ANONYMOUS | MAP_PRIVATE;
	uint prot = PROT_NONE;
#ifdef __APPLE__
	if (jit) {
		flags |= MAP_JIT;
#if TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR
		// iOS rejects PROT_NONE MAP_JIT reservations on the LiveContainer/JIT path.
		// Code memory must be born as an actual JIT mapping; callers can mprotect it
		// afterward, but we never fall back to a non-MAP_JIT executable region.
		prot = PROT_READ | PROT_WRITE | PROT_EXEC;
#endif
	}
#endif

	void* alloc = MAP_FAILED;

#if defined(ARCH_ARM32)
	if (fixed_base_hint != 0)
	{
		for (const uptr cand : FindLowAddressGaps(size))
		{
			void* const want = reinterpret_cast<void*>(cand);
			void* const got = mmap(want, size, prot, flags, -1, 0);
			if (got == MAP_FAILED)
				continue;
			if (got == want)
			{
				alloc = got;
				break;
			}
			munmap(got, size);
		}
	}
#endif

	// Deterministic VA placement for the on-disk VU program cache: when a
	// fixed base hint is given, try it (plus 256MB-stride fallback slots) with a
	// hint-and-verify mmap (no MAP_FIXED, so we never clobber an existing
	// mapping). If none of the slots land exactly, fall through to kernel
	// placement — the program cache records the arena base and simply misses on
	// a mismatch, so this trades determinism for booting, never correctness.
	if (fixed_base_hint != 0 && alloc == MAP_FAILED)
	{
		for (int slot = 0; slot <= 10; slot++)
		{
			void* const want = reinterpret_cast<void*>(fixed_base_hint + (static_cast<uptr>(slot) << 28));
#if defined(ARCH_ARM32)
			// VTLB keeps the top bit of a host pointer free as its "handler" flag, so every
			// guest-memory pointer must be below 2 GB.
			if (reinterpret_cast<uptr>(want) + size > 0x80000000u)
				break;
#endif
			void* const got = mmap(want, size, prot, flags, -1, 0);
			if (got == MAP_FAILED)
				continue;
			if (got == want)
			{
				alloc = got;
				break;
			}
			munmap(got, size);
		}
	}

	if (alloc == MAP_FAILED)
		alloc = mmap(nullptr, size, prot, flags, -1, 0);
#if defined(ARCH_ARM32)
	if (alloc != MAP_FAILED && fixed_base_hint != 0 && reinterpret_cast<uptr>(alloc) + size > 0x80000000u)
	{
		std::fprintf(stderr, "@@HOST_MMAP_FAIL@@ op=reserve_low size=%zu got=%p (needs <2GB for VTLB)\n", size, alloc);
		munmap(alloc, size);
		LogLowMapsToLogcat(size);
		return nullptr;
	}
#endif
	if (alloc == MAP_FAILED)
	{
		const int err = errno;
		std::fprintf(stderr,
			"@@HOST_MMAP_FAIL@@ op=reserve size=%zu jit=%d flags=0x%x prot=0x%x err=%d message=\"%s\"\n",
			size, jit ? 1 : 0, flags, prot, err, std::strerror(err));
		return nullptr;
	}

	return std::unique_ptr<SharedMemoryMappingArea>(new SharedMemoryMappingArea(static_cast<u8*>(alloc), size, size / __pagesize));
}

u8* SharedMemoryMappingArea::Map(void* file_handle, size_t file_offset, void* map_base, size_t map_size, const PageProtectionMode& mode)
{
	pxAssert(static_cast<u8*>(map_base) >= m_base_ptr && static_cast<u8*>(map_base) < (m_base_ptr + m_size));

	const uint lnxmode = LinuxProt(mode);
	if (file_handle)
	{
		const int fd = static_cast<int>(reinterpret_cast<intptr_t>(file_handle));
		// MAP_FIXED is okay here, since we've reserved the entire region, and *want* to overwrite the mapping.
		void* const ptr = mmap(map_base, map_size, lnxmode, MAP_SHARED | MAP_FIXED, fd, static_cast<off_t>(file_offset));
		if (ptr == MAP_FAILED)
		{
			const int err = errno;
			std::fprintf(stderr,
				"@@HOST_MMAP_FAIL@@ op=map_shared base=%p size=%zu prot=0x%x err=%d message=\"%s\"\n",
				map_base, map_size, lnxmode, err, std::strerror(err));
			return nullptr;
		}
	}
	else
	{
		// macOS doesn't seem to allow MAP_JIT with MAP_FIXED
		// So we do the MAP_JIT in the allocation, and just mprotect here
		// Note that this will only work the first time for a given region
		if (mprotect(map_base, map_size, lnxmode) < 0)
		{
			const int err = errno;
			std::fprintf(stderr,
				"@@HOST_MMAP_FAIL@@ op=mprotect base=%p size=%zu prot=0x%x err=%d message=\"%s\"\n",
				map_base, map_size, lnxmode, err, std::strerror(err));
			return nullptr;
		}
	}

	m_num_mappings++;
	return static_cast<u8*>(map_base);
}

bool SharedMemoryMappingArea::Unmap(void* map_base, size_t map_size, bool is_file)
{
	pxAssert(static_cast<u8*>(map_base) >= m_base_ptr && static_cast<u8*>(map_base) < (m_base_ptr + m_size));

	if (mmap(map_base, map_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == MAP_FAILED)
		return false;

	m_num_mappings--;
	return true;
}

#ifdef ARCH_ARM64

void HostSys::FlushInstructionCache(void* address, u32 size)
{
#ifdef __APPLE__
	sys_icache_invalidate(address, size);
#else
	__builtin___clear_cache(reinterpret_cast<char*>(address), reinterpret_cast<char*>(address) + size);
#endif
}

#endif

#ifndef __APPLE__ // These are done in DarwinMisc

namespace PageFaultHandler
{
	static std::recursive_mutex s_exception_handler_mutex;
	static bool s_in_exception_handler = false;
	static bool s_installed = false;
	static std::atomic<UnhandledFaultReporter> s_unhandled_fault_reporter{nullptr};
} // namespace PageFaultHandler

#ifdef ARCH_ARM64

[[maybe_unused]] static bool IsStoreInstruction(const void* ptr)
{
	u32 bits;
	std::memcpy(&bits, ptr, sizeof(bits));

	// Based on vixl's disassembler Instruction::IsStore().
	// if (Mask(LoadStoreAnyFMask) != LoadStoreAnyFixed)
	if ((bits & 0x0a000000) != 0x08000000)
		return false;

	// if (Mask(LoadStorePairAnyFMask) == LoadStorePairAnyFixed)
	if ((bits & 0x3a000000) == 0x28000000)
	{
		// return Mask(LoadStorePairLBit) == 0
		return (bits & (1 << 22)) == 0;
	}

	switch (bits & 0xC4C00000)
	{
		case 0x00000000: // STRB_w
		case 0x40000000: // STRH_w
		case 0x80000000: // STR_w
		case 0xC0000000: // STR_x
		case 0x04000000: // STR_b
		case 0x44000000: // STR_h
		case 0x84000000: // STR_s
		case 0xC4000000: // STR_d
		case 0x04800000: // STR_q
			return true;

		default:
			return false;
	}
}

#if defined(__linux__)

// Whether the fault was a write, from the ESR the kernel saves in the signal
// frame. Not from the instruction at the pc: when the guest jumps through a
// null or wild pointer the pc is the bad address itself, and reading it faults
// again inside this handler, so the report describes the handler instead of
// the fault.
static bool IsWriteFault(const ucontext_t* uc)
{
	const u8* p = reinterpret_cast<const u8*>(uc->uc_mcontext.__reserved);
	const u8* const end = p + sizeof(uc->uc_mcontext.__reserved);
	while (static_cast<size_t>(end - p) >= sizeof(_aarch64_ctx))
	{
		const _aarch64_ctx* const head = reinterpret_cast<const _aarch64_ctx*>(p);
		if (head->magic == 0 || head->size < sizeof(_aarch64_ctx) || head->size > static_cast<size_t>(end - p))
			break;
		if (head->magic == ESR_MAGIC && head->size >= sizeof(esr_context))
		{
			const u64 esr = reinterpret_cast<const esr_context*>(p)->esr;
			const u32 ec = static_cast<u32>(esr >> 26) & 0x3f;
			// Data abort from EL0 (0x24) or EL1 (0x25); bit 6 is WnR.
			return (ec == 0x24 || ec == 0x25) && (esr & (1u << 6)) != 0;
		}
		p += head->size;
	}
	return false;
}

#endif // __linux__

#endif // ARCH_ARM64

namespace PageFaultHandler
{
	static void SignalHandler(int sig, siginfo_t* info, void* ctx);
#ifdef ARCH_ARM64
	static void IllegalInstructionHandler(int sig, siginfo_t* info, void* ctx);
#endif
} // namespace PageFaultHandler

#ifdef ARCH_ARM64
// An illegal instruction is never ours to fix up, so there is no page fault
// handling to try: the reporter writes its post-mortem, and the crash handler
// hands the signal back to whoever had it before us.
void PageFaultHandler::IllegalInstructionHandler(int sig, siginfo_t* info, void* ctx)
{
	if (const UnhandledFaultReporter reporter = s_unhandled_fault_reporter.load(std::memory_order_acquire))
		reporter(sig, info, ctx);
	CrashHandler::CrashSignalHandler(sig, info, ctx);
}
#endif

void PageFaultHandler::SignalHandler(int sig, siginfo_t* info, void* ctx)
{
#if defined(__linux__)
	void* const exception_address = reinterpret_cast<void*>(info->si_addr);

#if defined(ARCH_X86)
	void* const exception_pc = reinterpret_cast<void*>(static_cast<ucontext_t*>(ctx)->uc_mcontext.gregs[REG_RIP]);
	const bool is_write = (static_cast<ucontext_t*>(ctx)->uc_mcontext.gregs[REG_ERR] & 2) != 0;
#elif defined(ARCH_ARM64)
	void* const exception_pc = reinterpret_cast<void*>(static_cast<ucontext_t*>(ctx)->uc_mcontext.pc);
	const bool is_write = IsWriteFault(static_cast<const ucontext_t*>(ctx));
#elif defined(ARCH_ARM32)
	void* const exception_pc = reinterpret_cast<void*>(static_cast<ucontext_t*>(ctx)->uc_mcontext.arm_pc);
	// DFSR.WnR is bit 11 of the kernel-reported error code.
	const bool is_write = (static_cast<ucontext_t*>(ctx)->uc_mcontext.error_code & (1u << 11)) != 0;
#endif

#elif defined(__FreeBSD__)

#if defined(ARCH_X86)
	void* const exception_address = reinterpret_cast<void*>(static_cast<ucontext_t*>(ctx)->uc_mcontext.mc_addr);
	void* const exception_pc = reinterpret_cast<void*>(static_cast<ucontext_t*>(ctx)->uc_mcontext.mc_rip);
	const bool is_write = (static_cast<ucontext_t*>(ctx)->uc_mcontext.mc_err & 2) != 0;
#elif defined(ARCH_ARM64)
	void* const exception_address = reinterpret_cast<void*>(static_cast<ucontext_t*>(ctx)->uc_mcontext->__es.__far);
	void* const exception_pc = reinterpret_cast<void*>(static_cast<ucontext_t*>(ctx)->uc_mcontext->__ss.__pc);
	const bool is_write = IsStoreInstruction(exception_pc);
#endif

#endif

	// Executing the handler concurrently from multiple threads wouldn't go down well.
	s_exception_handler_mutex.lock();

	// Prevent recursive exception filtering.
	HandlerResult result = HandlerResult::ExecuteNextHandler;
	if (!s_in_exception_handler)
	{
		s_in_exception_handler = true;
		result = HandlePageFault(exception_pc, exception_address, is_write);
		s_in_exception_handler = false;
	}

	s_exception_handler_mutex.unlock();

	// Resumes execution right where we left off (re-executes instruction that caused the SIGSEGV).
	if (result == HandlerResult::ContinueExecution)
		return;

	// We couldn't handle it. Say what we can about it, then pass it off to the
	// crash dumper, which hands the signal back to whoever had it before us:
	// returning from here retries the instruction, and it faults under them.
	if (const UnhandledFaultReporter reporter = s_unhandled_fault_reporter.load(std::memory_order_acquire))
		reporter(sig, info, ctx);
	CrashHandler::CrashSignalHandler(sig, info, ctx);
}

void PageFaultHandler::SetUnhandledFaultReporter(UnhandledFaultReporter reporter)
{
	s_unhandled_fault_reporter.store(reporter, std::memory_order_release);
}

bool PageFaultHandler::Install(Error* error)
{
	std::unique_lock lock(s_exception_handler_mutex);
	// Android keeps one process across game launches, so the VM lifecycle can call
	// Install() more than once. Make it idempotent instead of tripping the release
	// assert below (which aborts the CPU thread on the second game boot).
	if (s_installed)
		return true;
	pxAssertRel(!s_installed, "Page fault handler has already been installed.");

	struct sigaction sa;

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_SIGINFO | SA_NODEFER;
	sa.sa_sigaction = SignalHandler;

	// What we replace is what a crash goes back to (CrashHandler). On Android
	// that is debuggerd's handler, as ART's sigchain reports it.
	struct sigaction replaced;
	if (sigaction(SIGSEGV, &sa, &replaced) != 0)
	{
		Error::SetErrno(error, "sigaction() for SIGSEGV failed: ", errno);
		return false;
	}
	CrashHandler::RecordReplacedHandler(SIGSEGV, replaced);

#ifdef ARCH_ARM64
	// We can get SIGBUS on ARM64.
	if (sigaction(SIGBUS, &sa, &replaced) != 0)
	{
		Error::SetErrno(error, "sigaction() for SIGBUS failed: ", errno);
		return false;
	}
	CrashHandler::RecordReplacedHandler(SIGBUS, replaced);

	// A jump into code that is not there (a stale dispatcher, zeroed code
	// memory) usually ends in SIGILL, and gets the same post-mortem.
	struct sigaction ill = sa;
	ill.sa_sigaction = IllegalInstructionHandler;
	if (sigaction(SIGILL, &ill, &replaced) != 0)
	{
		Error::SetErrno(error, "sigaction() for SIGILL failed: ", errno);
		return false;
	}
	CrashHandler::RecordReplacedHandler(SIGILL, replaced);
#endif

	s_installed = true;
	return true;
}

bool PageFaultHandler::InstallSecondaryThread() { return true; }

#endif // __APPLE__
