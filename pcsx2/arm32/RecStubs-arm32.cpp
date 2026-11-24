// SPDX-License-Identifier: GPL-3.0
//
// ARMv7 (32-bit) has no recompilers yet. These definitions satisfy the references the
// shared code makes to the recompiler providers and route everything to the interpreters.
// SysMemory::HasCodeMemory() is false on this build, so VMManager never selects them anyway.

#include "common/Assertions.h"
#include "common/Console.h"
#include "R5900.h"
#include "R3000A.h"
#include "VUmicro.h"
#include "Vif.h"
#include "Vif_Dynarec.h"
#include "SaveState.h"
#include "vtlb.h"
#include <cstdlib>

R5900cpu recCpu = intCpu;
R3000Acpu psxRec = psxInt;

recMicroVU0 CpuMicroVU0;
recMicroVU1 CpuMicroVU1;

recMicroVU0::recMicroVU0() { m_Idx = 0; IsInterpreter = true; }
void recMicroVU0::Reserve() {}
void recMicroVU0::Shutdown() {}
void recMicroVU0::Reset() { CpuIntVU0.Reset(); }
void recMicroVU0::Step() { CpuIntVU0.Step(); }
void recMicroVU0::SetStartPC(u32 startPC) { CpuIntVU0.SetStartPC(startPC); }
void recMicroVU0::Execute(u32 cycles) { CpuIntVU0.Execute(cycles); }
void recMicroVU0::Clear(u32, u32) {}

recMicroVU1::recMicroVU1() { m_Idx = 1; IsInterpreter = true; }
void recMicroVU1::Reserve() {}
void recMicroVU1::Shutdown() {}
void recMicroVU1::Reset() { CpuIntVU1.Reset(); }
void recMicroVU1::Step() { CpuIntVU1.Step(); }
void recMicroVU1::SetStartPC(u32 startPC) { CpuIntVU1.SetStartPC(startPC); }
void recMicroVU1::Execute(u32 cycles) { CpuIntVU1.Execute(cycles); }
void recMicroVU1::Clear(u32, u32) {}
void recMicroVU1::ResumeXGkick() {}

void dVifReset(int) {}
void dVifRelease(int) {}
void VifUnpackSSE_Init() {}

template <int idx>
void dVifUnpack(const u8* data, bool isFill)
{
	_nVifUnpack(idx, data, vifXRegs.mode, isFill);
}

template void dVifUnpack<0>(const u8* data, bool isFill);
template void dVifUnpack<1>(const u8* data, bool isFill);

// No JIT state exists to serialise.
bool SaveStateBase::vuJITFreeze()
{
	return true;
}

// Only reachable from the fastmem fault handler, which never runs without executable code memory.
void vtlb_DynBackpatchLoadStore(uptr, u32, u32, u32, u32, u32, u8, u8, u8, bool, bool, bool)
{
	std::abort();
}
