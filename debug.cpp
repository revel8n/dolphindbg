// Copyright (C) 2014 oct0xor
// 
// This program is free software : you can redistribute it and / or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, version 2.0.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
// GNU General Public License 2.0 for more details.
// 
// A copy of the GPL 2.0 should have been included with the program.
// If not, see http ://www.gnu.org/licenses/

#define _WINSOCKAPI_

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <iostream>
#include <algorithm>
#include <vector>
#include <string>
#include <unordered_map>
#include <set>

#include <ida.hpp>
#include <area.hpp>
#include <ua.hpp>
#include <nalt.hpp>
#include <idd.hpp>
#include <segment.hpp>
#include <dbg.hpp>
#include <allins.hpp>

#include "debmod.h"

#include "gdb.h"

#ifdef _DEBUG
#define debug_printf ::msg
#else
#define debug_printf(...)
#endif

#define DEBUGGER_NAME "dolphin"
#define DEBUGGER_ID (0x8003)
#define PROCESSOR_NAME "ppc"

static error_t idaapi idc_threadlst(idc_value_t *argv, idc_value_t *res);
void get_threads_info(void);
void clear_all_bp(uint32 tid);
uint32 read_pc_register(uint32 tid);
uint32 read_lr_register(uint32 tid);
uint32 read_ctr_register(uint32 tid);
int do_step(uint32 tid, uint32 dbg_notification);
bool addr_has_bp(uint32 ea);

static const char idc_threadlst_args[] = {0};

uint32 ProcessID;
uint32 ThreadID;

bool LaunchTargetPicker = true;
bool AlwaysDC = false;
bool ForceDC = true;
bool WasOriginallyConnected = false;

static bool attaching = false; 
static bool singlestep = false;
static bool continue_from_bp = false;
static bool dabr_is_set = false;
uint32 dabr_addr;
uint8 dabr_type;

eventlist_t events;

std::unordered_map<int, std::string> process_names;
std::unordered_map<int, std::string> modules;
std::unordered_map<int, int> main_bpts_map;

std::set<uint32> step_bpts;
std::set<uint32> main_bpts;

static const unsigned char bpt_code[] = {0x7f, 0xe0, 0x00, 0x08};

#define STEP_INTO 15
#define STEP_OVER 16

#define RC_GENERAL 1
#define RC_FLOAT   2
#define RC_VECTOR  4

enum RegisterIndexType
{
    REF_INDEX_PC = 32,
    REF_INDEX_LR = 34,
    REF_INDEX_CTR = 35,
};


struct regval
{
    uint64 lval;
    uint64 rval;
};
typedef struct regval regval;

//--------------------------------------------------------------------------
const char* register_classes[] =
{
    "General registers",
    "Floating point registers",
    "Paired singles registers",
    NULL
};

static const char *const CReg[] =
{
    "cr7",
    "cr7",
    "cr7",
    "cr7",
    "cr6",
    "cr6",
    "cr6",
    "cr6",
    "cr5",
    "cr5",
    "cr5",
    "cr5",
    "cr4",
    "cr4",
    "cr4",
    "cr4",
    "cr3",
    "cr3",
    "cr3",
    "cr3",
    "cr2",
    "cr2",
    "cr2",
    "cr2",
    "cr1",
    "cr1",
    "cr1",
    "cr1",
    "cr0",
    "cr0",
    "cr0",
    "cr0",
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
};

//--------------------------------------------------------------------------
const char* register_formats[] =
{
    "ps2_2_doubles",
    NULL
};

//--------------------------------------------------------------------------
register_info_t registers[] =
{
    { "r0",     REGISTER_ADDRESS,               RC_GENERAL,  dt_dword,  NULL,   0 },
    { "r1",     REGISTER_ADDRESS | REGISTER_SP, RC_GENERAL,  dt_dword,  NULL,   0 },
    { "r2",     REGISTER_ADDRESS,               RC_GENERAL,  dt_dword,  NULL,   0 },
    { "r3",     REGISTER_ADDRESS,               RC_GENERAL,  dt_dword,  NULL,   0 },
    { "r4",     REGISTER_ADDRESS,               RC_GENERAL,  dt_dword,  NULL,   0 },
    { "r5",     REGISTER_ADDRESS,               RC_GENERAL,  dt_dword,  NULL,   0 },
    { "r6",     REGISTER_ADDRESS,               RC_GENERAL,  dt_dword,  NULL,   0 },
    { "r7",     REGISTER_ADDRESS,               RC_GENERAL,  dt_dword,  NULL,   0 },
    { "r8",     REGISTER_ADDRESS,               RC_GENERAL,  dt_dword,  NULL,   0 },
    { "r9",     REGISTER_ADDRESS,               RC_GENERAL,  dt_dword,  NULL,   0 },
    { "r10",    REGISTER_ADDRESS,               RC_GENERAL,  dt_dword,  NULL,   0 },
    { "r11",    REGISTER_ADDRESS,               RC_GENERAL,  dt_dword,  NULL,   0 },
    { "r12",    REGISTER_ADDRESS,               RC_GENERAL,  dt_dword,  NULL,   0 },
    { "r13",    REGISTER_ADDRESS,               RC_GENERAL,  dt_dword,  NULL,   0 },
    { "r14",    REGISTER_ADDRESS,               RC_GENERAL,  dt_dword,  NULL,   0 },
    { "r15",    REGISTER_ADDRESS,               RC_GENERAL,  dt_dword,  NULL,   0 },
    { "r16",    REGISTER_ADDRESS,               RC_GENERAL,  dt_dword,  NULL,   0 },
    { "r17",    REGISTER_ADDRESS,               RC_GENERAL,  dt_dword,  NULL,   0 },
    { "r18",    REGISTER_ADDRESS,               RC_GENERAL,  dt_dword,  NULL,   0 },
    { "r19",    REGISTER_ADDRESS,               RC_GENERAL,  dt_dword,  NULL,   0 },
    { "r20",    REGISTER_ADDRESS,               RC_GENERAL,  dt_dword,  NULL,   0 },
    { "r21",    REGISTER_ADDRESS,               RC_GENERAL,  dt_dword,  NULL,   0 },
    { "r22",    REGISTER_ADDRESS,               RC_GENERAL,  dt_dword,  NULL,   0 },
    { "r23",    REGISTER_ADDRESS,               RC_GENERAL,  dt_dword,  NULL,   0 },
    { "r24",    REGISTER_ADDRESS,               RC_GENERAL,  dt_dword,  NULL,   0 },
    { "r25",    REGISTER_ADDRESS,               RC_GENERAL,  dt_dword,  NULL,   0 },
    { "r26",    REGISTER_ADDRESS,               RC_GENERAL,  dt_dword,  NULL,   0 },
    { "r27",    REGISTER_ADDRESS,               RC_GENERAL,  dt_dword,  NULL,   0 },
    { "r28",    REGISTER_ADDRESS,               RC_GENERAL,  dt_dword,  NULL,   0 },
    { "r29",    REGISTER_ADDRESS,               RC_GENERAL,  dt_dword,  NULL,   0 },
    { "r30",    REGISTER_ADDRESS,               RC_GENERAL,  dt_dword,  NULL,   0 },
    { "r31",    REGISTER_ADDRESS,               RC_GENERAL,  dt_dword,  NULL,   0 },

    { "PC",     REGISTER_ADDRESS | REGISTER_IP, RC_GENERAL,  dt_dword,  NULL,   0 },
    { "CR",     NULL,							RC_GENERAL,  dt_dword,  CReg,   0xFFFFFFFF },
    //{ "CR",     NULL,							  RC_GENERAL,  dt_qword,  NULL,   0 },
    { "LR",     REGISTER_ADDRESS,               RC_GENERAL,  dt_dword,  NULL,   0 },
    { "CTR",    REGISTER_ADDRESS,               RC_GENERAL,  dt_dword,  NULL,   0 },
    { "MSR",    REGISTER_READONLY,				RC_GENERAL,  dt_dword,  NULL,   0 },
    { "XER",    REGISTER_READONLY,              RC_GENERAL,  dt_dword,  NULL,   0 },
    { "UNK",    REGISTER_READONLY,              RC_GENERAL,  dt_dword,  NULL,   0 },
    { "FPCSR",  REGISTER_READONLY,              RC_GENERAL,  dt_dword,  NULL,   0 },

    { "f0",     NULL,							RC_FLOAT,    dt_double,  NULL,   0 },
    { "f1",     NULL,							RC_FLOAT,    dt_double,  NULL,   0 },
    { "f2",     NULL,							RC_FLOAT,    dt_double,  NULL,   0 },
    { "f3",     NULL,							RC_FLOAT,    dt_double,  NULL,   0 },
    { "f4",     NULL,							RC_FLOAT,    dt_double,  NULL,   0 },
    { "f5",     NULL,							RC_FLOAT,    dt_double,  NULL,   0 },
    { "f6",     NULL,							RC_FLOAT,    dt_double,  NULL,   0 },
    { "f7",     NULL,							RC_FLOAT,    dt_double,  NULL,   0 },
    { "f8",     NULL,							RC_FLOAT,    dt_double,  NULL,   0 },
    { "f9",     NULL,							RC_FLOAT,    dt_double,  NULL,   0 },
    { "f10",    NULL,							RC_FLOAT,    dt_double,  NULL,   0 },
    { "f11",    NULL,							RC_FLOAT,    dt_double,  NULL,   0 },
    { "f12",    NULL,							RC_FLOAT,    dt_double,  NULL,   0 },
    { "f13",    NULL,							RC_FLOAT,    dt_double,  NULL,   0 },
    { "f14",    NULL,							RC_FLOAT,    dt_double,  NULL,   0 },
    { "f15",    NULL,							RC_FLOAT,    dt_double,  NULL,   0 },
    { "f16",    NULL,							RC_FLOAT,    dt_double,  NULL,   0 },
    { "f17",    NULL,							RC_FLOAT,    dt_double,  NULL,   0 },
    { "f18",    NULL,							RC_FLOAT,    dt_double,  NULL,   0 },
    { "f19",    NULL,							RC_FLOAT,    dt_double,  NULL,   0 },
    { "f20",    NULL,							RC_FLOAT,    dt_double,  NULL,   0 },
    { "f21",    NULL,							RC_FLOAT,    dt_double,  NULL,   0 },
    { "f22",    NULL,							RC_FLOAT,    dt_double,  NULL,   0 },
    { "f23",    NULL,							RC_FLOAT,    dt_double,  NULL,   0 },
    { "f24",    NULL,							RC_FLOAT,    dt_double,  NULL,   0 },
    { "f25",    NULL,							RC_FLOAT,    dt_double,  NULL,   0 },
    { "f26",    NULL,							RC_FLOAT,    dt_double,  NULL,   0 },
    { "f27",    NULL,							RC_FLOAT,    dt_double,  NULL,   0 },
    { "f28",    NULL,							RC_FLOAT,    dt_double,  NULL,   0 },
    { "f29",    NULL,							RC_FLOAT,    dt_double,  NULL,   0 },
    { "f30",    NULL,							RC_FLOAT,    dt_double,  NULL,   0 },
    { "f31",    NULL,							RC_FLOAT,    dt_double,  NULL,   0 },

    { "fr0",   REGISTER_CUSTFMT,				RC_VECTOR,   dt_byte16, register_formats,   0 },
    { "fr1",   REGISTER_CUSTFMT,				RC_VECTOR,   dt_byte16, register_formats,   0 },
    { "fr2",   REGISTER_CUSTFMT,				RC_VECTOR,   dt_byte16, register_formats,   0 },
    { "fr3",   REGISTER_CUSTFMT,				RC_VECTOR,   dt_byte16, register_formats,   0 },
    { "fr4",   REGISTER_CUSTFMT,				RC_VECTOR,   dt_byte16, register_formats,   0 },
    { "fr5",   REGISTER_CUSTFMT,				RC_VECTOR,   dt_byte16, register_formats,   0 },
    { "fr6",   REGISTER_CUSTFMT,				RC_VECTOR,   dt_byte16, register_formats,   0 },
    { "fr7",   REGISTER_CUSTFMT,				RC_VECTOR,   dt_byte16, register_formats,   0 },
    { "fr8",   REGISTER_CUSTFMT,				RC_VECTOR,   dt_byte16, register_formats,   0 },
    { "fr9",   REGISTER_CUSTFMT,				RC_VECTOR,   dt_byte16, register_formats,   0 },
    { "fr10",  REGISTER_CUSTFMT,				RC_VECTOR,   dt_byte16, register_formats,   0 },
    { "fr11",  REGISTER_CUSTFMT,				RC_VECTOR,   dt_byte16, register_formats,   0 },
    { "fr12",  REGISTER_CUSTFMT,				RC_VECTOR,   dt_byte16, register_formats,   0 },
    { "fr13",  REGISTER_CUSTFMT,				RC_VECTOR,   dt_byte16, register_formats,   0 },
    { "fr14",  REGISTER_CUSTFMT,				RC_VECTOR,   dt_byte16, register_formats,   0 },
    { "fr15",  REGISTER_CUSTFMT,				RC_VECTOR,   dt_byte16, register_formats,   0 },
    { "fr16",  REGISTER_CUSTFMT,				RC_VECTOR,   dt_byte16, register_formats,   0 },
    { "fr17",  REGISTER_CUSTFMT,				RC_VECTOR,   dt_byte16, register_formats,   0 },
    { "fr18",  REGISTER_CUSTFMT,				RC_VECTOR,   dt_byte16, register_formats,   0 },
    { "fr19",  REGISTER_CUSTFMT,				RC_VECTOR,   dt_byte16, register_formats,   0 },
    { "fr20",  REGISTER_CUSTFMT,				RC_VECTOR,   dt_byte16, register_formats,   0 },
    { "fr21",  REGISTER_CUSTFMT,				RC_VECTOR,   dt_byte16, register_formats,   0 },
    { "fr22",  REGISTER_CUSTFMT,				RC_VECTOR,   dt_byte16, register_formats,   0 },
    { "fr23",  REGISTER_CUSTFMT,				RC_VECTOR,   dt_byte16, register_formats,   0 },
    { "fr24",  REGISTER_CUSTFMT,				RC_VECTOR,   dt_byte16, register_formats,   0 },
    { "fr25",  REGISTER_CUSTFMT,				RC_VECTOR,   dt_byte16, register_formats,   0 },
    { "fr26",  REGISTER_CUSTFMT,				RC_VECTOR,   dt_byte16, register_formats,   0 },
    { "fr27",  REGISTER_CUSTFMT,				RC_VECTOR,   dt_byte16, register_formats,   0 },
    { "fr28",  REGISTER_CUSTFMT,				RC_VECTOR,   dt_byte16, register_formats,   0 },
    { "fr29",  REGISTER_CUSTFMT,				RC_VECTOR,   dt_byte16, register_formats,   0 },
    { "fr30",  REGISTER_CUSTFMT,				RC_VECTOR,   dt_byte16, register_formats,   0 },
    { "fr31",  REGISTER_CUSTFMT,				RC_VECTOR,   dt_byte16, register_formats,   0 }
};

uint32 register_ids[] =
{
    0,  // gpr_0,
    1,  // gpr_1,
    2,  // gpr_2,
    3,  // gpr_3,
    4,  // gpr_4,
    5,  // gpr_5,
    6,  // gpr_6,
    7,  // gpr_7,
    8,  // gpr_8,
    9,  // gpr_9,
    10, // gpr_10,
    11, // gpr_11,
    12, // gpr_12,
    13, // gpr_13,
    14, // gpr_14,
    15, // gpr_15,
    16, // gpr_16,
    17, // gpr_17,
    18, // gpr_18,
    19, // gpr_19,
    20, // gpr_20,
    21, // gpr_21,
    22, // gpr_22,
    23, // gpr_23,
    24, // gpr_24,
    25, // gpr_25,
    26, // gpr_26,
    27, // gpr_27,
    28, // gpr_28,
    29, // gpr_29,
    30, // gpr_30,
    31, // gpr_31,

    64, // pc,
    66, // cr,
    67, // lr,
    68, // ctr,
    65, // msr,
    69, // xer,
    70, // 0x0BADC0DE
    71, // fpscr

    32 + 0,  // fpr_0,
    32 + 1,  // fpr_1,
    32 + 2,  // fpr_2,
    32 + 3,  // fpr_3,
    32 + 4,  // fpr_4,
    32 + 5,  // fpr_5,
    32 + 6,  // fpr_6,
    32 + 7,  // fpr_7,
    32 + 8,  // fpr_8,
    32 + 9,  // fpr_9,
    32 + 10, // fpr_10,
    32 + 11, // fpr_11,
    32 + 12, // fpr_12,
    32 + 13, // fpr_13,
    32 + 14, // fpr_14,
    32 + 15, // fpr_15,
    32 + 16, // fpr_16,
    32 + 17, // fpr_17,
    32 + 18, // fpr_18,
    32 + 19, // fpr_19,
    32 + 20, // fpr_20,
    32 + 21, // fpr_21,
    32 + 22, // fpr_22,
    32 + 23, // fpr_23,
    32 + 24, // fpr_24,
    32 + 25, // fpr_25,
    32 + 26, // fpr_26,
    32 + 27, // fpr_27,
    32 + 28, // fpr_28,
    32 + 29, // fpr_29,
    32 + 30, // fpr_30,
    32 + 31, // fpr_31,

    32 + 0,  // psr_0,
    32 + 1,  // psr_1,
    32 + 2,  // psr_2,
    32 + 3,  // psr_3,
    32 + 4,  // psr_4,
    32 + 5,  // psr_5,
    32 + 6,  // psr_6,
    32 + 7,  // psr_7,
    32 + 8,  // psr_8,
    32 + 9,  // psr_9,
    32 + 10, // psr_10,
    32 + 11, // psr_11,
    32 + 12, // psr_12,
    32 + 13, // psr_13,
    32 + 14, // psr_14,
    32 + 15, // psr_15,
    32 + 16, // psr_16,
    32 + 17, // psr_17,
    32 + 18, // psr_18,
    32 + 19, // psr_19,
    32 + 20, // psr_20,
    32 + 21, // psr_21,
    32 + 22, // psr_22,
    32 + 23, // psr_23,
    32 + 24, // psr_24,
    32 + 25, // psr_25,
    32 + 26, // psr_26,
    32 + 27, // psr_27,
    32 + 28, // psr_28,
    32 + 29, // psr_29,
    32 + 30, // psr_30,
    32 + 31, // psr_31
};

void setup_registers()
{
}

//-------------------------------------------------------------------------
static inline uint32 bswap32(uint32 x)
{
    return ( (x << 24) & 0xff000000 ) |
           ( (x <<  8) & 0x00ff0000 ) |
           ( (x >>  8) & 0x0000ff00 ) |
           ( (x >> 24) & 0x000000ff );
}

static inline uint64 bswap64(uint64 x)
{
    return ( (x << 56) & 0xff00000000000000ULL ) |
           ( (x << 40) & 0x00ff000000000000ULL ) |
           ( (x << 24) & 0x0000ff0000000000ULL ) |
           ( (x <<  8) & 0x000000ff00000000ULL ) |
           ( (x >>  8) & 0x00000000ff000000ULL ) |
           ( (x >> 24) & 0x0000000000ff0000ULL ) |
           ( (x >> 40) & 0x000000000000ff00ULL ) |
           ( (x >> 56) & 0x00000000000000ffULL );
}

bool GetHostnames(const char* input, std::string& ipOut, std::string& dnsNameOut)
{
    WSADATA wsaData;
    int iResult;

    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        return false;
    }

    sockaddr_in remotemachine;
    char hostname[NI_MAXHOST];

    remotemachine.sin_family = AF_INET;
    remotemachine.sin_addr.s_addr = inet_addr(input);

    // IP->Hostname
    DWORD dwRetVal = getnameinfo((SOCKADDR *)&remotemachine, 
        sizeof(sockaddr), 
        hostname, 
        NI_MAXHOST, 
        NULL, 
        0, 
        NI_NAMEREQD);

    if (dwRetVal == 0)
    {
        dnsNameOut = hostname;
        return true;
    }

    // Hostname -> IP
    struct hostent *remoteHost;
    remoteHost = gethostbyname(input);

    int i = 0;
    struct in_addr addr = { 0 };
    if (remoteHost && remoteHost->h_addrtype == AF_INET)
    {
        if (remoteHost->h_addr_list[0] != 0)
        {
            addr.s_addr = *(u_long *) remoteHost->h_addr_list[0];
            ipOut = inet_ntoa(addr);
            return true;
        }
    }

    WSACleanup();
    return false;
}

static void handle_events(u32 signal, u32 pc, u32 address)
{
    debug_printf("handle_events\n");

    debug_event_t ev;

    switch (signal)
    {
    case SIGABRT:
        {
            if (attaching)
            {
                debug_printf("dolphin_DBG_EVENT_PROCESS_START\n");

                attaching = false;

                ev.eid     = PROCESS_START;
                ev.pid     = ProcessID;
                ev.tid     = NO_THREAD;
                ev.ea      = BADADDR;
                ev.handled = true;

                qstrncpy(ev.modinfo.name, "dolphin", sizeof(ev.modinfo.name));
                ev.modinfo.base = 0x100000;
                ev.modinfo.size = 0;
                ev.modinfo.rebase_to = BADADDR;

                events.enqueue(ev, IN_BACK);

                ev.eid     = PROCESS_SUSPEND;
                ev.pid     = ProcessID;

                events.enqueue(ev, IN_BACK);

                break;
            }
        }
        break;
    case SIGSEGV:
    case SIGTERM:
        {
            debug_printf("dolphin_DBG_EVENT_PROCESS_EXIT\n");

            ev.eid     = PROCESS_EXIT;
            ev.pid     = ProcessID;
            ev.tid     = NO_THREAD;
            ev.ea      = BADADDR;
            ev.handled = true;
            ev.exit_code = 0;

            events.enqueue(ev, IN_BACK);
        }
        break;
    case SIGSTOP:
        {
            debug_printf("dolphin_DBG_EVENT_PROCESS_SUSPEND\n");

            ev.eid = PROCESS_SUSPEND;
            ev.pid = ProcessID;
            ev.tid = ThreadID;
            ev.ea = pc;
            ev.handled = true;
            ev.exit_code = 0;

            events.enqueue(ev, IN_BACK);
        }
        break;
    case SIGCONT:
        {
            debug_printf("dolphin_DBG_EVENT_PROCESS_CONTINUE\n");

            ev.eid = NO_EVENT;
            ev.pid = ProcessID;
            ev.tid = ThreadID;
            ev.ea = pc;
            ev.handled = true;
            ev.exit_code = 0;

            events.enqueue(ev, IN_BACK);
        }
        break;
    case SIGTRAP:
        {
            debug_printf("dolphin_DBG_EVENT_TRAP\n");

            if (continue_from_bp == true)
            {
                debug_printf("\tContinuing from breakpoint...\n");
                continue_from_bp = false;
            }
            else if (BADADDR != address)
            {
                debug_printf("\tData breakpoint...\n");

                ev.eid = BREAKPOINT;
                ev.pid = ProcessID;
                ev.tid = ThreadID;
                ev.ea = pc;
                ev.handled = true;
                ev.bpt.hea = address;
                ev.bpt.kea = BADADDR;
                ev.exc.ea = BADADDR;

                events.enqueue(ev, IN_BACK);
            }
            else if (singlestep == true)
            {
                debug_printf("\tSingle step...\n");

                ev.eid     = STEP;
                ev.pid     = ProcessID;
                ev.tid     = ThreadID;
                ev.ea      = pc;
                ev.handled = true;
                ev.exc.code = 0;
                ev.exc.can_cont = true;
                ev.exc.ea = BADADDR;

                events.enqueue(ev, IN_BACK);

                continue_from_bp = false;
                singlestep = false;
            }
            else if (!addr_has_bp(pc))
            {
                ev.eid     = PROCESS_SUSPEND;
                ev.pid     = ProcessID;
                ev.tid     = ThreadID;
                ev.ea      = pc;
                ev.handled = true;

                events.enqueue(ev, IN_BACK);
            }
            else
            {
                debug_printf("\tBreakpoint...\n");

                ev.eid     = BREAKPOINT;
                ev.pid     = ProcessID;
                ev.tid     = ThreadID;
                ev.ea      = pc;
                ev.handled = true;
                ev.bpt.hea = BADADDR;
                ev.bpt.kea = BADADDR;
                ev.exc.ea  = BADADDR;

                events.enqueue(ev, IN_BACK);
            }

            for (std::set<uint32>::const_iterator step_it = step_bpts.begin(); step_it != step_bpts.end(); ++step_it)
            {
                uint32 addr = *step_it;

                if (!addr_has_bp(addr))
                {
                    main_bpts_map.erase(addr);

                    gdb_remove_bp(addr, GDB_BP_TYPE_X, 4);
                    debug_printf("step bpt cleared: 0x%08X\n", (uint32)addr);
                }
            }
            step_bpts.clear();
        }
        break;
    default:
        debug_printf("Unknown event signal: 0x%08X\n");
        break;
    }
}

//--------------------------------------------------------------------------
// Initialize debugger
static bool idaapi init_debugger(const char *hostname, int port_num, const char *password)
{
    debug_printf("init_debugger\n");

    if (!gdb_init(port_num))
        return false;

    set_idc_func_ex("threadlst", idc_threadlst, idc_threadlst_args, 0);

    return true;
}

//--------------------------------------------------------------------------
// Terminate debugger
static bool idaapi term_debugger(void)
{
    debug_printf("term_debugger\n");

    gdb_deinit();

    set_idc_func_ex("threadlst", NULL, idc_threadlst_args, 0);

    return true;
}

//--------------------------------------------------------------------------
int idaapi process_get_info(int n, process_info_t *info)
{
    if (n > 0)
        return 0;

    info->pid = 0;
    qstrncpy(info->name, "dolphin", sizeof(info->name));

    return 1;
}

static error_t idaapi idc_threadlst(idc_value_t *argv, idc_value_t *res)
{
    get_threads_info();
    return eOk;
}

void get_threads_info(void)
{
    debug_printf("get_threads_info\n");

    if (attaching == true) 
    {
        debug_event_t ev;

        attaching = false;

        ThreadID = 1;

        ev.eid     = THREAD_START;
        ev.pid     = ProcessID;
        ev.tid     = ThreadID;
        ev.ea      = read_pc_register(ThreadID);
        ev.handled = true;

        events.enqueue(ev, IN_BACK);

        clear_all_bp(0);

        // set break point on current instruction
        //gdb_add_bp(ev.ea, GDB_BP_TYPE_X, 4);
        //step_bpts.insert(ev.ea);
    }
}

void get_modules_info(void)
{
}

void clear_all_bp(uint32 tid)
{
}

void bp_list(void)
{
}

bool addr_has_bp(uint32 ea)
{
    return (main_bpts.end() != main_bpts.find(ea));
}

//--------------------------------------------------------------------------
// Start an executable to debug
static int idaapi deci3_start_process(const char *path,
                              const char *args,
                              const char *startdir,
                              int dbg_proc_flags,
                              const char *input_path,
                              uint32 input_file_crc32)
{
    //uint64 tid;

    debug_printf("start_process\n");
    debug_printf("path: %s\n", path);

    ProcessID = 0;

    attaching = true;

    debug_event_t ev;

    ev.eid     = PROCESS_START;
    ev.pid     = ProcessID;
    ev.tid     = NO_THREAD;
    ev.ea      = BADADDR;
    ev.handled = true;

    qstrncpy(ev.modinfo.name, "dolphin", sizeof(ev.modinfo.name));
    ev.modinfo.base = 0x100000;
    ev.modinfo.size = 0;
    ev.modinfo.rebase_to = BADADDR;

    events.enqueue(ev, IN_BACK);

    get_threads_info();
    get_modules_info();
    clear_all_bp(-1);

    gdb_handle_events(handle_events);

    gdb_continue();

/*
    ev.eid     = PROCESS_SUSPEND;
    ev.pid     = ProcessID;

    events.enqueue(ev, IN_BACK);

    gdb_handle_events(handle_events);
*/

    debug_printf("ProcessID: 0x%X\n", ProcessID);

    /*debug_event_t ev;
    ev.eid     = PROCESS_START;
    ev.pid     = ProcessID;
    ev.tid     = NO_THREAD;
    ev.ea      = BADADDR;
    ev.handled = true;

    qstrncpy(ev.modinfo.name, path, sizeof(ev.modinfo.name));
    ev.modinfo.base = 0x10200;
    ev.modinfo.size = 0;
    ev.modinfo.rebase_to = BADADDR;

    events.enqueue(ev, IN_BACK);*/

    return 1;
}

//--------------------------------------------------------------------------
// Attach to an existing running process
int idaapi deci3_attach_process(pid_t pid, int event_id)
{
    debug_printf("deci3_attach_process\n");

    // block the process until all generated events are processed
    attaching = true;

    ProcessID = pid;

    process_names[ProcessID] = "dolphin";

    debug_event_t ev;
    ev.eid     = PROCESS_START;
    ev.pid     = ProcessID;
    ev.tid     = NO_THREAD;
    ev.ea      = BADADDR;
    ev.handled = true;

    qstrncpy(ev.modinfo.name, process_names[ProcessID].c_str(), sizeof(ev.modinfo.name));
    ev.modinfo.base = 0x100000;
    ev.modinfo.size = 0;
    ev.modinfo.rebase_to = BADADDR;

    events.enqueue(ev, IN_BACK);

    get_threads_info();
    get_modules_info();
    clear_all_bp(-1);

    ev.eid     = PROCESS_ATTACH;
    ev.pid     = ProcessID;
    ev.tid     = NO_THREAD;
    ev.ea      = BADADDR;
    ev.handled = true;

    qstrncpy(ev.modinfo.name, process_names[ProcessID].c_str(), sizeof(ev.modinfo.name));
    ev.modinfo.base = 0x100000;
    ev.modinfo.size = 0;
    ev.modinfo.rebase_to = BADADDR;

    events.enqueue(ev, IN_BACK);

    process_names.clear();

    return 1;
}

//--------------------------------------------------------------------------
int idaapi deci3_detach_process(void)
{
    debug_printf("deci3_detach_process\n");

    gdb_handle_events(handle_events);

    gdb_continue();

    gdb_deinit();

    debug_event_t ev;
    ev.eid     = PROCESS_DETACH;
    ev.pid     = ProcessID;

    events.enqueue(ev, IN_BACK);

    return 1;
}

//-------------------------------------------------------------------------
void idaapi rebase_if_required_to(ea_t new_base)
{
    debug_printf("rebase_if_required_to: 0x%llX\n", (uint64)new_base);
}

//--------------------------------------------------------------------------
int idaapi prepare_to_pause_process(void)
{
    debug_printf("prepare_to_pause_process\n");

    //gdb_pause();

    debug_event_t ev;
    ev.eid     = PROCESS_SUSPEND;
    ev.pid     = ProcessID;

    events.enqueue(ev, IN_BACK);

    return 1;
}

//--------------------------------------------------------------------------
int idaapi deci3_exit_process(void)
{
    debug_printf("deci3_exit_process\n");

    gdb_handle_events(handle_events);

    gdb_kill();

    debug_event_t ev;
    ev.eid     = PROCESS_EXIT;
    ev.pid     = ProcessID;
    ev.tid     = NO_THREAD;
    ev.ea      = BADADDR;
    ev.exit_code = 0;
    ev.handled = true;

    events.enqueue(ev, IN_BACK);

    return 1;
}

#ifdef _DEBUG

static const char *get_event_name(event_id_t id)
{
    switch ( id )
    {
        case NO_EVENT:        return "NO_EVENT";
        case THREAD_START:    return "THREAD_START";
        case THREAD_EXIT:     return "THREAD_EXIT";
        case PROCESS_ATTACH:  return "PROCESS_ATTACH";
        case PROCESS_DETACH:  return "PROCESS_DETACH";
        case PROCESS_START:   return "PROCESS_START";
        case PROCESS_SUSPEND: return "PROCESS_SUSPEND";
        case PROCESS_EXIT:    return "PROCESS_EXIT";
        case LIBRARY_LOAD:    return "LIBRARY_LOAD";
        case LIBRARY_UNLOAD:  return "LIBRARY_UNLOAD";
        case BREAKPOINT:      return "BREAKPOINT";
        case STEP:            return "STEP";
        case EXCEPTION:       return "EXCEPTION";
        case INFORMATION:     return "INFORMATION";
        case SYSCALL:         return "SYSCALL";
        case WINMESSAGE:      return "WINMESSAGE";
        default:              return "???";
    }
}

#endif

//--------------------------------------------------------------------------
// Get a pending debug event and suspend the process
gdecode_t idaapi get_debug_event(debug_event_t *event, int ida_is_idle)
{
    if ( event == NULL )
        return GDE_NO_EVENT;

    while ( true )
    {
        gdb_handle_events(handle_events);

        if ( events.retrieve(event) )
        {
#ifdef _DEBUG

            if (event->eid == BREAKPOINT && event->bpt.hea != BADADDR)
            {
                debug_printf("get_debug_event: BREAKPOINT (HW)\n");
            }
            else
            {
                debug_printf("get_debug_event: %s\n", get_event_name(event->eid));
            }

#endif

            if (event->eid == PROCESS_ATTACH)
            {
                attaching = false;
            }

            if (attaching == false) 
            {
            }

            return (events.empty()) ? GDE_ONE_EVENT : GDE_MANY_EVENTS;
        }

        if (events.empty())
            break;
    }

    if (attaching == false)
    {
    }

    return GDE_NO_EVENT;
}

//--------------------------------------------------------------------------
// Continue after handling the event
int idaapi continue_after_event(const debug_event_t *event)
{
    if ( event == NULL )
        return false;

    if (!events.empty())
        return true;

#ifdef _DEBUG

    if (event->eid == BREAKPOINT && event->bpt.hea != BADADDR)
    {
        debug_printf("continue_after_event: BREAKPOINT (HW)\n");
    }
    else
    {
        debug_printf("continue_after_event: %s\n", get_event_name(event->eid));
    }

#endif

    gdb_handle_events(handle_events);

    switch (event->eid)
    {
    case PROCESS_ATTACH:
    case PROCESS_SUSPEND:
    case STEP:
    case BREAKPOINT:
    case NO_EVENT:
        gdb_continue();
        break;
    default:
        break;
    } 

    return true;
}

//--------------------------------------------------------------------------
void idaapi stopped_at_debug_event(bool dlls_added)
{
}

//--------------------------------------------------------------------------
int idaapi thread_suspend(thid_t tid)
{
    debug_printf("thread_suspend: tid = 0x%llX\n", (uint64)tid);

    gdb_handle_events(handle_events);

    gdb_pause();

    return 1;
}

//--------------------------------------------------------------------------
int idaapi thread_continue(thid_t tid)
{
    debug_printf("thread_continue: tid = 0x%llX\n", (uint64)tid);

    gdb_handle_events(handle_events);

    gdb_continue();

    return 1;
}

#define G_STR_SIZE 256

enum spu_instructions
{
    SPU_a  =   58,
    SPU_absdb  =   150,
    SPU_addx  =   108,
    SPU_ah  =   76,
    SPU_ahi  =   9,
    SPU_ai  =   8,
    SPU_and  =   70,
    SPU_andbi  =   7,
    SPU_andc  =   59,
    SPU_andhi  =   6,
    SPU_andi  =   5,
    SPU_avgb  =   84,
    SPU_bg  =   41,
    SPU_bgx  =   97,
    SPU_bi  =   109,
    SPU_bihnz  =   93,
    SPU_bihz  =   92,
    SPU_binz  =   91,
    SPU_bisl  =   110,
    SPU_bisled  =   112,
    SPU_biz  =   90,
    SPU_br  =   171,
    SPU_bra  =   166,
    SPU_brasl  =   169,
    SPU_brhnz  =   163,
    SPU_brhz  =   161,
    SPU_brnz  =   159,
    SPU_brsl  =   172,
    SPU_brz  =   157,
    SPU_cbd  =   180,
    SPU_cbx  =   139,
    SPU_cdd  =   183,
    SPU_cdx  =   142,
    SPU_ceq  =   124,
    SPU_ceqb  =   138,
    SPU_ceqbi  =   27,
    SPU_ceqh  =   131,
    SPU_ceqhi  =   26,
    SPU_ceqi  =   25,
    SPU_cflts  =   195,
    SPU_cfltu  =   196,
    SPU_cg  =   60,
    SPU_cgt  =   39,
    SPU_cgtb  =   44,
    SPU_cgtbi  =   17,
    SPU_cgth  =   42,
    SPU_cgthi  =   16,
    SPU_cgti  =   15,
    SPU_cgx  =   96,
    SPU_chd  =   181,
    SPU_chx  =   140,
    SPU_clgt  =   69,
    SPU_clgtb  =   83,
    SPU_clgtbi  =   21,
    SPU_clgth  =   65,
    SPU_clgthi  =   20,
    SPU_clgti  =   19,
    SPU_clz  =   62,
    SPU_cntb  =   66,
    SPU_csflt  =   197,
    SPU_cuflt  =   198,
    SPU_cwd  =   182,
    SPU_cwx  =   141,
    SPU_dfa  =   80,
    SPU_dfceq  =   126,
    SPU_dfcgt  =   72,
    SPU_dfcmeq  =   133,
    SPU_dfcmgt  =   79,
    SPU_dfm  =   82,
    SPU_dfma  =   101,
    SPU_dfms  =   102,
    SPU_dfnma  =   104,
    SPU_dfnms  =   103,
    SPU_dfs  =   81,
    SPU_dftsv  =   178,
    SPU_dsync  =   32,
    SPU_eqv  =   43,
    SPU_fa  =   73,
    SPU_fceq  =   125,
    SPU_fcgt  =   71,
    SPU_fcmeq  =   132,
    SPU_fcmgt  =   78,
    SPU_fesd  =   45,
    SPU_fi  =   86,
    SPU_fm  =   75,
    SPU_fma  =   155,
    SPU_fms  =   156,
    SPU_fnms  =   154,
    SPU_frds  =   47,
    SPU_frest  =   121,
    SPU_frsqest  =   122,
    SPU_fs  =   74,
    SPU_fscrrd  =   107,
    SPU_fscrwr  =   123,
    SPU_fsm  =   117,
    SPU_fsmb  =   119,
    SPU_fsmbi  =   162,
    SPU_fsmh  =   118,
    SPU_gb  =   114,
    SPU_gbb  =   116,
    SPU_gbh  =   115,
    SPU_hbr  =   113,
    SPU_hbra  =   192,
    SPU_hbrr  =   194,
    SPU_heq  =   89,
    SPU_heqi  =   28,
    SPU_hgt  =   37,
    SPU_hgti  =   18,
    SPU_hlgt  =   85,
    SPU_hlgti  =   22,
    SPU_il  =   165,
    SPU_ila  =   193,
    SPU_ilh  =   160,
    SPU_ilhu  =   173,
    SPU_iohl  =   167,
    SPU_iret  =   111,
    SPU_lnop  =   30,
    SPU_lqa  =   170,
    SPU_lqd  =   11,
    SPU_lqr  =   168,
    SPU_lqx  =   127,
    SPU_lr  =   199,
    SPU_mfspr  =   34,
    SPU_mpy  =   61,
    SPU_mpya  =   153,
    SPU_mpyh  =   128,
    SPU_mpyhh  =   129,
    SPU_mpyhha  =   99,
    SPU_mpyhhau  =   100,
    SPU_mpyhhu  =   136,
    SPU_mpyi  =   23,
    SPU_mpys  =   130,
    SPU_mpyu  =   38,
    SPU_mpyui  =   24,
    SPU_mtspr  =   87,
    SPU_nand  =   68,
    SPU_nop  =   33,
    SPU_nor  =   120,
    SPU_or  =   40,
    SPU_orbi  =   2,
    SPU_orc  =   77,
    SPU_orhi  =   1,
    SPU_ori  =   0,
    SPU_orx  =   149,
    SPU_rchcnt  =   36,
    SPU_rdch  =   35,
    SPU_rot  =   48,
    SPU_roth  =   52,
    SPU_rothi  =   188,
    SPU_rothm  =   53,
    SPU_rothmi  =   189,
    SPU_roti  =   184,
    SPU_rotm  =   49,
    SPU_rotma  =   50,
    SPU_rotmah  =   54,
    SPU_rotmahi  =   190,
    SPU_rotmai  =   186,
    SPU_rotmi  =   185,
    SPU_rotqbi  =   143,
    SPU_rotqbii  =   179,
    SPU_rotqby  =   146,
    SPU_rotqbybi  =   134,
    SPU_rotqbyi  =   176,
    SPU_rotqmbi  =   144,
    SPU_rotqmbii  =   174,
    SPU_rotqmby  =   147,
    SPU_rotqmbybi  =   135,
    SPU_rotqmbyi  =   177,
    SPU_selb  =   151,
    SPU_sf  =   105,
    SPU_sfh  =   56,
    SPU_sfhi  =   4,
    SPU_sfi  =   3,
    SPU_sfx  =   95,
    SPU_shl  =   51,
    SPU_shlh  =   55,
    SPU_shlhi  =   57,
    SPU_shli  =   187,
    SPU_shlqbi  =   145,
    SPU_shlqbii  =   191,
    SPU_shlqby  =   148,
    SPU_shlqbybi  =   137,
    SPU_shlqbyi  =   175,
    SPU_shufb  =   152,
    SPU_stop  =   29,
    SPU_stopd  =   94,
    SPU_stqa  =   158,
    SPU_stqd  =   10,
    SPU_stqr  =   164,
    SPU_stqx  =   98,
    SPU_sumb  =   46,
    SPU_sync  =   31,
    SPU_wrch  =   88,
    SPU_xor  =   106,
    SPU_xorbi  =   14,
    SPU_xorhi  =   13,
    SPU_xori  =   12,
    SPU_xsbh  =   67,
    SPU_xshw  =   64,
    itype_xswd  =   63,
};

//-------------------------------------------------------------------------
ea_t get_branch_target(uint32 tid, insn_t insn_cmd, int operand, bool& link)
{
    link = (0x08 == insn_cmd.auxpref_chars.low);

    // PPC plugin uses IDP specific values instead of relevant enumerations
    if ((0x0B == insn_cmd.Operands[0].type ||
        0x0C == insn_cmd.Operands[0].type) &&
        0x08 == insn_cmd.Operands[1].type)
    {
        switch (insn_cmd.Operands[1].value_shorts.low)
        {
        case 0x08:
            return read_lr_register(tid);
        case 0x09:
            return read_ctr_register(tid);
        }
    }

    if (0 <= operand)
    {
        return insn_cmd.Operands[operand].addr;
    }

    return BADADDR;
}

int do_step(uint32 tid, uint32 dbg_notification)
{
    debug_printf("do_step\n");

    char mnem[G_STR_SIZE] = {0};

    gdb_handle_events(handle_events);

    ea_t ea = read_pc_register(tid);

    mnem[0] = 0;

    bool unconditional_noret = false;

    bool step_over = (STEP_OVER == dbg_notification);
    bool link = false;
    ea_t next_addr = ea + 4;
    ea_t resolved_addr = BADADDR;
    if (decode_insn(ea))
    {
        insn_t l_cmd = cmd;
        switch (l_cmd.itype)
        {
        case PPC_balways:
        {
            resolved_addr = get_branch_target(tid, l_cmd, -1, link);
            if (!link)
            {
                unconditional_noret = true;
                next_addr = resolved_addr;
                resolved_addr = BADADDR;
            }
        }
        break;
        case PPC_bc:         // Branch Conditional
        {
            resolved_addr = get_branch_target(tid, l_cmd, 2, link); //l_cmd.Op3.addr;
            step_over = step_over && link;
        }
        break;
        case PPC_bdnz:       // CTR--; branch if CTR non-zero
        case PPC_bdz:        // CTR--; branch if CTR zero
        case PPC_blt:        // Branch if less than
        case PPC_ble:        // Branch if less than or equal
        case PPC_beq:        // Branch if equal
        case PPC_bge:        // Branch if greater than or equal
        case PPC_bgt:        // Branch if greater than
        case PPC_bne:        // Branch if not equal
        {
            resolved_addr = get_branch_target(tid, l_cmd, 1, link); //l_cmd.Op2.addr;
            step_over = step_over && link;
        }
        break;
        case PPC_b:          // Branch
        {
            resolved_addr = get_branch_target(tid, l_cmd, 0, link); //l_cmd.Op1.addr;
            if (!link)
            {
                unconditional_noret = true;
                next_addr = resolved_addr;
                resolved_addr = BADADDR;
            }
        }
        break;
        case PPC_bcctr:      // Branch Conditional to Count Register
        {
            resolved_addr = get_branch_target(tid, l_cmd, -1, link); //read_ctr_register(tid);
        }
        break;
        case PPC_bclr:       // Branch Conditional to Link Register
        {
            resolved_addr = get_branch_target(tid, l_cmd, -1, link); //read_lr_register(tid);
        }
        break;
        default:
        {
        }
        break;
        }

        // get mnemonic
        //ua_mnem(ea, mnem, sizeof(mnem));

        generate_disasm_line(ea, mnem, sizeof(mnem));
        tag_remove(mnem, mnem, sizeof(mnem));

        char* next_start = mnem;
        qstrtok(mnem, " ", &next_start);

        debug_printf("do_step:\n");
        debug_printf("\tnext address: %08X - resolved address: %08X - decoded mnemonic: %s - decoded itype: 0x%04X\n", next_addr, resolved_addr, mnem, l_cmd.itype);
    }

    uint32 instruction;
    if (BADADDR != next_addr && (BADADDR == resolved_addr || !unconditional_noret))
    {
        gdb_add_bp(next_addr, GDB_BP_TYPE_X, 4);
        step_bpts.insert(next_addr);
    }

    if (BADADDR != resolved_addr && (unconditional_noret || !step_over))
    {
        gdb_add_bp(resolved_addr, GDB_BP_TYPE_X, 4);
        step_bpts.insert(resolved_addr);
    }

    return 1;
}

//--------------------------------------------------------------------------
// Run one instruction in the thread
int idaapi thread_set_step(thid_t tid)
{
    debug_printf("thread_set_step\n");

    int dbg_notification;
    int result = 0;

    dbg_notification = get_running_notification();

    if (dbg_notification == STEP_INTO || dbg_notification == STEP_OVER)
    {
        result = do_step(tid, dbg_notification);
        singlestep = true;
    }

    return result;
}

//-------------------------------------------------------------------------
uint32 read_pc_register(uint32 tid) 
{
    gdb_handle_events(handle_events);

    u64 reg[2];
    gdb_read_register(register_ids[REF_INDEX_PC], reg);

    return reg[0];
}

//-------------------------------------------------------------------------
uint32 read_lr_register(uint32 tid)
{
    gdb_handle_events(handle_events);

    u64 reg[2];
    gdb_read_register(register_ids[REF_INDEX_LR], reg);

    return reg[0];
}

//-------------------------------------------------------------------------
uint32 read_ctr_register(uint32 tid)
{
    gdb_handle_events(handle_events);

    u64 reg[2];
    gdb_read_register(register_ids[REF_INDEX_CTR], reg);

    return reg[0];
}

void set_register_value(char dtyp, regval_t& reg, const u64 values[2])
{
    switch (dtyp)
    {
    case dt_dword:
    case dt_qword:
    case dt_float:
    case dt_double:
    {
        reg.ival = values[0];
    }
    break;

    case dt_byte16:
    {
        reg.set_bytes((u8*)values, 16);
    }
    break;

    default:
        break;
    }
}

void get_register_value(char dtyp, const regval_t& reg, u64 values[2])
{
    switch (dtyp)
    {
    case dt_dword:
    case dt_qword:
    case dt_float:
    case dt_double:
    {
        values[0] = reg.ival;
    }
    break;

    case dt_byte16:
    {
        memcpy(values, reg.get_data(), 16);
    }
    break;

    default:
        break;
    }
}

//--------------------------------------------------------------------------
// Read thread registers
int idaapi read_registers(thid_t tid, int clsmask, regval_t *values)
{
    if ( values == NULL ) 
    {
        debug_printf("NULL ptr detected !\n");
        return 0;
    }

    debug_printf("read_registers\n");

    gdb_handle_events(handle_events);

    context regs = { 0 };
    gdb_read_registers(regs);

    for (u32 i = 0; i <= qnumber(registers); ++i)
    {
        if (0 == (clsmask & registers[i].register_class))
            continue;

        u32 id = register_ids[i];
        u64 v[2] = { 0 };

        if (0 <= id && id <= 31)
        {
            v[0] = regs.gpr[id];
        }
        else if (32 <= id && id <= 63)
        {
            v[0] = regs.fpr[id - 32][0];
            v[1] = regs.fpr[id - 32][1];
        }
        else
        {
            switch (id)
            {
            case 64:
                v[0] = regs.pc;
                break;
            case 65:
                v[0] = regs.msr;
                break;
            case 66:
                v[0] = regs.cr;
                break;
            case 67:
                v[0] = regs.lr;
                break;
            case 68:
                v[0] = regs.ctr;
                break;
            case 69:
                v[0] = regs.xer;
                break;
            case 70:
                v[0] = regs.unk;
                break;
            case 71:
                v[0] = regs.fpscr;
                break;
            }
        }

        set_register_value(registers[i].dtyp, values[i], v);
    }

    return 1;
}

//--------------------------------------------------------------------------
// Write one thread register
int idaapi write_register(thid_t tid, int reg_idx, const regval_t *value)
{
    debug_printf("write_register\n");

    // zero register should be read only
    if (0 == reg_idx || GPR_COUNT == reg_idx)
        return 0;

    u64 reg[2] = {0};
    const int reg_id = register_ids[reg_idx];
    const int reg_type = registers[reg_idx].dtyp;

    gdb_handle_events(handle_events);

    gdb_read_register(reg_id, reg);

    get_register_value(reg_type, *value, reg);

    gdb_write_register(reg_id, reg);

    return 1;
}

//--------------------------------------------------------------------------
// Get information on the memory areas
// The debugger module fills 'areas'. The returned vector MUST be sorted.
// Returns:
//   -3: use idb segmentation
//   -2: no changes
//   -1: the process does not exist anymore
//    0: failed
//    1: new memory layout is returned
int idaapi get_memory_info(meminfo_vec_t &areas)
{
    debug_printf("get_memory_info\n");

    memory_info_t info;

    info.startEA = 0;
    info.endEA = 0; // 0xFFFF0000;
    info.name = NULL;
    info.sclass = NULL;
    info.sbase = 0;
    info.bitness = 1;
    info.perm = 0; // SEGPERM_EXEC / SEGPERM_WRITE / SEGPERM_READ
    
    areas.push_back(info);

    return -3;
}

//--------------------------------------------------------------------------
// Read process memory
ssize_t idaapi read_memory(ea_t ea, void *buffer, size_t size)
{
    debug_printf("read_memory\n");

    gdb_handle_events(handle_events);

    return gdb_read_mem(ea, (u8*)buffer, size);
}

//--------------------------------------------------------------------------
// Write process memory
ssize_t idaapi write_memory(ea_t ea, const void *buffer, size_t size)
{
    debug_printf("write_memory\n");

    gdb_handle_events(handle_events);

    return gdb_write_mem(ea, (u8*)buffer, size);
}

//--------------------------------------------------------------------------
int idaapi is_ok_bpt(bpttype_t type, ea_t ea, int len)
{
    debug_printf("is_ok_bpt\n");

    switch(type)
    {
        case BPT_SOFT:
            {
                debug_printf("Software breakpoint\n");

                return BPT_OK;
            }
            break;

        case BPT_EXEC:
            {
                debug_printf("Execute instruction\n");

                return BPT_OK;
            }
            break;

        case BPT_WRITE:
            {
                debug_printf("Write access\n");

                return BPT_OK;

                /*if (len != 8)
                {
                    msg("Hardware breakpoints must be 8 bytes long\n");
                    return BPT_BAD_LEN;
                }*/
                
/*
                if (ea % 8 != 0)
                {
                    msg("Hardware breakpoints must be 8 byte aligned\n");
                    return BPT_BAD_ALIGN;
                }
                
                if (dabr_is_set == false)
                {
                    //dabr_is_set is not set yet bug
                    return BPT_OK;
                }
                else
                {
                    msg("It's possible to set a single hardware breakpoint\n");
                    return BPT_TOO_MANY;
                }
*/
            }
            break;

            // No read access?

        case BPT_RDWR:
            {
                debug_printf("Read/write access\n");

                return BPT_OK;

                /*if (len != 8)
                {
                    msg("Hardware breakpoints must be 8 bytes long\n");
                    return BPT_BAD_LEN;
                }*/

/*
                if (ea % 8 != 0)
                {
                    msg("Hardware breakpoints must be 8 byte aligned\n");
                    return BPT_BAD_ALIGN;
                }

                if (dabr_is_set == false)
                {
                    //dabr_is_set is not set yet bug
                    return BPT_OK;
                }
                else
                {
                    msg("It's possible to set a single hardware breakpoint\n");
                    return BPT_TOO_MANY;
                }
*/
            }
            break;

        default:
            debug_printf("Unsupported BP type !\n");
            return BPT_BAD_TYPE;
    }

}

//--------------------------------------------------------------------------
int idaapi update_bpts(update_bpt_info_t *bpts, int nadd, int ndel)
{
    debug_printf("update_bpts - add: %d - del: %d\n", (uint32)nadd, (uint32)ndel);

    int i;
    //std::vector<uint32>::iterator it;
    uint32 orig_inst = -1;
    uint32 BPCount;
    int cnt = 0;

    //debug_printf("BreakPoints sum: %d\n", BPCount);

    //bp_list();

    gdb_handle_events(handle_events);

    for (i = 0; i < ndel; i++)
    {
        debug_printf("del_bpt: type: %d, ea: 0x%llX, code: %d\n", (uint32)bpts[nadd + i].type, (uint64)bpts[nadd + i].ea, (uint32)bpts[nadd + i].code);

        bpts[nadd + i].code = BPT_OK;
        cnt++;

        switch(bpts[nadd + i].type)
        {
        case BPT_SOFT:
            {
                debug_printf("Software breakpoint\n");

                gdb_remove_bp(bpts[nadd + i].ea, GDB_BP_TYPE_X, bpts[nadd + i].size);

                main_bpts.erase(bpts[nadd + i].ea);

                main_bpts_map.erase(bpts[nadd + i].ea);
            }
            break;

        case BPT_EXEC:
            {
                debug_printf("Execute breakpoint\n");

                gdb_remove_bp(bpts[nadd + i].ea, GDB_BP_TYPE_X, bpts[nadd + i].size);

                main_bpts.erase(bpts[nadd + i].ea);

                main_bpts_map.erase(bpts[nadd + i].ea);
            }
            break;

        case BPT_WRITE:
            {
                debug_printf("Write access\n");

                gdb_remove_bp(bpts[nadd + i].ea, GDB_BP_TYPE_W, bpts[nadd + i].size);

                main_bpts.erase(bpts[nadd + i].ea);

                main_bpts_map.erase(bpts[nadd + i].ea);
            }
            break;

        case BPT_RDWR:
            {
                debug_printf("Read/write access\n");

                gdb_remove_bp(bpts[nadd + i].ea, GDB_BP_TYPE_A, bpts[nadd + i].size);

                main_bpts.erase(bpts[nadd + i].ea);

                main_bpts_map.erase(bpts[nadd + i].ea);
            }
            break;
        }
    }

    for (i = 0; i < nadd; i++)
    {
        if (bpts[i].code != BPT_OK)
            continue;

        debug_printf("add_bpt: type: %d, ea: 0x%llX, code: %d, size: %d\n", (uint32)bpts[i].type, (uint64)bpts[i].ea, (uint32)bpts[i].code, (uint32)bpts[i].size);

        //BPT_SKIP

        switch(bpts[i].type)
        {
        case BPT_SOFT:
            {
                debug_printf("Software breakpoint\n");

                gdb_add_bp(bpts[i].ea, GDB_BP_TYPE_X, bpts[i].size);

                bpts[i].code = BPT_OK;

                main_bpts.insert(bpts[i].ea);

                // NOTE: Software breakpoints require "original bytes" data
                gdb_read_mem(bpts[i].ea, (u8*)&orig_inst, sizeof(orig_inst));

                bpts[i].orgbytes.qclear();
                bpts[i].orgbytes.append(&orig_inst,  sizeof(orig_inst));

                cnt++;
            }
            break;

        case BPT_EXEC:
            {
                debug_printf("Execute instruction\n");

                gdb_add_bp(bpts[i].ea, GDB_BP_TYPE_X, bpts[i].size);

                bpts[i].code = BPT_OK;

                main_bpts.insert(bpts[i].ea);

                cnt++;
            }
            break;

        case BPT_WRITE:
            {
                debug_printf("Write access\n");

                gdb_add_bp(bpts[i].ea, GDB_BP_TYPE_W, bpts[i].size);

                bpts[i].code = BPT_OK;

                main_bpts.insert(bpts[i].ea);

                cnt++;
            }
            break;

            // No read access?

        case BPT_RDWR:
            {
                debug_printf("Read/write access\n");

                gdb_add_bp(bpts[i].ea, GDB_BP_TYPE_A, bpts[i].size);

                bpts[i].code = BPT_OK;

                main_bpts.insert(bpts[i].ea);

                cnt++;
            }
            break;

        default:
            debug_printf("Unsupported BP type !\n");
            break;
        }
    }

    //debug_printf("BreakPoints sum: %d\n", BPCount);

    //bp_list();

    return cnt;
}

//--------------------------------------------------------------------------
// Map process address
ea_t idaapi map_address(ea_t off, const regval_t *regs, int regnum)
{
    //debug_printf("map_address\n");

    if (regs == NULL)
    {
        return off;
    }

    if (regnum >= 0)
    {
        if (regnum < GPR_COUNT)
        {
            return regs[regnum].ival & 0xFFFFFFFF;
        }
    }

    return BADADDR;
}

//-------------------------------------------------------------------------
int idaapi send_ioctl(int fn, const void *buf, size_t size, void **poutbuf, ssize_t *poutsize)
{
    return 0;
}

//--------------------------------------------------------------------------
//
//      DEBUGGER DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
debugger_t debugger =
{
    IDD_INTERFACE_VERSION,
    DEBUGGER_NAME,				// Short debugger name
    DEBUGGER_ID,	// Debugger API module id
    PROCESSOR_NAME,				// Required processor name
    DBG_FLAG_REMOTE | DBG_FLAG_NOHOST | DBG_FLAG_NEEDPORT | DBG_FLAG_CAN_CONT_BPT | DBG_FLAG_NOSTARTDIR | DBG_FLAG_NOPARAMETERS | DBG_FLAG_NOPASSWORD | DBG_FLAG_DEBTHREAD,

    register_classes,			// Array of register class names
    RC_GENERAL,					// Mask of default printed register classes
    registers,					// Array of registers
    qnumber(registers),			// Number of registers

    0x1000,						// Size of a memory page

    bpt_code,				    // Array of bytes for a breakpoint instruction
    qnumber(bpt_code),			// Size of this array
    0,							// for miniidbs: use this value for the file type after attaching
    0,							// reserved

    init_debugger,
    term_debugger,

    process_get_info,
    deci3_start_process,
    deci3_attach_process,
    deci3_detach_process,
    rebase_if_required_to,
    prepare_to_pause_process,
    deci3_exit_process,

    get_debug_event,
    continue_after_event,
    NULL, //set_exception_info,
    stopped_at_debug_event,

    thread_suspend,
    thread_continue,
    thread_set_step,
    read_registers,
    write_register,
    NULL, //thread_get_sreg_base

    get_memory_info,
    read_memory,
    write_memory,

    is_ok_bpt,
    update_bpts,
    NULL, //update_lowcnds
    NULL, //open_file
    NULL, //close_file
    NULL, //read_file
    map_address,
    NULL, //set_dbg_options
    NULL, //get_debmod_extensions
    NULL, //update_call_stack
    NULL, //appcall
    NULL, //cleanup_appcall
    NULL, //eval_lowcnd
    NULL, //write_file
    send_ioctl,
};
