// Copyright 2010 fail0verflow <master@fail0verflow.com>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt


#include "types.h"

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#ifdef _WIN32
#define _WINSOCKAPI_
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <iphlpapi.h>
#else
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif
#include <stdarg.h>

#include <dbg.hpp>

#include "gdb.h"

#undef dbgprintf
#ifndef _DEBUG
#define dbgprintf(...)
#else
#define dbgprintf ::msg
#endif

#define		GDB_BFR_MAX	10000
#define		GDB_MAX_BP	10

#define		GDB_STUB_START	'$'
#define		GDB_STUB_END	'#'
#define		GDB_STUB_ACK	'+'
#define		GDB_STUB_NAK	'-'

static int sock = -1;
static struct sockaddr_in saddr_server, saddr_client;

static u8 cmd_bfr[GDB_BFR_MAX + 1];
static u32 cmd_len;

static u32 sig = 0;
static u32 send_signal = 0;

typedef struct
{
    u32 active;
    u32 addr;
    u32 len;
} gdb_bp_t;

static gdb_bp_t bp_x[GDB_MAX_BP];
static gdb_bp_t bp_r[GDB_MAX_BP];
static gdb_bp_t bp_w[GDB_MAX_BP];
static gdb_bp_t bp_a[GDB_MAX_BP];

bool fail(const char *a, ...)
{
    char msg[1024];
    va_list va;

    va_start(va, a);
    vsnprintf_s(msg, 1024, sizeof msg, a, va);
    perror(msg);

    dbgprintf(msg);

#ifdef FAIL_DUMP_REGS
    dump_regs();
#endif

#ifdef FAIL_DUMP_LS
    dump_ls();
#endif

    gdb_deinit();
    //exit(1);

    return false;
}

// private helpers
static u8 hex2char(u8 hex)
{
    if (hex >= '0' && hex <= '9')
        return hex - '0';
    else if (hex >= 'a' && hex <= 'f')
        return hex - 'a' + 0xa;
    else if (hex >= 'A' && hex <= 'F')
        return hex - 'A' + 0xa;

    printf("Invalid nibble: %c (%02x)\n", hex, hex);
    return 0;
}

static u8 nibble2hex(u8 n)
{
    n &= 0xf;
    if (n < 0xa)
        return '0' + n;
    else
        return 'A' + n - 0xa;
}

static void mem2hex(u8 *dst, u8 *src, u32 len)
{
    u8 tmp;

    while (len-- > 0)
    {
        tmp = *src++;
        *dst++ = nibble2hex(tmp>>4);
        *dst++ = nibble2hex(tmp);
    }
}

static void hex2mem(u8 *dst, u8 *src, u32 len)
{
    while (len-- > 0)
    {
        *dst = hex2char(*src++) << 4;
        *dst++ |= hex2char(*src++);
    }
}

static void wbe32hex(u8 *p, u32 v)
{
    u32 i;

    for (i = 0; i < 8; i++)
        p[i] =  nibble2hex(v >> (28 - 4*i));
}

static void wbe64hex(u8 *p, u64 v)
{
    u32 i;
    for (i = 0; i < 16; i++)
        p[i] = nibble2hex(u8(v >> (60 - 4 * i)));
}

static void wle32hex(u8 *p, u32 v)
{
    u32 i;

    for (i = 0; i < 8; i++)
        p[i] = nibble2hex(u8(v >> (4 * (i ^ 1))));
}

static void wle64hex(u8 *p, u64 v)
{
    u32 i;

    for (i = 0; i < 16; i++)
        p[i] = nibble2hex(u8(v >> (4 * (i ^ 1))));
}

static u32 rbe32hex(u8 *p)
{
    u32 i;
    u32 res = 0;

    for (i = 0; i < 8; i++)
        res = (res << 4) | hex2char(p[i]);

    return res;
}

static u64 rbe64hex(u8 *p)
{
    u32 i;
    u64 res = 0;

    for (i = 0; i < 16; i++)
        res = (res << 4) | hex2char(p[i]);

    return res;
}

static u32 rle32hex(u8 *p)
{
    u32 i;
    u32 res = 0;

    for (i = 0; i < 8; i++)
        res = (res) | (hex2char(p[i]) << (4 * (i ^ 1)));

    return res;
}

static u32 rle64hex(u8 *p)
{
    u32 i;
    u32 res = 0;

    for (i = 0; i < 16; i++)
        res = (res) | (hex2char(p[i]) << (4 * (i ^ 1)));

    return res;
}

static u8 gdb_read_byte(void)
{
    size_t res;
    u8 c = '+';

    res = recv(sock, (char*)&c, 1, MSG_WAITALL);
    if (res != 1)
        return fail("recv failed\n");

    return c;
}

static u8 gdb_calc_chksum(void)
{
    u32 len = cmd_len;
    u8 *ptr = cmd_bfr;
    u8 c = 0;

    while(len-- > 0)
        c += *ptr++;

    return c;
}

static gdb_bp_t *gdb_bp_ptr(u32 type)
{
    switch (type)
    {
        case GDB_BP_TYPE_X:
            return bp_x;
        case GDB_BP_TYPE_R:
            return bp_r;
        case GDB_BP_TYPE_W:
            return bp_w;
        case GDB_BP_TYPE_A:
            return bp_a;
        default:
            return NULL;
    }
}

static gdb_bp_t *gdb_bp_empty_slot(u32 type)
{
    gdb_bp_t *p;
    u32 i;

    p = gdb_bp_ptr(type);
    if (p == NULL)
        return NULL;

    for (i = 0; i < GDB_MAX_BP; i++)
    {
        if (p[i].active == 0)
            return &p[i];
    }

    return NULL;
}

static gdb_bp_t *gdb_bp_find(u32 type, u32 addr, u32 len)
{
    gdb_bp_t *p;
    u32 i;

    p = gdb_bp_ptr(type);
    if (p == NULL)
        return NULL;

    for (i = 0; i < GDB_MAX_BP; i++)
    {
        if (p[i].active == 1 &&
            p[i].addr == addr &&
            p[i].len == len)
            return &p[i];
    }

    return NULL;
}

static void gdb_bp_remove(u32 type, u32 addr, u32 len)
{
    gdb_bp_t *p;

    do
    {
        p = gdb_bp_find(type, addr, len);
        if (p != NULL)
        {
            dbgprintf("gdb: remvoed a breakpoint: %08x bytes at %08x\n", len, addr);
            p->active = 0;
            memset(p, 0, sizeof p);
        }
    } while (p != NULL);
}

static int gdb_bp_check(u32 addr, u32 type)
{
    gdb_bp_t *p;
    u32 i;

    p = gdb_bp_ptr(type);
    if (p == NULL)
        return 0;

    for (i = 0; i < GDB_MAX_BP; i++)
    {
        if (p[i].active == 1 &&
            (addr >= p[i].addr && addr < p[i].addr + p[i].len))
            return 1;
    }

    return 0;
}

static void gdb_nak(void)
{
    const char nak = GDB_STUB_NAK;
    size_t res;

    res = send(sock, &nak, 1, 0);
    if (res != 1)
        fail("send failed");
}

static void gdb_ack(void)
{
    const char ack = GDB_STUB_ACK;
    size_t res;

    res = send(sock, &ack, 1, 0);
    if (res != 1)
        fail("send failed");
}

static bool gdb_read_command(void)
{
    u8 c;
    u8 chk_read, chk_calc;

    cmd_len = 0;
    memset(cmd_bfr, 0, sizeof cmd_bfr);

    c = gdb_read_byte();

    if (c == GDB_STUB_ACK ||
        c == GDB_STUB_NAK)
    {
        cmd_bfr[cmd_len++] = c;
        dbgprintf("gdb: read command %c with a length of %d: %s\n", cmd_bfr[0], cmd_len, cmd_bfr);
        return true;
    }

    if (c != GDB_STUB_START)
    {
        dbgprintf("gdb: read invalid byte %02x\n", c);
        return false;
    }

    while ((c = gdb_read_byte()) != GDB_STUB_END)
    {
        cmd_bfr[cmd_len++] = c;
        if (cmd_len == sizeof cmd_bfr)
            return fail("gdb: cmd_bfr overflow\n");
    }

    chk_read = hex2char(gdb_read_byte()) << 4;
    chk_read |= hex2char(gdb_read_byte());

    chk_calc = gdb_calc_chksum();

    if (chk_calc != chk_read)
    {
        dbgprintf("gdb: invalid checksum: calculated %02x and read %02x for $%s# (length: %d)\n", chk_calc, chk_read, cmd_bfr, cmd_len);
        cmd_len = 0;
    
        gdb_nak();

        return false;
    }

    dbgprintf("gdb: read command %c with a length of %d: %s\n", cmd_bfr[0], cmd_len, cmd_bfr);

    return true;
}

static int gdb_data_available(void)
{
    struct timeval t;
    fd_set _fds, *fds = &_fds;
    
    FD_ZERO(fds);
    FD_SET(sock, fds);

    t.tv_sec = 0;
    t.tv_usec = 2000;

    if (select(sock + 1, fds, NULL, NULL, &t) < 0)
        return fail("select failed\n");

    if (FD_ISSET(sock, fds))
        return 1;
    return 0;
}

static void gdb_reply(const char *reply)
{
    if (sock == -1)
        return;

    u8 chk;
    u32 left;
    u8 *ptr;
    int n;

    memset(cmd_bfr, 0, sizeof cmd_bfr);

    cmd_len = strlen(reply);
    if (cmd_len + 4 > sizeof cmd_bfr)
    {
        fail("cmd_bfr overflow in gdb_reply\n");
        return;
    }

    memcpy(cmd_bfr + 1, reply, cmd_len);

    cmd_len++;
    chk = gdb_calc_chksum();
    cmd_len--;
    cmd_bfr[0] = GDB_STUB_START;
    cmd_bfr[cmd_len + 1] = GDB_STUB_END;
    cmd_bfr[cmd_len + 2] = nibble2hex(chk >> 4);
    cmd_bfr[cmd_len + 3] = nibble2hex(chk);

    dbgprintf("gdb: reply (len: %d): %s\n", cmd_len, cmd_bfr);

    ptr = cmd_bfr;
    left = cmd_len + 4;
    while ((int)left > 0)
    {
        n = send(sock, (char*)ptr, left, 0);
        dbgprintf("gdb: reply (sent: %d of %d)\n", n, cmd_len);
        if (n < 0)
        {
            fail("gdb: send failed\n");
            return;
        }
        left -= n;
        ptr += n;
    }
}

static void gdb_handle_query(void)
{
    dbgprintf("gdb: query '%s'\n", cmd_bfr+1);
    gdb_ack();
    gdb_reply("");
}

static void gdb_handle_set_thread(void)
{
    gdb_ack();
    if (memcmp(cmd_bfr, "Hg0", 3) == 0 ||
        memcmp(cmd_bfr, "Hc-1", 4) == 0)
        return gdb_reply("OK");
    gdb_reply("E01");
}

static void gdb_handle_signal(event_callback* callback)
{
    dbgprintf("gdb_handle_signal\n");

    u32 sig = 0;

    sig = hex2char(cmd_bfr[1]) << 4;
    sig |= hex2char(cmd_bfr[2]);

    u32 reg_id = rbe32hex(cmd_bfr + 3);
    u32 reg_value = rbe32hex(cmd_bfr + 12);

    u32 addr = -1;

    // data read breakpoint
    if (0 == qstrcmp("rwatch", (const char*)&cmd_bfr[21]))
    {
       addr = rbe32hex(cmd_bfr + 28);
    }
    // data write breakpoint
    else if (0 == qstrcmp("watch", (const char*)&cmd_bfr[21]))
    {
        addr = rbe32hex(cmd_bfr + 27);
    }
    // data read/write breakpoint
    else if (0 == qstrcmp("awatch", (const char*)&cmd_bfr[21]))
    {
        addr = rbe32hex(cmd_bfr + 28);
    }

    if (0 != callback)
    {
        callback(sig, reg_value, addr);
    }
}

void gdb_read_registers(context& regs)
{
    u8 reply[4] = {0};

    //memset(reply, 0, sizeof reply);

    reply[0] = 'g';

    gdb_reply((char *)reply);

    // read ack/nak
    gdb_read_command();
    // read register values
    gdb_read_command();

    u8 * bufptr = cmd_bfr;

    for (u32 id = 0; id <= 71; ++id)
    {
        if (0 <= id && id <= 31)
        {
            regs.gpr[id] = rbe32hex(bufptr);
            bufptr += 8;
        }
        else if (32 <= id && id <= 63)
        {
            regs.fpr[(id - 32)][1] = rbe64hex(bufptr);
            bufptr += 16;
            regs.fpr[(id - 32)][0] = rbe64hex(bufptr);
            bufptr += 16;
        }
        else
        {
            switch (id)
            {
            case 64:
                regs.pc = rbe32hex(bufptr);
                bufptr += 8;
                break;
            case 65:
                regs.msr = rbe32hex(bufptr);
                bufptr += 8;
                break;
            case 66:
                regs.cr = rbe32hex(bufptr);
                bufptr += 8;
                break;
            case 67:
                regs.lr = rbe32hex(bufptr);
                bufptr += 8;
                break;
            case 68:
                regs.ctr = rbe32hex(bufptr);
                bufptr += 8;
                break;
            case 69:
                regs.xer = rbe32hex(bufptr);
                bufptr += 8;
                break;
            case 70:
                // do nothing, we don't have MQ
                regs.unk = rbe32hex(bufptr);
                bufptr += 8;
                break;
            case 71:
                regs.fpscr = rbe32hex(bufptr);
                bufptr += 8;
                break;
            }
        }
    }
}

void gdb_write_registers(context& regs)
{
    u8 reply[GDB_BFR_MAX - 4];

    memset(reply, 0, sizeof reply);

    reply[0] = 'G';

    u8* bufptr = reply + 1;

    for (u32 id = 0; id <= 71; ++id)
    {
        if (0 <= id && id <= 31)
        {
            wbe32hex(bufptr, regs.gpr[id]);
            bufptr += 8;
        }
        else if (32 <= id && id <= 63)
        {
            wbe64hex(bufptr, regs.fpr[(id - 32)][1]);
            bufptr += 16;
            wbe64hex(bufptr, regs.fpr[(id - 32)][0]);
            bufptr += 16;
        }
        else
        {
            switch (id)
            {
            case 64:
                wbe32hex(bufptr, regs.pc);
                bufptr += 8;
                break;
            case 65:
                wbe32hex(bufptr, regs.msr);
                bufptr += 8;
                break;
            case 66:
                wbe32hex(bufptr, regs.cr);
                bufptr += 8;
                break;
            case 67:
                wbe32hex(bufptr, regs.lr);
                bufptr += 8;
                break;
            case 68:
                wbe32hex(bufptr, regs.ctr);
                bufptr += 8;
                break;
            case 69:
                wbe32hex(bufptr, regs.xer);
                bufptr += 8;
                break;
            case 70:
                wbe32hex(bufptr, 0x0BADC0DE);
                bufptr += 8;
                break;
            case 71:
                wbe32hex(bufptr, regs.fpscr);
                bufptr += 8;
                break;
            }
        }
    }

    gdb_reply((char *)reply);

    // read ack/nak
    gdb_read_command();
    // read OK/E##
    gdb_read_command();
}

void gdb_read_register(u32 id, u64 reg[2])
{
    u8 reply[64] = { 0 };

    reply[0] = 'p';
    reply[1] = nibble2hex(id >> 4);
    reply[2] = nibble2hex(id);

    gdb_reply((char *)reply);

    // read ack/nak
    gdb_read_command();
    // read register value
    gdb_read_command();

    u8 * bufptr = cmd_bfr;

    if (0 <= id && id <= 31)
    {
        reg[1] = 0;
        reg[0] = rbe32hex(bufptr);
    }
    else if (32 <= id && id <= 63)
    {
        reg[1] = rbe64hex(bufptr);
        reg[0] = rbe64hex(bufptr + 16);
    }
    else
    {
        switch (id)
        {
        case 64:
            reg[1] = 0;
            reg[0] = rbe32hex(bufptr);
            break;
        case 65:
            reg[1] = 0;
            reg[0] = rbe32hex(bufptr);
            break;
        case 66:
            reg[1] = 0;
            reg[0] = rbe32hex(bufptr);
            break;
        case 67:
            reg[1] = 0;
            reg[0] = rbe32hex(bufptr);
            break;
        case 68:
            reg[1] = 0;
            reg[0] = rbe32hex(bufptr);
            break;
        case 69:
            reg[1] = 0;
            reg[0] = rbe32hex(bufptr);
            break;
        case 70:
            reg[1] = 0;
            reg[0] = rbe32hex(bufptr);
            break;
        case 71:
            reg[1] = 0;
            reg[0] = rbe32hex(bufptr);
            break;
        default:
            return gdb_reply("E01");
            break;
        }
    }
}

void gdb_write_register(u32 id, u64 reg[2])
{
    u8 reply[64] = { 0 };

    if (id > 127 && id != 129)
        return;

    reply[0] = 'P';
    reply[1] = nibble2hex(id >> 4);
    reply[2] = nibble2hex(id);
    reply[3] = '=';

    u8* bufptr = reply + 4;

    if (0 <= id && id <= 31)
    {
        wbe32hex(bufptr, (u32)reg[0]);
    }
    else if (32 <= id && id <= 63)
    {
        wbe64hex(bufptr, reg[1]);
        wbe64hex(bufptr + 16, reg[0]);
    }
    else
    {
        switch (id)
        {
        case 64:
            wbe32hex(bufptr, (u32)reg[0]);
            break;
        case 65:
            wbe32hex(bufptr, (u32)reg[0]);
            break;
        case 66:
            wbe32hex(bufptr, (u32)reg[0]);
            break;
        case 67:
            wbe32hex(bufptr, (u32)reg[0]);
            break;
        case 68:
            wbe32hex(bufptr, (u32)reg[0]);
            break;
        case 69:
            wbe32hex(bufptr, (u32)reg[0]);
            break;
        case 70:
            return;
            break;
        case 71:
            wbe32hex(bufptr, (u32)reg[0]);
            break;
        default:
            return;
            break;
        }
    }

    gdb_reply((char *)reply);

    // read ack/nak
    gdb_read_command();
    // read OK/E##
    gdb_read_command();
}

u32 gdb_read_mem(u32 addr, u8* buffer, u32 size)
{
    u8 reply[32] = { 0 };

    reply[0] = 'm';
    wbe32hex(reply + 1, addr);
    reply[9] = ',';
    wbe32hex(reply + 10, size);

    gdb_reply((char *)reply);

    // read ack/nak
    gdb_read_command();
    // read OK/E##/""
    gdb_read_command();

    u32 length = min(cmd_len, size);

    if (length > 0)
    {
        hex2mem(buffer, cmd_bfr, length);
    }

    return length;
}

u32 gdb_write_mem(u32 addr, u8* buffer, u32 size)
{
    u8 reply[GDB_BFR_MAX - 4] = { 0 };

    u32 length = min(GDB_BFR_MAX - 23, size);

    if (length > 0)
    {
        memset(reply, 0, sizeof reply);

        reply[0] = 'M';
        wbe32hex(reply + 1, addr);
        reply[9] = ',';
        wbe32hex(reply + 10, size);
        reply[18] = ':';

        mem2hex(reply + 19, buffer, length);

        gdb_reply((char *)reply);

        // read ack/nak
        gdb_read_command();
        // read OK/E##/""
        gdb_read_command();
    }

    return length;
}

void gdb_continue(void)
{
    gdb_reply("c");
    // read ack/nak
    gdb_read_command();
}

void gdb_step(void)
{
    gdb_reply("s");
    // read ack/nak
    gdb_read_command();
}

void gdb_pause(void)
{
    gdb_reply(" ");
    // read ack/nak
    gdb_read_command();
}

void gdb_add_bp(u32 addr, gdb_bp_type type, u32 size)
{
    u8 reply[32] = { 0 };

    u8 bpt = 0;
    switch (type)
    {
    case GDB_BP_TYPE_X:
        bpt = 0;
        //type = 1;
        break;
    case GDB_BP_TYPE_W:
        bpt = 2;
        break;
    case GDB_BP_TYPE_R:
        bpt = 3;
        break;
    case GDB_BP_TYPE_A:
        bpt = 4;
        break;
    default:
        dbgprintf("Unsupported breakpoint type.\n");
        return;
    }

    reply[0] = 'Z';
    reply[1] = nibble2hex(bpt);
    reply[2] = ',';
    wbe32hex(reply +  3, addr);
    reply[11] = ',';
    wbe32hex(reply + 12, size);

    gdb_reply((char *)reply);

    // read ack/nak
    gdb_read_command();
    // read OK/E##/""
    gdb_read_command();
}

void gdb_remove_bp(u32 addr, gdb_bp_type type, u32 size)
{
    u8 reply[32] = { 0 };

    u8 bpt = 0;
    switch (type)
    {
    case GDB_BP_TYPE_X:
        bpt = 0;
        //type = 1;
        break;
    case GDB_BP_TYPE_W:
        bpt = 2;
        break;
    case GDB_BP_TYPE_R:
        bpt = 3;
        break;
    case GDB_BP_TYPE_A:
        bpt = 4;
        break;
    default:
        dbgprintf("Unsupported breakpoint type.\n");
        return;
    }

    reply[0] = 'z';
    reply[1] = nibble2hex(bpt);
    reply[2] = ',';
    wbe32hex(reply +  3, addr);
    reply[11] = ',';
    wbe32hex(reply + 12, size);

    gdb_reply((char *)reply);

    // read ack/nak
    gdb_read_command();
    // read OK/E##/""
    gdb_read_command();
}

static void gdb_parse_command(event_callback* callback)
{
    if (cmd_len == 0)
        return;

    if (sock < 0)
    {
        if (0 != callback)
            callback(SIGTERM, -1, -1);
        return;
    }

    switch(cmd_bfr[0])
    {
    case GDB_STUB_ACK:
        dbgprintf("ACK received.\n");
        break;
    case GDB_STUB_NAK:
        dbgprintf("NAK received.\n");
        break;
    case 'S':
    case 'T':
        gdb_handle_signal(callback);
        break;
    default:
        dbgprintf("Unhandled command: %02X ('%c')\n", cmd_bfr[0], cmd_bfr[0]);
        break;
/*
    case 'q':
        gdb_handle_query();
        break;
    case 'H':
        gdb_handle_set_thread();
        break;
    case '?':
        gdb_handle_signal();
        break;
    case 'k':
        gdb_ack();
        fail("killed by gdb");
        break;
    case 'g':
        gdb_read_registers();
        break;
    case 'G':
        gdb_write_registers();
        break;
    case 'p':
        gdb_read_register();
        break;
    case 'P':
        gdb_write_register();
        break;
    case 'm':
        gdb_read_mem();
        break;
    case 'M':
        gdb_write_mem();
        break;
    case 'c':
        gdb_continue();
        break;
    case 'z':
        gdb_remove_bp();
        break;
    case 'Z':
        gdb_add_bp();
        break;
    default:
        gdb_ack();
        gdb_reply("");
        break;
*/
    }
}

#ifdef _WIN32
    WSADATA InitData;
#endif

// exported functions

bool gdb_init(u32 port)
{
    int tmpsock;
    //socklen_t len;
    int on;
#ifdef _WIN32
    WSAStartup(MAKEWORD(2,2), &InitData);
#endif
    memset(bp_x, 0, sizeof bp_x);
    memset(bp_r, 0, sizeof bp_r);
    memset(bp_w, 0, sizeof bp_w);
    memset(bp_a, 0, sizeof bp_a);

    tmpsock = socket(AF_INET, SOCK_STREAM, 0);
    if (tmpsock == -1)
        return fail("Failed to create gdb socket");

    sock = tmpsock;

    on = 1;
    if (setsockopt(tmpsock, SOL_SOCKET, SO_REUSEADDR, (char*)&on, sizeof on) < 0)
        return fail("Failed to setsockopt");

    memset(&saddr_server, 0, sizeof saddr_server);
    saddr_server.sin_family = AF_INET;
    saddr_server.sin_port = htons(port);
    saddr_server.sin_addr.s_addr = inet_addr("127.0.0.1");

    dbgprintf("Connecting to gdb server...\n");
    int result = connect(tmpsock, (struct sockaddr *)&saddr_server, sizeof saddr_server);

    if (result < 0)
        return fail("Failed to connect to gdb server");

    dbgprintf("Server connected.\n");
    
    saddr_client.sin_addr.s_addr = ntohl(saddr_client.sin_addr.s_addr);
    /*if (((saddr_client.sin_addr.s_addr >> 24) & 0xff) != 127 ||
        ((saddr_client.sin_addr.s_addr >> 16) & 0xff) !=   0 ||
        ((saddr_client.sin_addr.s_addr >>  8) & 0xff) !=   0 ||
        ((saddr_client.sin_addr.s_addr >>  0) & 0xff) !=   1)
        fail("gdb: incoming connection not from localhost");
    */
    //close(tmpsock);

    return true;
}


void gdb_deinit(void)
{
    if (sock == -1)
        return;

    shutdown(sock, SD_BOTH);

    closesocket(sock);
    sock = -1;

#ifdef _WIN32
    WSACleanup();
#endif
}

void gdb_kill()
{
    gdb_reply("k");
    // read ack/nak
    gdb_read_command();

    gdb_deinit();
}


void gdb_handle_events(event_callback* callback)
{

    if (sock < 0)
    {
        if (0 != callback)
            callback(SIGTERM, -1, -1);
        return;
    }

    while (gdb_data_available())
    {
        if (!gdb_read_command())
            break;
        gdb_parse_command(callback);
    }
}

/*
int gdb_signal(u32 s)
{
    if (sock == -1)
        return 1;

    sig = s;

    if (send_signal)
    {
        gdb_handle_signal();
        send_signal = 0;
    }

    return 0;
}
*/
