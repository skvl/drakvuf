/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
*                                                                         *
* DRAKVUF (C) 2014-2017 Tamas K Lengyel.                                  *
* Tamas K Lengyel is hereinafter referred to as the author.               *
* This program is free software; you may redistribute and/or modify it    *
* under the terms of the GNU General Public License as published by the   *
* Free Software Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE   *
* CLARIFICATIONS AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your   *
* right to use, modify, and redistribute this software under certain      *
* conditions.  If you wish to embed DRAKVUF technology into proprietary   *
* software, alternative licenses can be aquired from the author.          *
*                                                                         *
* Note that the GPL places important restrictions on "derivative works",  *
* yet it does not provide a detailed definition of that term.  To avoid   *
* misunderstandings, we interpret that term as broadly as copyright law   *
* allows.  For example, we consider an application to constitute a        *
* derivative work for the purpose of this license if it does any of the   *
* following with any software or content covered by this license          *
* ("Covered Software"):                                                   *
*                                                                         *
* o Integrates source code from Covered Software.                         *
*                                                                         *
* o Reads or includes copyrighted data files.                             *
*                                                                         *
* o Is designed specifically to execute Covered Software and parse the    *
* results (as opposed to typical shell or execution-menu apps, which will *
* execute anything you tell them to).                                     *
*                                                                         *
* o Includes Covered Software in a proprietary executable installer.  The *
* installers produced by InstallShield are an example of this.  Including *
* DRAKVUF with other software in compressed or archival form does not     *
* trigger this provision, provided appropriate open source decompression  *
* or de-archiving software is widely available for no charge.  For the    *
* purposes of this license, an installer is considered to include Covered *
* Software even if it actually retrieves a copy of Covered Software from  *
* another source during runtime (such as by downloading it from the       *
* Internet).                                                              *
*                                                                         *
* o Links (statically or dynamically) to a library which does any of the  *
* above.                                                                  *
*                                                                         *
* o Executes a helper program, module, or script to do any of the above.  *
*                                                                         *
* This list is not exclusive, but is meant to clarify our interpretation  *
* of derived works with some common examples.  Other people may interpret *
* the plain GPL differently, so we consider this a special exception to   *
* the GPL that we apply to Covered Software.  Works which meet any of     *
* these conditions must conform to all of the terms of this license,      *
* particularly including the GPL Section 3 requirements of providing      *
* source code and allowing free redistribution of the work as a whole.    *
*                                                                         *
* Any redistribution of Covered Software, including any derived works,    *
* must obey and carry forward all of the terms of this license, including *
* obeying all GPL rules and restrictions.  For example, source code of    *
* the whole work must be provided and free redistribution must be         *
* allowed.  All GPL references to "this License", are to be treated as    *
* including the terms and conditions of this license text as well.        *
*                                                                         *
* Because this license imposes special exceptions to the GPL, Covered     *
* Work may not be combined (even as part of a larger work) with plain GPL *
* software.  The terms, conditions, and exceptions of this license must   *
* be included as well.  This license is incompatible with some other open *
* source licenses as well.  In some cases we can relicense portions of    *
* DRAKVUF or grant special permissions to use it in other open source     *
* software.  Please contact tamas.k.lengyel@gmail.com with any such       *
* requests.  Similarly, we don't incorporate incompatible open source     *
* software into Covered Software without special permission from the      *
* copyright holders.                                                      *
*                                                                         *
* If you have any questions about the licensing restrictions on using     *
* DRAKVUF in other works, are happy to help.  As mentioned above,         *
* alternative license can be requested from the author to integrate       *
* DRAKVUF into proprietary applications and appliances.  Please email     *
* tamas.k.lengyel@gmail.com for further information.                      *
*                                                                         *
* If you have received a written license agreement or contract for        *
* Covered Software stating terms other than these, you may choose to use  *
* and redistribute Covered Software under those terms instead of these.   *
*                                                                         *
* Source is provided to this software because we believe users have a     *
* right to know exactly what a program is going to do before they run it. *
* This also allows you to audit the software for security holes.          *
*                                                                         *
* Source code also allows you to port DRAKVUF to new platforms, fix bugs, *
* and add new features.  You are highly encouraged to submit your changes *
* on https://github.com/tklengyel/drakvuf, or by other methods.           *
* By sending these changes, it is understood (unless you specify          *
* otherwise) that you are offering unlimited, non-exclusive right to      *
* reuse, modify, and relicense the code.  DRAKVUF will always be          *
* available Open Source, but this is important because the inability to   *
* relicense code has caused devastating problems for other Free Software  *
* projects (such as KDE and NASM).                                        *
* To specify special license conditions of your contributions, just say   *
* so when you send them.                                                  *
*                                                                         *
* This program is distributed in the hope that it will be useful, but     *
* WITHOUT ANY WARRANTY; without even the implied warranty of              *
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the DRAKVUF   *
* license file for more details (it's in a COPYING file included with     *
* DRAKVUF, and also available from                                        *
* https://github.com/tklengyel/drakvuf/COPYING)                           *
*                                                                         *
***************************************************************************/

#include <glib.h>
#include <config.h>
#include <inttypes.h>
#include <libvmi/x86.h>
#include <algorithm>
#include <cassert>
#include <set>

#include "../plugins.h"
#include "filedelete.h"

#include <libinjector/libinjector.h>

#define FILE_DISPOSITION_INFORMATION 13

#undef UNUSED
#define UNUSED __attribute__((unused))

#undef PRINT_DEBUG
#define PRINT_DEBUG printf

enum offset
{
    FILE_OBJECT_TYPE,
    FILE_OBJECT_FILENAME,
    FILE_OBJECT_SECTIONOBJECTPOINTER,
    SECTIONOBJECTPOINTER_DATASECTIONOBJECT,
    SECTIONOBJECTPOINTER_SHAREDCACHEMAP,
    SECTIONOBJECTPOINTER_IMAGESECTIONOBJECT,
    CONTROL_AREA_SEGMENT,
    SEGMENT_CONTROLAREA,
    SEGMENT_SIZEOFSEGMENT,
    SEGMENT_TOTALNUMBEROFPTES,
    SUBSECTION_NEXTSUBSECTION,
    SUBSECTION_SUBSECTIONBASE,
    SUBSECTION_PTESINSUBSECTION,
    SUBSECTION_CONTROLAREA,
    SUBSECTION_STARTINGSECTOR,
    OBJECT_HEADER_BODY,
    __OFFSET_MAX
};

static const char* offset_names[__OFFSET_MAX][2] =
{
    [FILE_OBJECT_TYPE] = {"_FILE_OBJECT", "Type"},
    [FILE_OBJECT_FILENAME] = {"_FILE_OBJECT", "FileName"},
    [FILE_OBJECT_SECTIONOBJECTPOINTER] = {"_FILE_OBJECT", "SectionObjectPointer"},
    [SECTIONOBJECTPOINTER_DATASECTIONOBJECT] = {"_SECTION_OBJECT_POINTERS", "DataSectionObject"},
    [SECTIONOBJECTPOINTER_SHAREDCACHEMAP] = {"_SECTION_OBJECT_POINTERS", "SharedCacheMap"},
    [SECTIONOBJECTPOINTER_IMAGESECTIONOBJECT] = {"_SECTION_OBJECT_POINTERS", "ImageSectionObject"},
    [CONTROL_AREA_SEGMENT] = {"_CONTROL_AREA", "Segment"},
    [SEGMENT_CONTROLAREA] = {"_SEGMENT", "ControlArea"},
    [SEGMENT_SIZEOFSEGMENT] = {"_SEGMENT", "SizeOfSegment"},
    [SEGMENT_TOTALNUMBEROFPTES] = {"_SEGMENT", "TotalNumberOfPtes"},
    [SUBSECTION_NEXTSUBSECTION] = {"_SUBSECTION", "NextSubsection"},
    [SUBSECTION_SUBSECTIONBASE] = {"_SUBSECTION", "SubsectionBase"},
    [SUBSECTION_PTESINSUBSECTION] = {"_SUBSECTION", "PtesInSubsection"},
    [SUBSECTION_CONTROLAREA] = {"_SUBSECTION", "ControlArea"},
    [SUBSECTION_STARTINGSECTOR] = {"_SUBSECTION", "StartingSector"},
    [OBJECT_HEADER_BODY] = { "_OBJECT_HEADER", "Body" },
};

static void save_file_metadata(filedelete* f,
                               const drakvuf_trap_info_t* info,
                               int sequence_number,
                               addr_t control_area,
                               const unicode_string_t* filename)
{
    char* file = NULL;
    if ( asprintf(&file, "%s/file.%06d.metadata", f->dump_folder, sequence_number) < 0 )
        return;

    FILE* fp = fopen(file, "w");
    if (!fp)
    {
        free(file);
        return;
    }

    if (filename)
        fprintf(fp, "FileName: \"%s\"\n", filename->contents);
    fprintf(fp, "SequenceNumber: %d\n", sequence_number);
    fprintf(fp, "ControlArea: 0x%lx\n", control_area);
    fprintf(fp, "PID: %" PRIu64 "\n", static_cast<uint64_t>(info->proc_data.pid));
    fprintf(fp, "PPID: %" PRIu64 "\n", static_cast<uint64_t>(info->proc_data.ppid));
    fprintf(fp, "ProcessName: \"%s\"\n", info->proc_data.name);

    fclose(fp);
    free(file);
}

static void extract_ca_file(filedelete* f,
                            drakvuf_t drakvuf,
                            const drakvuf_trap_info_t* info,
                            vmi_instance_t vmi,
                            addr_t control_area,
                            access_context_t* ctx,
                            const unicode_string_t* filename)
{
    addr_t subsection = control_area + f->control_area_size;
    addr_t segment = 0, test = 0, test2 = 0;

    /* Check whether subsection points back to the control area */
    ctx->addr = control_area + f->offsets[CONTROL_AREA_SEGMENT];
    if ( VMI_FAILURE == vmi_read_addr(vmi, ctx, &segment) )
        return;

    ctx->addr = segment + f->offsets[SEGMENT_CONTROLAREA];
    if ( VMI_FAILURE == vmi_read_addr(vmi, ctx, &test) || test != control_area )
        return;

    ctx->addr = segment + f->offsets[SEGMENT_SIZEOFSEGMENT];
    if ( VMI_FAILURE == vmi_read_64(vmi, ctx, &test) )
        return;

    ctx->addr = segment + f->offsets[SEGMENT_TOTALNUMBEROFPTES];
    if ( VMI_FAILURE == vmi_read_32(vmi, ctx, (uint32_t*)&test2) )
        return;

    if ( test != (test2 * 4096) )
        return;

    const int curr_sequence_number = ++f->sequence_number;

    char* file = NULL;
    if ( asprintf(&file, "%s/file.%06d.mm", f->dump_folder, curr_sequence_number) < 0 )
        return;

    FILE* fp = fopen(file, "w");

    while (subsection)
    {
        /* Check whether subsection points back to the control area */
        ctx->addr = subsection + f->offsets[SUBSECTION_CONTROLAREA];
        if ( VMI_FAILURE == vmi_read_addr(vmi, ctx, &test) || test != control_area )
            break;

        addr_t base = 0, start = 0;
        uint32_t ptes = 0;

        ctx->addr = subsection + f->offsets[SUBSECTION_SUBSECTIONBASE];
        if ( VMI_FAILURE == vmi_read_addr(vmi, ctx, &base) )
            break;

        if ( !(base & VMI_BIT_MASK(0,11)) )
            break;

        ctx->addr = subsection + f->offsets[SUBSECTION_PTESINSUBSECTION];
        if ( VMI_FAILURE == vmi_read_32(vmi, ctx, &ptes) )
            break;

        ctx->addr = subsection + f->offsets[SUBSECTION_STARTINGSECTOR];
        if ( VMI_FAILURE == vmi_read_32(vmi, ctx, (uint32_t*)&start) )
            break;

        /*
         * The offset into the file is stored implicitely
         * based on the PTE's location within the Subsection.
         */
        addr_t subsection_offset = start * 0x200;
        addr_t ptecount;
        for (ptecount=0; ptecount < ptes; ptecount++)
        {
            addr_t pteoffset = base + f->mmpte_size * ptecount;
            addr_t fileoffset = subsection_offset + ptecount * 0x1000;

            addr_t pte = 0;
            ctx->addr = pteoffset;
            if ( VMI_FAILURE == vmi_read(vmi, ctx, f->mmpte_size, &pte, NULL) )
                break;

            if ( ENTRY_PRESENT(1, pte) )
            {
                uint8_t page[4096];

                if ( VMI_FAILURE == vmi_read_pa(vmi, VMI_BIT_MASK(12,48) & pte, 4096, &page, NULL) )
                    continue;

                if ( !fseek ( fp, fileoffset, SEEK_SET ) )
                    fwrite(page, 4096, 1, fp);
            }
        }

        ctx->addr = subsection + f->offsets[SUBSECTION_NEXTSUBSECTION];
        if ( !vmi_read_addr(vmi, ctx, &subsection) )
            break;
    }

    fclose(fp);
    free(file);

    save_file_metadata(f, info, curr_sequence_number, control_area, filename);
}

static void extract_file(filedelete* f,
                         drakvuf_t drakvuf,
                         const drakvuf_trap_info_t* info,
                         vmi_instance_t vmi,
                         addr_t file_pa,
                         access_context_t* ctx,
                         const unicode_string_t* filename)
{
    addr_t sop = 0;
    addr_t datasection = 0, sharedcachemap = 0, imagesection = 0;

    ctx->addr = file_pa + f->offsets[FILE_OBJECT_SECTIONOBJECTPOINTER];
    if ( VMI_FAILURE == vmi_read_addr(vmi, ctx, &sop) )
        return;

    ctx->addr = sop + f->offsets[SECTIONOBJECTPOINTER_DATASECTIONOBJECT];
    if ( VMI_FAILURE == vmi_read_addr(vmi, ctx, &datasection) )
        return;

    if ( datasection )
        extract_ca_file(f, drakvuf, info, vmi, datasection, ctx, filename);

    ctx->addr = sop + f->offsets[SECTIONOBJECTPOINTER_SHAREDCACHEMAP];
    if ( VMI_FAILURE == vmi_read_addr(vmi, ctx, &sharedcachemap) )
        return;

    // TODO: extraction from sharedcachemap

    ctx->addr = sop + f->offsets[SECTIONOBJECTPOINTER_IMAGESECTIONOBJECT];
    if ( VMI_FAILURE == vmi_read_addr(vmi, ctx, &imagesection) )
        return;

    if ( imagesection != datasection )
        extract_ca_file(f, drakvuf, info, vmi, imagesection, ctx, filename);
}

/*
 * The approach where the system process list es enumerated looking for
 * the matching cr3 value in each _EPROCESS struct is not going to work
 * if a DKOM attack unhooks the _EPROCESS struct.
 *
 * We can access the _EPROCESS structure by reading the FS_BASE register on x86
 * or the GS_BASE register on x64, which contains the _KPCR.
 *
 * FS/GS -> _KPCR._KPRCB.CurrentThread -> _ETHREAD._KTHREAD.Process = _EPROCESS
 *
 * Also see: http://www.csee.umbc.edu/~stephens/SECURITY/491M/HiddenProcesses.ppt
 */
static void grab_file_by_handle(filedelete* f, drakvuf_t drakvuf,
                                vmi_instance_t vmi,
                                drakvuf_trap_info_t* info, addr_t handle)
{
    uint8_t type = 0;
    addr_t process=drakvuf_get_current_process(drakvuf, info->vcpu);

    // TODO: verify that the dtb in the _EPROCESS is the same as the cr3?

    if (!process)
        return;

    addr_t obj = drakvuf_get_obj_by_handle(drakvuf, process, handle);

    if (!obj)
        return;

    addr_t file = obj + f->offsets[OBJECT_HEADER_BODY];
    addr_t filename = file + f->offsets[FILE_OBJECT_FILENAME];
    addr_t filetype = file + f->offsets[FILE_OBJECT_TYPE];

    access_context_t ctx;
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.addr = filetype;
    ctx.dtb = info->regs->cr3;

    if (VMI_FAILURE == vmi_read_8(vmi, &ctx, &type))
        return;

    if (type != 5)
        return;

    unicode_string_t* filename_us = drakvuf_read_unicode(drakvuf, info, filename);

    if (filename_us)
    {
        switch (f->format)
        {
            case OUTPUT_CSV:
                printf("filedelete," FORMAT_TIMEVAL ",%" PRIu32 ",0x%" PRIx64 ",\"%s\",%" PRIi64 ",\"%s\"\n",
                       UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name, info->proc_data.userid, filename_us->contents);
                break;
            default:
            case OUTPUT_DEFAULT:
                printf("[FILEDELETE] TIME:" FORMAT_TIMEVAL " VCPU:%" PRIu32 " CR3:0x%" PRIx64 ",\"%s\" %s:%" PRIi64" \"%s\"\n",
                       UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name,
                       USERIDSTR(drakvuf), info->proc_data.userid, filename_us->contents);
                break;
        }

        if (f->dump_folder)
            extract_file(f, drakvuf, info, vmi, file, &ctx, filename_us);

        vmi_free_unicode_str(filename_us);
    }
}

/*
 * NTSTATUS ZwSetInformationFile(
 *  HANDLE                 FileHandle,
 *  PIO_STATUS_BLOCK       IoStatusBlock,
 *  PVOID                  FileInformation,
 *  ULONG                  Length,
 *  FILE_INFORMATION_CLASS FileInformationClass
 * );
 *
 * When FileInformationClass is FileDispositionInformation then FileInformation points to
 * struct _FILE_DISPOSITION_INFORMATION {
 *  BOOLEAN DeleteFile;
 * }
 */
UNUSED
static event_response_t setinformation(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    filedelete* f = (filedelete*)info->trap->data;
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    access_context_t ctx;
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;

    uint32_t fileinfoclass = 0;
    reg_t handle = 0, fileinfo = 0;

    if (f->pm == VMI_PM_IA32E)
    {
        handle = info->regs->rcx;
        fileinfo = info->regs->r8;

        ctx.addr = info->regs->rsp + 5 * sizeof(addr_t); // addr of fileinfoclass
        if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, &fileinfoclass) )
            goto done;
    }
    else
    {
        ctx.addr = info->regs->rsp + sizeof(uint32_t);
        if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, (uint32_t*) &handle) )
            goto done;
        ctx.addr += 2 * sizeof(uint32_t);
        if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, (uint32_t*) &fileinfo) )
            goto done;
        ctx.addr += 2 * sizeof(uint32_t);
        if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, &fileinfoclass) )
            goto done;
    }

    if (fileinfoclass == FILE_DISPOSITION_INFORMATION)
    {
        uint8_t del = 0;
        ctx.addr = fileinfo;
        if ( VMI_FAILURE == vmi_read_8(vmi, &ctx, &del) )
            goto done;

        if (del)
            grab_file_by_handle(f, drakvuf, vmi, info, handle);
    }

done:
    drakvuf_release_vmi(drakvuf);
    return 0;
}

UNUSED
static event_response_t close_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    filedelete* f = (filedelete*)info->trap->data;
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    reg_t handle = 0;

    if (f->pm == VMI_PM_IA32E)
    {
        handle = info->regs->rcx;
    }
    else
    {
        access_context_t ctx;
        ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
        ctx.dtb = info->regs->cr3;
        ctx.addr = info->regs->rsp + sizeof(uint32_t);
        if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, (uint32_t*) &handle) )
            goto done;
    }

    if (f->changed_file_handles.erase(std::make_pair(info->proc_data.pid, handle)) > 0)
    {
        // We detect the fact of closing of the previously modified file.
        grab_file_by_handle(f, drakvuf, vmi, info, handle);
    }

done:
    drakvuf_release_vmi(drakvuf);
    return 0;
}

// TODO Check structure layout (packed?)
// The structure is described on MSDN
struct by_handle_file_information
{
    uint32_t dwFileAttributes;
    uint64_t ftCreationTime;
    uint64_t ftLastAccessTime;
    uint64_t ftLastWriteTime;
    uint32_t dwVolumeSerialNumber;
    uint32_t nFileSizeHigh;
    uint32_t nFileSizeLow;
    uint32_t nNumberOfLinks;
    uint32_t nFileIndexHigh;
    uint32_t nFileIndexLow;
};

#define FILE_ATTRIBUTE_DIRECTORY 0x10ULL
#define FILE_ATTRIBUTE_DEVICE    0x40ULL

#define FILE_ATTRIBUTE_IGNORE (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_DEVICE)

struct injector
{
    filedelete* f;
    bool is32bit;

    reg_t handle;

    reg_t target_cr3;
    uint32_t target_thread_id;
    addr_t eprocess_base;

    x86_registers_t saved_regs;

    struct
    {
        uint64_t size;
        // Duplicate handle
        reg_t handle;
    } file;

    union
    {
        struct
        {
            addr_t exec_func;
            bool get_type_info;
            addr_t out;
            size_t size;
        } ntqueryobject_info;

        struct
        {
            addr_t out;
        } getfileinformationbyhandle_info, duplicatehandle_info;

        struct
        {
            size_t size;
            addr_t out;
        } ntreadfile_info;
    };

    drakvuf_trap_t* bp;
};

static event_response_t final_closehandle_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    struct injector* injector = (struct injector*)info->trap->data;

    auto response = 0;
    uint32_t thread_id = 0;
    std::pair<addr_t, uint32_t> thread;
    auto pid = info->proc_data.pid;

    if (info->regs->cr3 != injector->target_cr3)
        goto done;

    if ( !drakvuf_get_current_thread_id(drakvuf, info->vcpu, &thread_id) ||
         !injector->target_thread_id || thread_id != injector->target_thread_id )
        goto done;

    PRINT_DEBUG("[FILEDELETE] [final NtClose] Finish processing handle %lu (dup %lu). (CR3 0x%lx, TID %d)\n", injector->file.handle, injector->handle, info->regs->cr3, thread_id);

    thread = std::make_pair(info->regs->cr3, thread_id);
    injector->f->closing_handles[thread] = true;
    injector->f->files[pid].erase(injector->handle);
    if (injector->f->files[pid].size() == 0)
        injector->f->files.erase(pid);

    memcpy(info->regs, &injector->saved_regs, sizeof(x86_registers_t));
    response = VMI_EVENT_RESPONSE_SET_REGISTERS;

    drakvuf_remove_trap(drakvuf, injector->bp, (drakvuf_trap_free_t)free);

    delete injector;

done:
    return response;
}

static event_response_t readfile_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    struct injector* injector = (struct injector*)info->trap->data;

    auto response = 0;
    uint32_t thread_id = 0;
    std::pair<addr_t, uint32_t> thread;
    filedelete* f = injector->f;

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    if (info->regs->cr3 != injector->target_cr3)
        goto done;

    if ( !drakvuf_get_current_thread_id(drakvuf, info->vcpu, &thread_id) ||
         !injector->target_thread_id || thread_id != injector->target_thread_id )
        goto done;

    {
        // TODO Idx should be calculated per file
        static uint64_t idx = 0;
        char* file = NULL;
        if ( asprintf(&file, "%s/file.%06lu.metadata", f->dump_folder, ++idx) < 0 )
            goto err;

        FILE* fp = fopen(file, "w");
        if (!fp)
        {
            free(file);
            goto err;
        }

        fprintf(fp, "FileName: \"%s\"\n", injector->f->files[info->proc_data.pid][injector->handle].c_str());
        fprintf(fp, "PID: %" PRIu64 "\n", static_cast<uint64_t>(info->proc_data.pid));
        fprintf(fp, "PPID: %" PRIu64 "\n", static_cast<uint64_t>(info->proc_data.ppid));
        fprintf(fp, "ProcessName: \"%s\"\n", info->proc_data.name);

        fclose(fp);
        free(file);

        access_context_t ctx =
        {
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3,
            .addr = injector->ntreadfile_info.out,
        };

        void* buffer = g_malloc0(injector->ntreadfile_info.size);
        if ((VMI_FAILURE == vmi_read(vmi, &ctx, injector->ntreadfile_info.size, buffer, NULL)))
                goto err;

        if ( asprintf(&file, "%s/file.%06lu", f->dump_folder, idx) < 0 )
            goto err;

        fp = fopen(file, "w");
        if (!fp)
        {
            free(file);
            goto err;
        }

        fwrite(buffer, 1, injector->ntreadfile_info.size, fp);
        fclose(fp);
        free(file);
    }

    {
        // Remove stack arguments and home space from previous injection
        info->regs->rsp = injector->saved_regs.rsp;

        access_context_t ctx =
        {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = info->regs->rsp,
        };

        if (injector->is32bit)
        {
        PRINT_DEBUG("[FILEDELETE] 32bit VMs not supported yet\n");
        goto err;
        }

        //p1
        info->regs->rcx = injector->file.handle;

        // allocate 0x20 "homing space"
        uint64_t home_space[4] = { 0 };
        ctx.addr -= 0x20;
        if (VMI_FAILURE == vmi_write(vmi, &ctx, 0x20, home_space, NULL))
            goto err;

        // save the return address
        ctx.addr -= 0x8;
        if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &info->regs->rip))
            goto err;

        // Grow the stack
        info->regs->rsp = ctx.addr;
    }

    // Current RIP is on NtClose already
    // info->regs->rip = exec_func;

    injector->bp->name = "final NtClose ret";
    injector->bp->cb = final_closehandle_cb;

    response = VMI_EVENT_RESPONSE_SET_REGISTERS;

    goto done;

err:
    PRINT_DEBUG("[FILEDELETE] [NtReadFile] Error. Stop processing (CR3 0x%lx, TID %d).\n",
            info->regs->cr3, thread_id);

    thread = std::make_pair(info->regs->cr3, thread_id);
    injector->f->closing_handles[thread] = true;

    memcpy(info->regs, &injector->saved_regs, sizeof(x86_registers_t));
    response = VMI_EVENT_RESPONSE_SET_REGISTERS;

    drakvuf_remove_trap(drakvuf, injector->bp, (drakvuf_trap_free_t)free);

    delete injector;

done:
    drakvuf_release_vmi(drakvuf);

    return response;
}

static event_response_t duplicatehandle_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    struct injector* injector = (struct injector*)info->trap->data;

    auto response = 0;
    uint32_t thread_id = 0;
    std::pair<addr_t, uint32_t> thread;

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    if (info->regs->cr3 != injector->target_cr3)
        goto done;

    if ( !drakvuf_get_current_thread_id(drakvuf, info->vcpu, &thread_id) ||
         !injector->target_thread_id || thread_id != injector->target_thread_id )
        goto done;

    if (info->regs->rax != 0)
    {
        access_context_t ctx =
        {
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3,
            .addr = injector->duplicatehandle_info.out,
        };

        if (VMI_FAILURE == vmi_read_32(vmi, &ctx, (uint32_t*)&injector->file.handle))
        {
            PRINT_DEBUG("[FILEDELETE] [DuplicateHandle] Failed to read duplicate handle.\n");
            goto err;
        }

        PRINT_DEBUG("[FILEDELETE] [DuplicateHandle] Duplicate handle of %lu is %lu. (CR3 0x%lx, TID %d)\n", injector->handle, injector->file.handle, info->regs->cr3, thread_id);

        const char* lib = "ntdll.dll";
        const char* fun = "NtReadFile";

        auto exec_func = drakvuf_exportsym_to_va(drakvuf, injector->eprocess_base, lib, fun);
        if (!exec_func)
        {
            PRINT_DEBUG("[FILEDELETE] [DuplicateHandle] Failed to get VA of '%s!%s'.\n", lib, fun);
            goto err;
        }

        {
            // Remove stack arguments and home space from previous injection
            info->regs->rsp = injector->saved_regs.rsp;

            access_context_t ctx =
            {
                .translate_mechanism = VMI_TM_PROCESS_DTB,
                .dtb = info->regs->cr3,
                .addr = info->regs->rsp,
            };

            if (injector->is32bit)
            {
                PRINT_DEBUG("[FILEDELETE] 32bit VMs not supported yet\n");
                goto err;
            }

            uint64_t null64 = 0;

            ctx.addr -= 16;
            auto pio_status_block = ctx.addr;

            injector->ntreadfile_info.size = std::min(injector->file.size, 0x4000UL);
            ctx.addr -= injector->ntreadfile_info.size;
            injector->ntreadfile_info.out = ctx.addr;

            //p9
            ctx.addr -= 8;
            if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &null64))
                goto err;

            //p8
            ctx.addr -= 8;
            if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &null64))
                goto err;

            //p7
            ctx.addr -= 8;
            if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &injector->ntreadfile_info.size))
                goto err;

            //p6
            ctx.addr -= 8;
            if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &injector->ntreadfile_info.out))
                goto err;

            //p5
            ctx.addr -= 8;
            if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &pio_status_block))
                goto err;

            //p1
            info->regs->rcx = injector->handle;
            //p2
            info->regs->rdx = 0;
            //p3
            info->regs->r8 = 0;
            //p4
            info->regs->r9 = 0;

            // allocate 0x20 "homing space"
            uint64_t home_space[4] = { 0 };
            ctx.addr -= 0x20;
            if (VMI_FAILURE == vmi_write(vmi, &ctx, 0x20, home_space, NULL))
                goto err;

            // save the return address
            ctx.addr -= 0x8;
            if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &info->regs->rip))
                goto err;

            // Grow the stack
            info->regs->rsp = ctx.addr;
        }

        info->regs->rip = exec_func;

        injector->bp->name = "NtReadFile ret";
        injector->bp->cb = readfile_cb;

        response = VMI_EVENT_RESPONSE_SET_REGISTERS;

        goto done;
    }
    else
        goto err;

err:
    PRINT_DEBUG("[FILEDELETE] [DuplicateHandle] Error. Stop processing (CR3 0x%lx, TID %d).\n",
            info->regs->cr3, thread_id);

    thread = std::make_pair(info->regs->cr3, thread_id);
    injector->f->closing_handles[thread] = true;

    memcpy(info->regs, &injector->saved_regs, sizeof(x86_registers_t));
    response = VMI_EVENT_RESPONSE_SET_REGISTERS;

    drakvuf_remove_trap(drakvuf, injector->bp, (drakvuf_trap_free_t)free);

    delete injector;

done:
    drakvuf_release_vmi(drakvuf);

    return response;
}

static event_response_t getfileinformationbyhandle_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    struct injector* injector = (struct injector*)info->trap->data;

    auto response = 0;
    uint32_t thread_id = 0;
    std::pair<addr_t, uint32_t> thread;

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    if (info->regs->cr3 != injector->target_cr3)
        goto done;

    if ( !drakvuf_get_current_thread_id(drakvuf, info->vcpu, &thread_id) ||
         !injector->target_thread_id || thread_id != injector->target_thread_id )
        goto done;

    {
        struct by_handle_file_information file_info = { 0 };

        access_context_t ctx =
        {
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3,
            .addr = injector->getfileinformationbyhandle_info.out,
        };

        size_t bytes_read = 0;
        if (VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(struct by_handle_file_information), &file_info, &bytes_read) ||
            bytes_read != sizeof(struct by_handle_file_information))
        {
            PRINT_DEBUG("[FILEDELETE] [GetFileInformationByHandle] Failed to read output structure.\n");
            goto err;
        }

        injector->file.size = ((uint64_t)file_info.nFileSizeHigh) | file_info.nFileSizeLow;
        if ( !(FILE_ATTRIBUTE_IGNORE & file_info.dwFileAttributes) && injector->file.size > 0)
        {
            PRINT_DEBUG("[FILEDELETE] [GetFileInformationByHandle] File '%s', size is 0x%lx (CR3 0x%lx, TID %d).\n",
                    injector->f->files[info->proc_data.pid][injector->handle].c_str(), injector->file.size, info->regs->cr3, thread_id);

            const char* lib = "kernel32.dll";
            const char* fun = "DuplicateHandle";

            auto exec_func = drakvuf_exportsym_to_va(drakvuf, injector->eprocess_base, lib, fun);
            if (!exec_func)
            {
                PRINT_DEBUG("[FILEDELETE] [GetFileInformationByHandle] Failed to get VA of '%s!%s'.\n", lib, fun);
                goto err;
            }

            {
                // Remove stack arguments and home space from previous injection
                info->regs->rsp = injector->saved_regs.rsp;

                access_context_t ctx =
                {
                    .translate_mechanism = VMI_TM_PROCESS_DTB,
                    .dtb = info->regs->cr3,
                    .addr = info->regs->rsp,
                };

                if (injector->is32bit)
                {
                    PRINT_DEBUG("[FILEDELETE] 32bit VMs not supported yet\n");
                    goto err;
                }

                uint64_t null64 = 0;

                // The place for output data
                ctx.addr -= 8;
                injector->duplicatehandle_info.out = ctx.addr;
                if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &null64))
                    goto err;

                //p7
                ctx.addr -= 8;
                injector->duplicatehandle_info.out = ctx.addr;
                if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &null64))
                    goto err;

                //p6
                ctx.addr -= 8;
                injector->duplicatehandle_info.out = ctx.addr;
                if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &null64))
                    goto err;

                //p5
                uint64_t desired_access = 0x80000000; // GENERIC_READ
                ctx.addr -= 8;
                injector->duplicatehandle_info.out = ctx.addr;
                if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &desired_access))
                    goto err;

                //p1
                info->regs->rcx = 0xffffffffffffffff; // Pseudo handle for current process
                //p2
                info->regs->rdx = injector->handle;
                //p3
                info->regs->r8 = 0xffffffffffffffff;
                //p4
                info->regs->r9 = injector->duplicatehandle_info.out;

                // allocate 0x20 "homing space"
                uint64_t home_space[4] = { 0 };
                ctx.addr -= 0x20;
                if (VMI_FAILURE == vmi_write(vmi, &ctx, 0x20, home_space, NULL))
                    goto err;

                // save the return address
                ctx.addr -= 0x8;
                if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &info->regs->rip))
                    goto err;

                // Grow the stack
                info->regs->rsp = ctx.addr;
            }

            info->regs->rip = exec_func;

            injector->bp->name = "DuplicateHandle ret";
            injector->bp->cb = duplicatehandle_cb;

            response = VMI_EVENT_RESPONSE_SET_REGISTERS;

            goto done;
        }
        else
            goto handled;
    }

err:
    PRINT_DEBUG("[FILEDELETE] [GetFileInformationByHandle] Error. Stop processing (CR3 0x%lx, TID %d).\n",
            info->regs->cr3, thread_id);

handled:
    thread = std::make_pair(info->regs->cr3, thread_id);
    injector->f->closing_handles[thread] = true;

    memcpy(info->regs, &injector->saved_regs, sizeof(x86_registers_t));
    response = VMI_EVENT_RESPONSE_SET_REGISTERS;

    drakvuf_remove_trap(drakvuf, injector->bp, (drakvuf_trap_free_t)free);

    delete injector;

done:
    drakvuf_release_vmi(drakvuf);

    return response;
}

static event_response_t ntqueryobject_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    struct injector* injector = (struct injector*)info->trap->data;

    auto response = 0;
    uint32_t thread_id = 0;
    uint64_t object_information_size = 0;
    std::pair<addr_t, uint32_t> thread;

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    if (info->regs->cr3 != injector->target_cr3)
        goto done;

    if ( !drakvuf_get_current_thread_id(drakvuf, info->vcpu, &thread_id) ||
         !injector->target_thread_id || thread_id != injector->target_thread_id )
        goto done;

    if (!injector->ntqueryobject_info.get_type_info)
    {
        access_context_t ctx =
        {
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3,
            .addr = injector->ntqueryobject_info.out,
        };

        if (VMI_FAILURE == vmi_read_64(vmi, &ctx, &object_information_size))
        {
            PRINT_DEBUG("[FILEDELETE] [NtQueryObject] Failed to read ObjectInformation size.\n");
            goto err;
        }

        injector->ntqueryobject_info.size = object_information_size;
        injector->ntqueryobject_info.get_type_info = true;

        {
            // Remove stack arguments and home space from previous injection
            info->regs->rsp = injector->saved_regs.rsp;

            access_context_t ctx =
            {
                .translate_mechanism = VMI_TM_PROCESS_DTB,
                .dtb = info->regs->cr3,
                .addr = info->regs->rsp,
            };

            if (injector->is32bit)
            {
                PRINT_DEBUG("[FILEDELETE] 32bit VMs not supported yet\n");
                goto err;
            }

            uint64_t nul64 = 0;

            // The string's length is undefined and could misalign stack which must be
            // aligned on 16B boundary (see Microsoft x64 ABI).
            ctx.addr &= ~0x1f;

            ctx.addr -= object_information_size;
            auto out_addr = ctx.addr;
            injector->ntqueryobject_info.out = out_addr;
            if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
                goto err;

            //p5
            ctx.addr -= 0x8;
            if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
                goto err;

            //p1
            info->regs->rcx = injector->handle;
            //p2
            info->regs->rdx = 2; // OBJECT_INFORMATION_CLASS ObjectTypeInformation
            //p3
            info->regs->r8 = out_addr;
            //p4
            info->regs->r9 = object_information_size;

            // allocate 0x20 "homing space"
            ctx.addr -= 0x8;
            if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
                goto err;

            ctx.addr -= 0x8;
            if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
                goto err;

            ctx.addr -= 0x8;
            if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
                goto err;

            ctx.addr -= 0x8;
            if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
                goto err;

            // save the return address
            ctx.addr -= 0x8;
            if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &info->regs->rip))
                goto err;

            // Grow the stack
            info->regs->rsp = ctx.addr;
        }

        info->regs->rip = injector->ntqueryobject_info.exec_func;

        response = VMI_EVENT_RESPONSE_SET_REGISTERS;

        goto done;
    }
    else
    {
        unicode_string_t* type_name = drakvuf_read_unicode(drakvuf, info, injector->ntqueryobject_info.out);
        if (!type_name->contents)
            goto err;

        std::string type_file = "File";
        if ( 0 != type_file.compare(std::string((const char*)type_name->contents)) )
            goto handled;

        {
            const char* lib = "kernel32.dll";
            const char* fun = "GetFileInformationByHandle";

            auto exec_func = drakvuf_exportsym_to_va(drakvuf, injector->eprocess_base, lib, fun);
            if (!exec_func)
            {
                PRINT_DEBUG("[FILEDELETE] [NtQueryObject] Failed to get VA of '%s!%s'.\n", lib, fun);
                goto err;
            }

            {
                // Remove stack arguments and home space from previous injection
                info->regs->rsp = injector->saved_regs.rsp;

                access_context_t ctx =
                {
                    .translate_mechanism = VMI_TM_PROCESS_DTB,
                    .dtb = info->regs->cr3,
                    .addr = info->regs->rsp,
                };

                if (injector->is32bit)
                {
                    PRINT_DEBUG("[FILEDELETE] 32bit VMs not supported yet\n");
                    goto err;
                }

                // The place for output data
                uint8_t null_buf[sizeof(struct by_handle_file_information)] = { 0 };
                ctx.addr -= sizeof(struct by_handle_file_information);
                injector->getfileinformationbyhandle_info.out = ctx.addr;
                if (VMI_FAILURE == vmi_write(vmi, &ctx, sizeof(struct by_handle_file_information), null_buf, NULL))
                    goto err;

                //p1
                info->regs->rcx = injector->handle;
                //p2
                info->regs->rdx = injector->getfileinformationbyhandle_info.out;

                // allocate 0x20 "homing space"
                uint64_t home_space[4] = { 0 };
                ctx.addr -= 0x20;
                if (VMI_FAILURE == vmi_write(vmi, &ctx, 0x20, home_space, NULL))
                    goto err;

                // save the return address
                ctx.addr -= 0x8;
                if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &info->regs->rip))
                    goto err;

                // Grow the stack
                info->regs->rsp = ctx.addr;
            }

            info->regs->rip = exec_func;

            injector->bp->name = "GetFileInformationByHandle ret";
            injector->bp->cb = getfileinformationbyhandle_cb;

            response = VMI_EVENT_RESPONSE_SET_REGISTERS;
        }

        goto done;
    }


err:
    PRINT_DEBUG("[FILEDELETE] [NtQueryObject] Error. Stop processing (CR3 0x%lx, TID %d).\n",
            info->regs->cr3, thread_id);

handled:
    thread = std::make_pair(info->regs->cr3, thread_id);
    injector->f->closing_handles[thread] = true;

    memcpy(info->regs, &injector->saved_regs, sizeof(x86_registers_t));
    response = VMI_EVENT_RESPONSE_SET_REGISTERS;

    drakvuf_remove_trap(drakvuf, injector->bp, (drakvuf_trap_free_t)free);

    delete injector;

done:
    drakvuf_release_vmi(drakvuf);

    return response;
}

/*
 * Intercept all handles close and filter file handles.
 *
 * The main difficulty is that this handler intercepts not only CloseHandle()
 * calls but returns from injected functions. To distinguish such situations
 * we use the regestry of processes/threads being processed.
 */
static event_response_t closehandle_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto response = 0;
    auto restore_regs = false;
    struct injector* injector = nullptr;
    const char* lib = "ntdll.dll";
    const char* fun = "NtQueryObject";
    addr_t exec_func = 0;

    filedelete* f = (filedelete*)info->trap->data;
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    access_context_t ctx;
    reg_t handle = 0;

    if (f->pm == VMI_PM_IA32E)
    {
        handle = info->regs->rcx;
    }
    else
    {
        ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
        ctx.dtb = info->regs->cr3;
        ctx.addr = info->regs->rsp + sizeof(uint32_t);
        if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, (uint32_t*) &handle) )
            goto err;
    }

    /*
     * Check if closing handle have been changed with NtWriteFile
     */
    if (f->files[info->proc_data.pid][handle].empty())
        goto err;


    injector = new struct injector;
    injector->f = f;
    injector->handle = handle;
    injector->is32bit = f->pm == VMI_PM_IA32E ? false : true;
    injector->target_cr3 = info->regs->cr3;
    injector->ntqueryobject_info.get_type_info = false;

    injector->eprocess_base = drakvuf_get_current_process(drakvuf, info->vcpu);
    if ( 0 == injector->eprocess_base )
    {
        PRINT_DEBUG("[FILEDELETE] Failed to get process base on vCPU 0x%d\n",
                    info->vcpu);
        goto err;
    }

    if ( !drakvuf_get_current_thread_id(drakvuf, info->vcpu, &injector->target_thread_id) ||
         !injector->target_thread_id )
    {
        PRINT_DEBUG("[FILEDELETE] Failed to get Thread ID\n");
        goto err;
    }

    exec_func = drakvuf_exportsym_to_va(drakvuf, injector->eprocess_base, lib, fun);
    if (!exec_func)
    {
        //PRINT_DEBUG("[FILEDELETE] Failed to get address of %s!%s\n", lib, fun);
        goto err;
    }
    injector->ntqueryobject_info.exec_func = exec_func;

    /*
     * Check if process/thread is being processed. If so skip it. Add it into
     * regestry otherwise.
     */
    {
        auto thread = std::make_pair(info->regs->cr3, injector->target_thread_id);
        auto thread_it = f->closing_handles.find(thread);
        auto map_end = f->closing_handles.end();
        if (map_end != thread_it)
        {
            bool handled = thread_it->second;
            if (handled)
                f->closing_handles.erase(thread);

            goto err;
        }
        else
            f->closing_handles[thread] = false;
    }

    /*
     * Real function body.
     *
     * Now we are sure this is new call to NtClose (not result of function injection) and
     * the Handle have been modified in NtWriteFile. So we should save it on the host.
     */
    memcpy(&injector->saved_regs, info->regs, sizeof(x86_registers_t));
    restore_regs = true;

    {
        access_context_t ctx =
        {
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3,
            .addr = info->regs->rsp,
        };

        if (injector->is32bit)
        {
            PRINT_DEBUG("[FILEDELETE] 32bit VMs not supported yet\n");
            goto err;
        }

        uint64_t nul64 = 0;

        ctx.addr -= 0x8;
        auto out_size_addr = ctx.addr;
        injector->ntqueryobject_info.out = out_size_addr;
        if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
            goto err;

        //p5
        ctx.addr -= 0x8;
        if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &out_size_addr))
            goto err;

        //p1
        info->regs->rcx = handle;
        //p2
        info->regs->rdx = 2; // OBJECT_INFORMATION_CLASS ObjectTypeInformation
        //p3
        info->regs->r8 = 0;
        //p4
        info->regs->r9 = 0;

        // allocate 0x20 "homing space"
        ctx.addr -= 0x8;
        if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
            goto err;

        ctx.addr -= 0x8;
        if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
            goto err;

        ctx.addr -= 0x8;
        if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
            goto err;

        ctx.addr -= 0x8;
        if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &nul64))
            goto err;

        // save the return address
        ctx.addr -= 0x8;
        if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &info->regs->rip))
            goto err;

        // Grow the stack
        info->regs->rsp = ctx.addr;
    }

    injector->bp = (drakvuf_trap_t*)g_malloc0(sizeof(drakvuf_trap_t));
    if (!injector->bp)
        goto err;

    injector->bp->type = BREAKPOINT;
    injector->bp->name = "NtQueryObject ret";
    injector->bp->cb = ntqueryobject_cb;
    injector->bp->data = injector;
    injector->bp->breakpoint.lookup_type = LOOKUP_DTB;
    injector->bp->breakpoint.dtb = info->regs->cr3;
    injector->bp->breakpoint.addr_type = ADDR_VA;
    injector->bp->breakpoint.addr = info->regs->rip;

    if ( !drakvuf_add_trap(drakvuf, injector->bp) )
    {
        fprintf(stderr, "Failed to trap return location of injected function call @ 0x%lx!\n",
                injector->bp->breakpoint.addr);
        goto err;
    }

    info->regs->rip = exec_func;

    response = VMI_EVENT_RESPONSE_SET_REGISTERS;

    goto done;

err:
    if (restore_regs)
        memcpy(info->regs, &injector->saved_regs, sizeof(x86_registers_t));

    if (injector)
        delete injector;

done:
    drakvuf_release_vmi(drakvuf);
    return response;
}

static event_response_t writefile_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    filedelete* f = (filedelete*)info->trap->data;
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    handle_t handle = 0;
    addr_t eprocess_base = 0;
    addr_t obj = 0; 
    uint8_t type = 0;
    unicode_string_t* filename_us = nullptr;
    addr_t file = 0;
    addr_t filename = 0;
    addr_t filetype = 0;
    access_context_t ctx;

    if (f->pm == VMI_PM_IA32E)
    {
        handle = info->regs->rcx;
    }
    else
    {
        ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
        ctx.dtb = info->regs->cr3;
        ctx.addr = info->regs->rsp + sizeof(uint32_t);
        if ( VMI_FAILURE == vmi_read_32(vmi, &ctx, (uint32_t*) &handle) )
            goto done;
    }

    eprocess_base = drakvuf_get_current_process(drakvuf, info->vcpu);
    if ( 0 == eprocess_base )
    {
        PRINT_DEBUG("[FILEDELETE] [NtWriteFile] Failed to get process base on vCPU 0x%d\n",
                    info->vcpu);
        goto done;
    }

    obj = drakvuf_get_obj_by_handle(drakvuf, eprocess_base, handle);
    if (!obj)
        goto done;

    file = obj + f->offsets[OBJECT_HEADER_BODY];
    filename = file + f->offsets[FILE_OBJECT_FILENAME];
    filetype = file + f->offsets[FILE_OBJECT_TYPE];

    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.addr = filetype;
    ctx.dtb = info->regs->cr3;

    if (VMI_FAILURE == vmi_read_8(vmi, &ctx, &type))
        goto done;

    if (type != 5)
        goto done;

    filename_us = drakvuf_read_unicode(drakvuf, info, filename);

    if (!filename_us)
        goto done;

    f->files[info->proc_data.pid][handle] = std::string((const char*)filename_us->contents);

done:
    drakvuf_release_vmi(drakvuf);
    return 0;
}

static event_response_t cr3_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto response = 0;
    addr_t exec_func = 0;
    const char* lib = "ntdll.dll";
    const char* fun = "NtClose";
    filedelete* f = (filedelete*)info->trap->data;

    auto eprocess_base = drakvuf_get_current_process(drakvuf, info->vcpu);
    if ( 0 == eprocess_base )
    {
        PRINT_DEBUG("[FILEDELETE] Failed to get process base on vCPU 0x%d\n",
                    info->vcpu);
        goto err;
    }

    exec_func = drakvuf_exportsym_to_va(drakvuf, eprocess_base, lib, fun);
    if (!exec_func)
    {
        //PRINT_DEBUG("[FILEDELETE] Failed to get address of %s!%s\n", lib, fun);
        goto err;
    }

    // Unsubscribe from the CR3 trap
    drakvuf_remove_trap(drakvuf, info->trap, (drakvuf_trap_free_t)free);

    f->traps[0].type = BREAKPOINT;
    f->traps[0].name = "NtClose";
    f->traps[0].cb = closehandle_cb;
    f->traps[0].data = info->trap->data;
    f->traps[0].breakpoint.lookup_type = LOOKUP_DTB;
    f->traps[0].breakpoint.dtb = info->regs->cr3;
    f->traps[0].breakpoint.addr_type = ADDR_VA;
    f->traps[0].breakpoint.addr = exec_func;

    if ( !drakvuf_add_trap(drakvuf, &f->traps[0]) )
    {
        fprintf(stderr, "Failed to trap return location of injected function call @ 0x%lx!\n",
                f->traps[0].breakpoint.addr);
        return 0;
    }

err:
    return response;
}

UNUSED
static void register_trap( drakvuf_t drakvuf, const char* rekall_profile, const char* syscall_name,
                           drakvuf_trap_t* trap,
                           event_response_t(*hook_cb)( drakvuf_t drakvuf, drakvuf_trap_info_t* info ) )
{
    if ( !drakvuf_get_function_rva( rekall_profile, syscall_name, &trap->breakpoint.rva) ) throw -1;

    trap->name = syscall_name;
    trap->cb   = hook_cb;

    if ( ! drakvuf_add_trap( drakvuf, trap ) ) throw -1;
}

filedelete::filedelete(drakvuf_t drakvuf, const void* config, output_format_t output)
    : sequence_number()
{
    const struct filedelete_config* c = (const struct filedelete_config*)config;
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    this->pm = vmi_get_page_mode(vmi, 0);
    this->domid = vmi_get_vmid(vmi);
    drakvuf_release_vmi(drakvuf);

    this->dump_folder = c->dump_folder;
    this->format = output;

    // Will be freed while "drakvuf_remove_trap()"
    drakvuf_trap_t* bp = (drakvuf_trap_t*)g_malloc0(sizeof(drakvuf_trap_t));
    if (!bp)
        throw -1;

    bp->type = REGISTER;
    bp->reg = CR3;
    bp->cb = cr3_cb;
    bp->data = this;
    if ( !drakvuf_add_trap(drakvuf, bp) )
        throw -1;

    // Slot 0 is used for "ntdll!NtClose" trap
    assert(sizeof(traps)/sizeof(traps[0]) > 1);
    register_trap(drakvuf, c->rekall_profile, "NtWriteFile", &traps[1], writefile_cb);

    this->offsets = (size_t*)malloc(sizeof(size_t)*__OFFSET_MAX);

    int i;
    for (i=0; i<__OFFSET_MAX; i++)
    {
        if ( !drakvuf_get_struct_member_rva(c->rekall_profile, offset_names[i][0], offset_names[i][1], &this->offsets[i]))
            throw -1;
    }

    if ( !drakvuf_get_struct_size(c->rekall_profile, "_CONTROL_AREA", &this->control_area_size) )
        throw -1;

    if ( VMI_PM_LEGACY == this->pm )
        this->mmpte_size = 4;
    else
        this->mmpte_size = 8;
}

filedelete::~filedelete()
{
    free(this->offsets);
}
