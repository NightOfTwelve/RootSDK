/*****************************************************************************
* Copyright (C) 2013-2014 Ming Hu tewilove<at>gmail.com
*
* This file is part of RootSDK.
*
* This program is free software; you can redistribute it and/or modify it
* under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation; either version 2.1 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public License
* along with this program; if not, write to the Free Software Foundation,
* Inc., 51 Franklin Street, Fifth Floor, Boston MA 02110-1301, USA.
*****************************************************************************/


#include <sys/types.h>
#include <unistd.h>
#include <linux/sched.h>
#include <signal.h>
#include <sys/syscall.h>
#include <string.h>
#include <stdio.h>

static unsigned long kstack_base_get_cve20132141() {
    return 0;
}

struct media_entity_desc {
	__u32 id;
	char name[32];
	__u32 type;
	__u32 revision;
	__u32 flags;
	__u32 group_id;
	__u16 pads;
	__u16 links;

	__u32 reserved[4];

	union {
		/* Node specifications */
		struct {
			__u32 major;
			__u32 minor;
		} v4l;
		struct {
			__u32 major;
			__u32 minor;
		} fb;
		struct {
			__u32 card;
			__u32 device;
			__u32 subdevice;
		} alsa;
		int dvb;

		/* Sub-device specifications */
		/* Nothing needed yet */
		__u8 raw[184];
	};
};

#define MEDIA_IOC_ENUM_ENTITIES		_IOWR('|', 0x01, struct media_entity_desc)
#define MEDIA_ENT_ID_FLAG_NEXT      (1 << 31)

static unsigned long kstack_base_get_cve20141739() {
    return 0;
}

unsigned long kstack_base_get() {
    unsigned long ret;

    ret = kstack_base_get_cve20132141();
#ifdef __arm__
    if (ret >= 0xbf000000)
        return ret;
#endif
    ret = kstack_base_get_cve20141739();
#ifdef __arm__
    if (ret >= 0xbf000000)
        return ret;
#endif
    return 0;
}

