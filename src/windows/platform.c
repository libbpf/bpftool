// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (C) 2022 Microsoft */
#include "platform.h"

char*
dirname(char* path)
{
    static char dir[_MAX_DIR];
    dir[0] = 0;
    (void)_splitpath_s(path, NULL, 0, dir, sizeof(dir), NULL, 0, NULL, 0);
    return dir;
}

int getpagesize(void)
{
    SYSTEM_INFO info;
    GetSystemInfo(&info);
    return info.dwPageSize;
}

int
if_stringtoindex(char* name)
{
    int ifindex = atoi(name);
    if (!ifindex) {
        WCHAR if_alias[80];
        if (MultiByteToWideChar(CP_ACP, 0, name, -1, if_alias, sizeof(if_alias) / sizeof(*if_alias)) > 0) {
            NET_LUID if_luid;
            if (ConvertInterfaceAliasToLuid(if_alias, &if_luid) == ERROR_SUCCESS) {
                ConvertInterfaceLuidToIndex(&if_luid, (NET_IFINDEX*)&ifindex);
            }
        }
    }
    if (!ifindex)
        ifindex = if_nametoindex(name);
    return ifindex;
}
