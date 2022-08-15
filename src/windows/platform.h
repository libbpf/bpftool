// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (C) 2022 Microsoft */
#include <winsock2.h>
#include <io.h>
#include <windows.h>
#include <netioapi.h>

#define round_up(value, increment) increment*((value + increment - 1) / increment)

char*
dirname(char* path);

int getpagesize(void);

int
if_stringtoindex(char* name);
