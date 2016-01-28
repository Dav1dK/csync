/*
 * cynapses libc functions
 *
 * Copyright (c) 2016-2016 by David Kahles <david.kahles96@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/* We want the XSI compatible version of c_strerror_r, but _GNU_SOURCE is defined all over the code.
   Thus, a GNU specific version would be used. Therefore we need this compilation unit. */
#undef _GNU_SOURCE
#define _POSIX_C_SOURCE 200112L

#include "config.h"
#include <string.h>
#include "c_strerror.h"
#include "c_macro.h"

#ifndef HAVE_STRERROR_R
#define strerror_r(errnum, buf, buflen) snprintf(buf, buflen, "%s", strerror(errnum))
#endif

void c_strerror_r(int errnum, char *buf, size_t buflen){
    if(unlikely(strerror_r(errnum, buf, buflen) != 0)){
        strncpy(buf, "Unknown error code", buflen - 1);
        buf[buflen - 1] = '\0';
    }
}
