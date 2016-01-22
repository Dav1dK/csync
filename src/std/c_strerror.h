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

#ifndef _C_STRERROR_H
#define _C_STRERROR_H

/**
 * @file c_strerror.h
 *
 * @brief Common error handling routines
 *
 * @defgroup cynErrorInternals cynapses libc error functions
 * @ingroup cynLibraryAPI
 *
 * @{
 */

/**
 * @brief Return a string describing an error number
 *
 * Because there are different versions of strerror_r avaible on different
 * systems depending on the #define strings, this is a common interface
 * to strerror_r, with a behavior which is a mix of the XSI compliant and
 * the GNU specific version.
 *
 * @param errnum    The error code to convert to a string.
 *
 * @param buf       The buffer to place the error string in.
 *                  If \p errnum is an unknown error code, the string
 *                  "Unkown error code" is placed in it.
 *
 * @param buflen    The size of \p buf. At most \p buflen - 1 characters are placed 
 *                  in buf, because a terminating null byte is added in any case.
 */
void c_strerror_r(int errnum, char *buf, size_t buflen);

/**
 * }@
 */

#endif /* _C_STRERROR_H */
