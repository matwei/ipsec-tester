/*
 * util.h
 */
/*
 Copyright (C) 2018 Mathias Weidner <mathias@mamawe.net>

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef UTIL_H
#define UTIL_H

#include <stdlib.h>

typedef struct {
	unsigned char *ptr;
	size_t len;
} chunk_t;

char *bytearray_to_string(const char *, size_t, char *, size_t);

// taken from: Klemens, 21 Century C, O'Reilly, 2013

#define make_err_s(intype, shortname) \
    typedef struct {                  \
	    intype value;             \
	    char const * error;       \
    } shortname##_err_s

make_err_s(unsigned char *, buffer);
make_err_s(unsigned char const *, buffer_const);

#endif /* UTIL_H */
