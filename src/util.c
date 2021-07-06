/*
 * util.c
 */
/*
 Copyright (C) 2020 Mathias Weidner <mathias@mamawe.net>

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

#include <stdio.h>

#include "util.h"

char *bytearray_to_string(const char *array, size_t as, char *buf, size_t bs)
{
	char *bp = buf;
	char *const ep = buf + bs;
	for (int i = 0; i < as; i++) {
		if (bp + 3 < ep) {
			bp += sprintf(bp, "%02hhX", array[i]);
		}
	}
	return buf;
}				// bytearray_to_string()
