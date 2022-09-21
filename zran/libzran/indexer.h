/*
   Copyright The Soci Snapshotter Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

/* 
  Copyright (C) 1995-2017 Jean-loup Gailly and Mark Adler
  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the authors be held liable for any damages
  arising from the use of this software.
  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:
  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.
  Jean-loup Gailly        Mark Adler
  jloup@gzip.org          madler@alumni.caltech.edu
*/
/* 
  This source code is based on 
  https://github.com/madler/zlib/blob/master/examples/zran.c 
  and related code from that repository. It retains the copyright and 
  distribution restrictions of that work. It has been substantially modified 
  from the original.
*/

#ifndef INDEXER_H
#define INDEXER_H

#include <stdint.h>
#include <stdio.h>

#include <string.h>
#include <zlib.h>

typedef unsigned char uchar;

/* Since gzip is compressed with 32 KiB window size, WINDOW_SIZE is fixed */
#define WINSIZE 32768U

enum 
{
    GZIP_INDEXER_OK = 0,
    GZIP_INDEXER_FILE_NOT_FOUND = -80,
    GZIP_INDEXER_INDEX_NULL = -81,
    GZIP_INDEXER_CANNOT_ALLOC = -82,
    GZIP_INDEXER_INVALID_BLOB = -83,
};

struct gzip_index_point
{
    off_t out;          /* corresponding offset in uncompressed data */
    off_t in;           /* offset in input file of first full byte */
    uint8_t bits;           /* number of bits (1-7) from byte at in - 1, or 0 */
    unsigned char window[WINSIZE];  /* preceding 32K of uncompressed data */    
};

struct gzip_index 
{
    int have;           /* number of list entries filled in */
    int size;           /* number of list entries allocated */
    struct gzip_index_point *list; /* allocated list */
    off_t span_size;
};


/* Get the index number of the point in the gzip index where
   the uncompressed offset is present 
*/
int pt_index_from_ucmp_offset(struct gzip_index* index, off_t off);

int generate_index_fp(FILE* fp, off_t span, struct gzip_index** index);
int generate_index(const char* filepath, off_t span, struct gzip_index** index);

// TODO: Improve this
int extract_data_from_buffer(void* d, off_t datalen, struct gzip_index* index, off_t offset, void* buffer, off_t len, int first_point_index);
int extract_data_fp(FILE *in, struct gzip_index *index, off_t offset, void *buf, int len);
int extract_data(const char* file, struct gzip_index* index, off_t offset, void* buf, int len);


int has_bits(struct gzip_index* index, int point_index);
off_t get_ucomp_off(struct gzip_index* index, int point_index);
off_t get_comp_off(struct gzip_index* index, int point_index);

/* Given a file's uncompressed start and end offset, returns the spans which
    contains those offsets
*/
int span_indices_for_file(struct gzip_index* index, off_t start, off_t end, void* index_start, void* index_end);

/* Subroutines to convert index to/from a binary blob */

/* Get size of blob given an index */
unsigned get_blob_size(struct gzip_index* index);

/* Converts index to blob
   Returns the size of the buffer on success
   This function assumes that the buffer is large enough already
   to hold the entire index
*/ 
int index_to_blob(struct gzip_index* index, void* buf);
struct gzip_index* blob_to_index(void* buf);

void free_index(struct gzip_index *index);

#endif // INDEXER_H
