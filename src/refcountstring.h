/*
 * Copyright (c) 2017-2020, OARC, Inc.
 * Copyright (c) 2011-2017, IIS - The Internet Foundation in Sweden
 * All rights reserved.
 *
 * This file is part of PacketQ.
 *
 * PacketQ is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * PacketQ is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with PacketQ.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __packetq_refcountstring_h
#define __packetq_refcountstring_h

#include <cstdlib>
#include <cstring>

// A simple reference-counted C string, intended to be used through a pointer
// as RefCountString * with manual management of the reference count in order
// to stay a POD (for use in unions). For the same reason, constructors are
// static. The wrapper RefCountStringHandle can be used where automatic
// reference handling is possible.
struct RefCountString {
    // data
    int  count;
    char data[sizeof(int)]; // this is a dummy, actual array will be larger

    // implementation
    void inc_refcount()
    {
        count += 1;
    }

    void dec_refcount()
    {
        count -= 1;
        if (count == 0)
            std::free(this);
    }

    static RefCountString* allocate(int data_length)
    {
        std::size_t size = sizeof(RefCountString) - sizeof(char[sizeof(int)]) + data_length * sizeof(char);

        void* chunk = std::calloc(1, size);
        if (!chunk)
            throw std::bad_alloc();

        RefCountString* new_str = static_cast<RefCountString*>(chunk);
        new_str->count          = 1;
        return new_str;
    }

    static RefCountString* construct(const char* c_string)
    {
        std::size_t     length = std::strlen(c_string);
        RefCountString* str    = RefCountString::allocate(length + 1);
        std::memcpy(str->data, c_string, length + 1);
        return str;
    }

    static RefCountString* construct(const char* data, int from, int to)
    {
        int length = to - from;
        if (length < 0)
            length          = 0;
        RefCountString* str = RefCountString::allocate(length + 1);
        std::memcpy(str->data, data + from, length);
        str->data[length - 1 + 1] = '\0';
        return str;
    }
};

class RefCountStringHandle {
public:
    RefCountStringHandle()
    {
        value = 0;
    }

    RefCountStringHandle(RefCountString* str)
    {
        value = str;
    }

    ~RefCountStringHandle()
    {
        if (value)
            value->dec_refcount();
    }

    RefCountString* operator*()
    {
        return value;
    }

    void set(RefCountString* str)
    {
        if (value != str) {
            if (value)
                value->dec_refcount();
            value = str;
        }
    }

    RefCountString* value;
};

#endif // __packetq_refcountstring_h
