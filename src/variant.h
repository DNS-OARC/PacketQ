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

#ifndef __packetq_variant_h
#define __packetq_variant_h

#include <cstdlib>

#include "MurmurHash3.h"
#include "refcountstring.h"

namespace packetq {

inline std::size_t hash_bytes(const char* bytes, int len)
{
    uint32_t result = 0;
    MurmurHash3_x86_32(bytes, len, 0, &result);
    return result;
}

// must be defined in this order - see the "if" statement
namespace Coltype {
    enum Type {
        _bool,
        _int,
        _float,
        _text,
        _max
    };
};

typedef bool     bool_column;
static const int bool_size  = sizeof(bool_column);
static const int bool_align = ((sizeof(bool_column) / sizeof(void*)) + 1) * sizeof(void*);

typedef int      int_column;
static const int int_size  = sizeof(int_column);
static const int int_align = ((sizeof(int_column) / sizeof(void*)) + 1) * sizeof(void*);

typedef double   float_column;
static const int float_size  = sizeof(float_column);
static const int float_align = ((sizeof(float_column) / sizeof(void*)) + 1) * sizeof(void*);

typedef RefCountString* text_column;
static const int        text_size  = sizeof(text_column);
static const int        text_align = ((sizeof(text_column) / sizeof(void*)) + 1) * sizeof(void*);

inline bool_column convert_column_to_bool(float_column v) { return v; }
inline bool_column convert_column_to_bool(int_column v) { return v; }
inline bool_column convert_column_to_bool(bool_column v) { return v; }
inline bool_column convert_column_to_bool(text_column v)
{
    return std::atoi(v->data);
}

inline int_column convert_column_to_int(float_column v) { return int(v); }
inline int_column convert_column_to_int(int_column v) { return v; }
inline int_column convert_column_to_int(bool_column v) { return v; }
inline int_column convert_column_to_int(text_column v)
{
    return v->data[0] != '\0';
}

inline float_column convert_column_to_float(float_column v) { return v; }
inline float_column convert_column_to_float(int_column v) { return v; }
inline float_column convert_column_to_float(bool_column v) { return v; }
inline float_column convert_column_to_float(text_column v)
{
    return std::atof(v->data);
}

inline text_column convert_column_to_text(float_column v)
{
    const int       bufsize = 50;
    RefCountString* str     = RefCountString::allocate(bufsize);
    snprintf(str->data, bufsize, "%g", v);
    return str;
}
inline text_column convert_column_to_text(int_column v)
{
    const int       bufsize = (sizeof(int_column) * 8 + 1) / 3 + 1;
    RefCountString* str     = RefCountString::allocate(bufsize);
    snprintf(str->data, bufsize, "%d", v);
    return str;
}
inline text_column convert_column_to_text(bool_column v)
{
    const int       bufsize = 1 + 1;
    RefCountString* str     = RefCountString::allocate(bufsize);
    if (v)
        str->data[0] = '1';
    else
        str->data[1] = '0';
    str->data[1]     = '\0';
    return str;
}
inline text_column convert_column_to_text(text_column v)
{
    // to stay symmetric with above functions that allocate a new string,
    // increment reference count
    v->inc_refcount();
    return v;
}

// Variant represents a value that can be either one of the column types,
// plus a type field to figure out which kind it represents
class Variant {
public:
    Variant()
    {
        m_type      = Coltype::_int;
        m_val.m_int = 0;
    }

    Variant(bool_column val)
    {
        m_type       = Coltype::_bool;
        m_val.m_bool = val;
    }

    Variant(int_column val)
    {
        m_type      = Coltype::_int;
        m_val.m_int = val;
    }

    Variant(float_column val)
    {
        m_type        = Coltype::_float;
        m_val.m_float = val;
    }

    Variant(text_column val)
    {
        m_type       = Coltype::_text;
        m_val.m_text = val;
        m_val.m_text->inc_refcount();
    }

    Variant(const Variant& other)
    {
        m_type = other.m_type;
        m_val  = other.m_val;
        if (m_type == Coltype::_text)
            m_val.m_text->inc_refcount();
    }

    // move constructor
    Variant(Variant&& other)
    {
        // would be cleaner to use default constructor, but alas
        // constructor delegation requires GCC >= 4.7
        m_type      = Coltype::_int;
        m_val.m_int = 0;

        swap(*this, other);
    }

    ~Variant()
    {
        if (m_type == Coltype::_text)
            m_val.m_text->dec_refcount();
    }

    Variant& operator=(Variant other)
    {
        // copy and swap idiom
        swap(*this, other);
        return *this;
    }

    inline friend void swap(Variant& first, Variant& second)
    {
        using std::swap;
        swap(first.m_type, second.m_type);
        swap(first.m_val, second.m_val);
    }

    bool_column get_bool() const
    {
        switch (m_type) {
        case Coltype::_float:
            return convert_column_to_bool(m_val.m_float);
        case Coltype::_int:
            return convert_column_to_bool(m_val.m_int);
        case Coltype::_bool:
            return convert_column_to_bool(m_val.m_bool);
        case Coltype::_text:
            return convert_column_to_bool(m_val.m_text);
        }
        return false;
    }

    int_column get_int() const
    {
        switch (m_type) {
        case Coltype::_float:
            return convert_column_to_int(m_val.m_float);
        case Coltype::_int:
            return convert_column_to_int(m_val.m_int);
        case Coltype::_bool:
            return convert_column_to_int(m_val.m_bool);
        case Coltype::_text:
            return convert_column_to_int(m_val.m_text);
        }
        return 0;
    }

    float_column get_float() const
    {
        switch (m_type) {
        case Coltype::_float:
            return convert_column_to_float(m_val.m_float);
        case Coltype::_int:
            return convert_column_to_float(m_val.m_int);
        case Coltype::_bool:
            return convert_column_to_float(m_val.m_bool);
        case Coltype::_text:
            return convert_column_to_float(m_val.m_text);
        }
        return 0.0;
    }

    // this returns a RefCountString with the ref-count incremented so
    // caller is responsible for decrementing after use
    text_column get_text() const
    {
        switch (m_type) {
        case Coltype::_float:
            return convert_column_to_text(m_val.m_float);
        case Coltype::_int:
            return convert_column_to_text(m_val.m_int);
        case Coltype::_bool:
            return convert_column_to_text(m_val.m_bool);
        case Coltype::_text:
            return convert_column_to_text(m_val.m_text);
        }
        return RefCountString::construct("");
    }

    int cmp(const Variant& rhs) const
    {
        switch (m_type) {
        case (Coltype::_bool):
            return m_val.m_bool - rhs.get_bool();
        case (Coltype::_int):
            return m_val.m_int - rhs.get_int();
        case (Coltype::_float): {
            float_column r = rhs.get_float();
            if (m_val.m_float < r)
                return -1;
            if (m_val.m_float > r)
                return 1;
            return 0;
        }
        case (Coltype::_text): {
            RefCountString* s   = rhs.get_text();
            auto            res = strcmp(m_val.m_text->data, s->data);
            s->dec_refcount();
            return res;
        }
        }
        return 0;
    }

    bool operator<(const Variant& rhs) const
    {
        return cmp(rhs) < 0;
    }
    bool operator==(const Variant& rhs) const
    {
        return cmp(rhs) == 0;
    }

    std::size_t hash() const
    {
        switch (m_type) {
        case (Coltype::_bool):
            return std::hash<bool>()(m_val.m_bool);
        case (Coltype::_int):
            return std::hash<int>()(m_val.m_int);
        case (Coltype::_float):
            return std::hash<float>()(m_val.m_float);
        case (Coltype::_text):
            return hash_bytes(m_val.m_text->data, strlen(m_val.m_text->data));
        }
        return 0;
    }

    Coltype::Type m_type;

private:
    union VariantUnion {
        bool_column  m_bool;
        int_column   m_int;
        float_column m_float;
        text_column  m_text;
    };

    VariantUnion m_val;
};

} // namespace packetq

#endif // __packetq_variant_h
