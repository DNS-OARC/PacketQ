/*
 * Copyright (c) 2017, OARC, Inc.
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

#ifndef __packetq_sql_h
#define __packetq_sql_h

#include <algorithm>
#include <functional>
#include <list>
#include <map>
#include <math.h>
#include <regex.h>
#include <set>
#include <stack>
#include <stdarg.h>
#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/types.h>
#include <vector>

#include "refcountstring.h"
#include "variant.h"

#ifdef WIN32
#define snprintf _snprintf
#endif

#define RE_LEN 64

namespace packetq {

extern int g_allocs;
static const int max_func_param = 4;
extern bool verbose;

inline void vlog(const char* fmt, ...)
{
    if (!verbose)
        return;

    char string[1024];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(string, sizeof(string), fmt, ap);
    va_end(ap);

    fprintf(stderr, "%s", string);
}

class Error {
public:
    Error(const char* fmt, ...)
    {
        char string[1024];
        va_list ap;

        va_start(ap, fmt);
        vsnprintf(string, sizeof(string), fmt, ap);
        va_end(ap);

        m_err = string;
    }
    std::string m_err;
};

class Query;
class Table;
class Parser;
class Row;
class Ordering_terms;

inline std::string lower(const char* s)
{
    std::string str = s;
    transform(str.begin(), str.end(), str.begin(), tolower);
    return str;
}

inline bool cmpi(const std::string& i_a, const char* b)
{
    std::string str = i_a;
    transform(str.begin(), str.end(), str.begin(), tolower);
    return (str.compare(b) == 0);
}

inline bool cmpii(const std::string& i_a, const char* b)
{
    std::string stra = i_a;
    transform(stra.begin(), stra.end(), stra.begin(), tolower);
    std::string strb = b;
    transform(strb.begin(), strb.end(), strb.begin(), tolower);
    return (stra.compare(strb) == 0);
}

inline const char* ind(int in)
{
    static const char spc[] = "                                                                                                    ";
    if (in < 0)
        in = 0;
    if (in > sizeof(spc) - 2)
        in = sizeof(spc) - 2;
    return &spc[sizeof(spc) - 1 - in];
}

class DB {
private:
    class Item {
    public:
        std::string m_function;
        int m_key;
        bool operator<(const Item& r) const
        {
            if (m_key < r.m_key)
                return true;
            if (m_key > r.m_key)
                return false;
            if (m_function < r.m_function)
                return true;
            return false;
        }
    };

public:
    DB();
    ~DB();

    bool query(const char* q);

    Table* create_table(const char* name);
    Table* create_or_use_table(const char* name);
    Table* get_table(const char* name);
    void add_lut(const char* table, int key, const char* value)
    {
        Item i;
        i.m_function = table;
        i.m_key = key;
        m_lut[i] = value;
    }

    RefCountString* get_value(const char* table, int key)
    {
        Item i;
        i.m_function = table;
        i.m_key = key;
        std::map<Item, std::string>::iterator it = m_lut.find(i);
        if (it != m_lut.end())
            // FIXME: we should store these strings in the first place
            return RefCountString::construct(it->second.c_str());

        return 0;
    }

private:
    std::map<std::string, Table*> m_tables;
    std::map<Item, std::string> m_lut;
};

extern DB g_db;

class Coldef {
public:
    int m_size;
    int m_align;
};

template <typename T>
class Allocator {
public:
    Allocator(int size, int buffersize)
        : m_buffersize(buffersize)
        , m_size(size)
    {
        add_buffer();
    }
    ~Allocator()
    {
        typename std::list<Buffer*>::iterator it = m_buffers.begin();
        while (it != m_buffers.end()) {
            delete *it;
            m_buffers.erase(it);
            it = m_buffers.begin();
        }
    }

    void add_buffer()
    {
        m_curr_buffer = new Buffer(*this);
        m_buffers.push_back(m_curr_buffer);
    }
    T* allocate()
    {

        T* obj = m_curr_buffer->allocate();
        if (!obj) {
            for (typename std::list<Buffer*>::iterator it = m_buffers.begin();
                 it != m_buffers.end();
                 it++) {
                if ((*it)->m_has_space)
                    obj = (*it)->allocate();
                if (obj) {
                    m_curr_buffer = *it;
                    break;
                }
            }
        }
        if (!obj) {
            add_buffer();
            obj = m_curr_buffer->allocate();
        }
        return obj;
    }
    void deallocate(T* item)
    {
        Buffer** buffptr = (Buffer**)item;
        buffptr[-1]->deallocate(item);
    }

private:
    class Buffer {
    public:
        friend class Allocator;
        Buffer(Allocator& allocator)
            : m_allocator(allocator)
        {
            m_has_space = true;
            m_used = 0;
            m_stride = (sizeof(Buffer*) + m_allocator.m_size);
            m_memory = (char*)malloc(m_stride * m_allocator.m_buffersize);
        }
        ~Buffer()
        {
            free(m_memory);
        }

        T* allocate()
        {
            T* obj = 0;
            if (m_free_list.size() > 0) {
                obj = m_free_list.top();
                m_free_list.pop();
            }
            if (!obj && m_used < m_allocator.m_buffersize) {
                char* ptr = &m_memory[m_stride * m_used++];
                Buffer** b = (Buffer**)ptr;
                *b = this;
                obj = (T*)(&b[1]);
            }
            m_has_space = true;
            if (!obj)
                m_has_space = false;
            return obj;
        }
        void deallocate(T* item)
        {
            m_has_space = true;
            memset(item, 0, m_allocator.m_size);
            m_free_list.push(item);
        }

        bool m_has_space;
        int m_stride;
        std::stack<T*> m_free_list;
        Allocator& m_allocator;
        int m_used;
        char* m_memory;
    };

    Buffer* m_curr_buffer;
    std::list<Buffer*> m_buffers;

    int m_buffersize;
    int m_size;
};

class Column {
public:
    static const bool HIDDEN = true;

    static Coldef m_coldefs[Coltype::_max];
    Column(const char* name, Coltype::Type type, int id, bool hidden);
    // called at startup by DB
    static void init_defs()
    {
        m_coldefs[Coltype::_bool].m_size = bool_size;
        m_coldefs[Coltype::_bool].m_align = bool_align;
        m_coldefs[Coltype::_int].m_size = int_size;
        m_coldefs[Coltype::_int].m_align = int_align;
        m_coldefs[Coltype::_float].m_size = float_size;
        m_coldefs[Coltype::_float].m_align = float_align;
        m_coldefs[Coltype::_text].m_size = text_size;
        m_coldefs[Coltype::_text].m_align = text_align;
    }
    std::string m_name;
    Coltype::Type m_type;
    Coldef& m_def;
    bool m_hidden;
    int m_id; // numeric id used by packet parsers for speed
    int m_offset;
};

// for accessing a field in a row
template <typename T>
class Accessor {
public:
    Accessor()
        : m_offset(0)
    {
    }

    T& value(Row* row);

    int m_offset;
};

typedef Accessor<bool_column> Bool_accessor;
typedef Accessor<int_column> Int_accessor;
typedef Accessor<float_column> Float_accessor;
typedef Accessor<text_column> Text_accessor;

// for writing a variant to a field in a row
class GenericAccessor {
public:
    void set(Row* row, const Variant& v);

    int m_offset;
    Coltype::Type m_type;
};

class Table {
public:
    Table(const char* name = 0, const char* query = 0)
        : m_rsize(0)
        , m_dsize(0)
    {
        m_row_allocator = 0;
        m_name = name ? name : "result";
        m_qstring = query ? query : "";
        m_curpos = 0;
    }
    ~Table()
    {
        for (auto i = m_rows.begin(), end = m_rows.end(); i != end; ++i)
            delete_row(*i);
        for (auto i = m_cols.begin(), end = m_cols.end(); i != end; ++i)
            delete *i;
        delete m_row_allocator;
    }
    static int align(int pos, int align)
    {
        int res = pos;
        int rem = pos % align;
        if (rem)
            res = pos + align - rem;
        return res;
    }
    int get_col_index(const char* col)
    {
        int i = 0;
        for (std::vector<Column*>::iterator it = m_cols.begin(); it != m_cols.end(); it++) {
            if (cmpii(m_cols[i]->m_name, col))
                return i;
            i++;
        }
        return -1;
    }
    int get_column_id(const char* col)
    {
        for (auto i = m_cols.begin(); i != m_cols.end(); ++i) {
            if (cmpii((*i)->m_name, col))
                return (*i)->m_id;
        }
        return -1;
    }

    template <typename T>
    Accessor<T> get_accessor(const char* col)
    {
        Accessor<T> res;
        res.m_offset = -1;

        int i = get_col_index(col);
        if (i >= 0)
            res.m_offset = m_cols[i]->m_offset;

        return res;
    }

    void dump();
    void json(bool trailing_comma);
    void csv(bool format = false);
    void xml();

    Column* add_column(const char* name, Coltype::Type type, int id = -1, bool hidden = false);
    Column* add_column(const char* name, const char* type, int id = -1, bool hidden = false);
    void merge_sort(Ordering_terms& order);
    void per_sort(Ordering_terms& order);
    Row* create_row();
    void delete_row(Row* row);
    void add_row(Row* row);
    void limit(int limit, int offset = 0);

    std::vector<Column*> m_cols;
    std::list<Row*> m_rows;
    int m_curpos;
    std::string m_name;
    std::string m_qstring;
    Allocator<Row>* m_row_allocator;
    int m_rsize;
    int m_dsize;
    std::vector<int> m_text_column_offsets;
};

class Row {
public:
    void zero_text_columns(const std::vector<int>& text_column_offsets)
    {
        for (auto i = text_column_offsets.begin(), end = text_column_offsets.end(); i != end; ++i)
            access_column<text_column>(*i) = 0;
    }

    void decref_text_columns(const std::vector<int>& text_column_offsets)
    {
        for (auto i = text_column_offsets.begin(), end = text_column_offsets.end(); i != end; ++i) {
            text_column& t = access_column<text_column>(*i);
            if (t)
                t->dec_refcount();
        }
    }

    void reset_text_columns(const std::vector<int>& text_column_offsets)
    {
        for (auto i = text_column_offsets.begin(), end = text_column_offsets.end(); i != end; ++i) {
            text_column& t = access_column<text_column>(*i);
            if (t) {
                t->dec_refcount();
                t = 0;
            }
        }
    }

    template <typename T>
    T& access_column(int offset)
    {
        void* ptr = m_data + offset;
        return *reinterpret_cast<T*>(ptr);
    }

    char m_data[4]; // dummy
};

template <typename T>
inline T& Accessor<T>::value(Row* row)
{
    return row->access_column<T>(m_offset);
}

inline void GenericAccessor::set(Row* row, const Variant& v)
{
    switch (m_type) {
    case Coltype::_bool:
        row->access_column<bool_column>(m_offset) = v.get_bool();
        break;

    case Coltype::_int:
        row->access_column<int_column>(m_offset) = v.get_int();
        break;

    case Coltype::_float:
        row->access_column<float_column>(m_offset) = v.get_float();
        break;

    case Coltype::_text:
        // reference count on string has already been incremented by get_text()
        // so we can assign the pointer directly
        row->access_column<text_column>(m_offset) = v.get_text();
        break;
    }
}

class Token {
public:
    enum Type {
        _invalid = 0,
        _label = 1,
        _number = 2,
        _op = 3,
        _uop = 4,
        _string = 5,
        _column = 6,
        _paren = 7,
        _function = 8,
        _semicolon = 9,
        _end = 10
    };

    Token(const Type type, const char* token)
    {
        m_type = type;
        m_token = token;
    }
    const char* get_token() const { return m_token.c_str(); }
    void set_token(const char* istr) { m_token = istr; }
    const Type get_type() const { return m_type; }
    void set_type(const Type type) { m_type = type; }
private:
    Type m_type;
    std::string m_token;
};

class OP : public Token {
public:
    static int is_binary(const char* str)
    {
        const char* bin_ops[] = { "||", "*", "/", "%", "+", "-", "<<", ">>", "&", "|", "<", "<=", ">", ">=", "=", "==", "!=", "<>", "is", "is not", "in", "like", "not like", "or", "and" };
        int pre_ops[] = { 8, 7, 7, 7, 6, 6, 5, 5, 5, 5, 4, 4, 4, 4, 3, 3, 3, 3, 3, 3, 3, 3, 3, 2, 1 };
        int len = sizeof(bin_ops) / sizeof(const char*);
        int idx = len - 1;
        while (idx >= 0) {
            if (cmpi(std::string(str), bin_ops[idx])) {
                return pre_ops[idx];
            }
            idx--;
        }
        return 0;
    }

    OP(const OP& op)
        : Token(op.get_type(), op.get_token())
    {
        for (int i = 0; i < max_param(); i++)
            m_param[i] = op.m_param[i];
        m_left = op.m_left;
        m_right = op.m_right;
        m_row_index = op.m_row_index;
        m_t = op.m_t;
        m_name = op.m_name;
        m_has_aggregate_function = op.m_has_aggregate_function;

        precedence();
    }
    OP(const Token& tok)
        : Token(tok.get_type(), tok.get_token())
    {
        for (int i = 0; i < max_param(); i++)
            m_param[i] = 0;
        m_left = m_right = 0;
        m_row_index = -1;
        m_t = Coltype::_int;
        m_name = "";
        m_has_aggregate_function = false;

        precedence();
    }
    virtual ~OP()
    {
        for (int i = 0; i < max_param(); i++)
            if (m_param[i])
                delete m_param[i];
        if (m_left)
            delete m_left;
        if (m_right)
            delete m_right;
    }
    static int max_param()
    {
        return max_func_param;
    }
    void clear_ptr()
    {
        for (int i = 0; i < max_param(); i++)
            m_param[i] = 0;
        m_left = m_right = 0;
    }
    void precedence()
    {
        m_precedence = is_binary(get_token());
    }
    const char* get_name()
    {
        if (m_name.length() > 0)
            return m_name.c_str();

        m_name = "";
        if (m_left) {
            m_name += "(";
            m_name += m_left->get_name();
        }
        m_name += get_token();
        if (m_right) {
            if (!m_left)
                m_name += "(";
            m_name += m_right->get_name();
            m_name += ")";
        }
        if (m_param[0]) {
            m_name += "(";
            for (int i = 0; i < max_param(); i++)
                if (m_param[i]) {
                    if (i > 0)
                        m_name += ",";
                    m_name += m_param[i]->get_name();
                }
            m_name += ")";
        }
        //m_name+=")";
        return m_name.c_str();
    }
    Coltype::Type ret_type() { return m_t; }

    // add a hidden column for storing intermediate results
    template <typename T>
    T add_intermediate_column(Table* table, std::string name_suffix, Coltype::Type type)
    {
        std::string name = std::string(get_name()) + name_suffix;
        Column* column = table->add_column(name.c_str(), type, -1, Column::HIDDEN);
        T res;
        res.m_offset = column->m_offset;
        return res;
    }

    virtual void evaluate(Row** rows, Variant& v) { throw Error("evaluate() called on abstract OP class"); };
    virtual void evaluate_aggregate_operands(Row** rows);
    virtual void combine_aggregate(Row* base_row, Row* other_row);
    OP* compile(const std::vector<Table*>& tables,
        const std::vector<int>& search_order, Query& q);
    int m_row_index;
    std::string m_name;
    int m_precedence;
    OP* m_param[max_func_param];
    OP* m_left;
    OP* m_right;
    Coltype::Type m_t;
    bool m_has_aggregate_function;
};

////////////////// column accessors

class Column_access_int : public OP {
public:
    Column_access_int(const OP& op, int offset)
        : OP(op)
    {
        m_accessor.m_offset = offset;
    }
    void evaluate(Row** rows, Variant& v)
    {
        v = m_accessor.value(rows[m_row_index]);
    }
    Int_accessor m_accessor;
};

class Column_access_bool : public OP {
public:
    Column_access_bool(const OP& op, int offset)
        : OP(op)
    {
        m_accessor.m_offset = offset;
    }
    void evaluate(Row** rows, Variant& v)
    {
        v = m_accessor.value(rows[m_row_index]);
    }
    Bool_accessor m_accessor;
};

class Column_access_float : public OP {
public:
    Column_access_float(const OP& op, int offset)
        : OP(op)
    {
        m_accessor.m_offset = offset;
    }
    void evaluate(Row** rows, Variant& v)
    {
        v = m_accessor.value(rows[m_row_index]);
    }
    Float_accessor m_accessor;
};

class Column_access_text : public OP {
public:
    Column_access_text(const OP& op, int offset)
        : OP(op)
    {
        m_accessor.m_offset = offset;
    }
    void evaluate(Row** rows, Variant& v)
    {
        v = m_accessor.value(rows[m_row_index]);
    }
    Text_accessor m_accessor;
};

///////////////// Static numbers

class Static_int : public OP {
public:
    Static_int(const OP& op)
        : OP(op)
    {
        m_val = atoi(get_token());
    }
    void evaluate(Row** rows, Variant& v)
    {
        v = m_val;
    }
    int m_val;
};

class Static_float : public OP {
public:
    Static_float(const OP& op)
        : OP(op)
    {
        m_val = atof(get_token());
    }
    void evaluate(Row** rows, Variant& v)
    {
        v = m_val;
    }
    double m_val;
};

class Static_text : public OP {
public:
    Static_text(const OP& op)
        : OP(op)
    {
        m_val.set(RefCountString::construct(get_token()));
    }
    void evaluate(Row** rows, Variant& v)
    {
        v = *m_val;
    }
    RefCountStringHandle m_val;
};

///////////////// Functions
class Truncate_func : public OP {
public:
    Truncate_func(const OP& op)
        : OP(op)
    {
    }
    void evaluate(Row** rows, Variant& v)
    {
        Variant val;
        m_param[0]->evaluate(rows, val);
        v = val.get_int();
    }
};

class Name_func : public OP {
public:
    Name_func(const OP& op)
        : OP(op)
    {
    }
    void evaluate(Row** rows, Variant& v)
    {
        Variant str, num;
        m_param[0]->evaluate(rows, str);
        m_param[1]->evaluate(rows, num);

        int_column n = num.get_int();
        RefCountStringHandle lookup(str.get_text());
        RefCountStringHandle r(g_db.get_value((*lookup)->data, n));

        if (!*r)
            r.set(num.get_text());

        v = *r;
    }
};

class Lower_func : public OP {
public:
    Lower_func(const OP& op)
        : OP(op)
    {
    }
    void evaluate(Row** rows, Variant& v)
    {
        Variant str;
        m_param[0]->evaluate(rows, str);
        RefCountStringHandle src(str.get_text());

        int l = strlen((*src)->data);
        RefCountStringHandle dest(RefCountString::allocate(l + 1));
        int p = 0;
        while ((*src)->data[p]) {
            char c = (*src)->data[p];
            if (c >= 'A' && c <= 'Z')
                c = c - 'A' + 'a';
            (*dest)->data[p] = c;
            p++;
        }
        (*dest)->data[p] = 0;

        v = *dest;
    }
};

class Rsplit_func : public OP {
public:
    Rsplit_func(const OP& op)
        : OP(op)
    {
    }
    void evaluate(Row** rows, Variant& v)
    {
        char sep = '.';
        Variant str, num;
        m_param[0]->evaluate(rows, str);
        m_param[1]->evaluate(rows, num);

        if (m_param[2]) {
            Variant vsep;
            m_param[2]->evaluate(rows, vsep);
            RefCountStringHandle sep_text(vsep.get_text());
            const char* s = (*sep_text)->data;
            if (s)
                sep = s[0];
        }

        int n = num.get_int();
        RefCountStringHandle src(str.get_text());
        const char* s = (*src)->data;
        int l = strlen(s);
        if (!l) {
            RefCountStringHandle res(RefCountString::construct(""));
            v = *res;
            return;
        }
        int p = l - 1;
        int found = 0, end = l, start = 0;
        if (n == 0)
            end = p + 1;
        while (p >= 0) {
            char c = s[p];
            if (c == sep) {
                found++;
                if (found == n)
                    end = p;
                if (found == n + 1)
                    start = p + 1;
            }
            p--;
        }
        char buf[256]; // FIXME: arbitrary limitation, would probably be
        // better to allocate result buffer directly
        if (found < n || start >= l || end - start > sizeof(buf)) {
            RefCountStringHandle res(RefCountString::construct(""));
            v = *res;
            return;
        }
        p = 0;
        while (start < end)
            buf[p++] = s[start++];
        buf[p] = 0;

        RefCountStringHandle res(RefCountString::construct(buf));
        v = *res;
    }
};

class Len_func : public OP {
public:
    Len_func(const OP& op)
        : OP(op)
    {
    }
    void evaluate(Row** rows, Variant& v)
    {
        Variant str;
        m_param[0]->evaluate(rows, str);
        RefCountStringHandle t(str.get_text());
        v = int(strlen((*t)->data));
    }
};

class Trim_func : public OP {
public:
    Trim_func(const OP& op)
        : OP(op)
    {
    }
    void evaluate(Row** rows, Variant& v);
};

class If_func : public OP {
public:
    If_func(const OP& op)
        : OP(op)
    {
    }
    void evaluate(Row** rows, Variant& v)
    {
        Variant cond;
        m_param[0]->evaluate(rows, cond);
        if (cond.get_bool())
            m_param[1]->evaluate(rows, v);
        else
            m_param[2]->evaluate(rows, v);
    }
};

// Aggregate functions, generally these store their calculations in hidden
// columns

class Min_func_int : public OP {
public:
    Min_func_int(const OP& op, Table* dest_table)
        : OP(op)
    {
        m_has_aggregate_function = true;
        acc_min = add_intermediate_column<Int_accessor>(dest_table, ".min", Coltype::_int);
    }
    virtual void evaluate_aggregate_operands(Row** rows)
    {
        Variant p;
        m_param[0]->evaluate(rows, p);
        acc_min.value(rows[m_row_index]) = p.get_int();
    }
    virtual void combine_aggregate(Row* base_row, Row* next_row)
    {
        int_column n = acc_min.value(next_row);
        if (n < acc_min.value(base_row))
            acc_min.value(base_row) = n;
    }
    void evaluate(Row** rows, Variant& v)
    {
        v = acc_min.value(rows[m_row_index]);
    }

    Int_accessor acc_min;
};

class Min_func_float : public OP {
public:
    Min_func_float(const OP& op, Table* dest_table)
        : OP(op)
    {
        m_has_aggregate_function = true;
        acc_min = add_intermediate_column<Float_accessor>(dest_table, ".min", Coltype::_float);
    }
    virtual void evaluate_aggregate_operands(Row** rows)
    {
        Variant p;
        m_param[0]->evaluate(rows, p);
        acc_min.value(rows[m_row_index]) = p.get_float();
    }
    virtual void combine_aggregate(Row* base_row, Row* next_row)
    {
        float_column n = acc_min.value(next_row);
        if (n < acc_min.value(base_row))
            acc_min.value(base_row) = n;
    }
    void evaluate(Row** rows, Variant& v)
    {
        v = acc_min.value(rows[m_row_index]);
    }

    Float_accessor acc_min;
};

class Max_func_int : public OP {
public:
    Max_func_int(const OP& op, Table* dest_table)
        : OP(op)
    {
        m_has_aggregate_function = true;
        acc_max = add_intermediate_column<Int_accessor>(dest_table, ".max", Coltype::_int);
    }
    virtual void evaluate_aggregate_operands(Row** rows)
    {
        Variant p;
        m_param[0]->evaluate(rows, p);
        acc_max.value(rows[m_row_index]) = p.get_int();
    }
    virtual void combine_aggregate(Row* base_row, Row* next_row)
    {
        int_column n = acc_max.value(next_row);
        if (n > acc_max.value(base_row))
            acc_max.value(base_row) = n;
    }
    void evaluate(Row** rows, Variant& v)
    {
        v = acc_max.value(rows[m_row_index]);
    }

    Int_accessor acc_max;
};

class Max_func_float : public OP {
public:
    Max_func_float(const OP& op, Table* dest_table)
        : OP(op)
    {
        m_has_aggregate_function = true;
        acc_max = add_intermediate_column<Float_accessor>(dest_table, ".max", Coltype::_float);
    }
    virtual void evaluate_aggregate_operands(Row** rows)
    {
        Variant p;
        m_param[0]->evaluate(rows, p);
        acc_max.value(rows[m_row_index]) = p.get_float();
    }
    virtual void combine_aggregate(Row* base_row, Row* next_row)
    {
        float_column n = acc_max.value(next_row);
        if (n > acc_max.value(base_row))
            acc_max.value(base_row) = n;
    }
    void evaluate(Row** rows, Variant& v)
    {
        v = acc_max.value(rows[m_row_index]);
    }

    Float_accessor acc_max;
};

class Stdev_func : public OP {
public:
    Stdev_func(const OP& op, Table* dest_table)
        : OP(op)
    {
        m_has_aggregate_function = true;
        acc_sum = add_intermediate_column<Float_accessor>(dest_table, ".sum", Coltype::_float);
        acc_sum_sq = add_intermediate_column<Float_accessor>(dest_table, ".sumsquared", Coltype::_float);
        acc_count = add_intermediate_column<Int_accessor>(dest_table, ".count", Coltype::_int);
    }
    virtual void evaluate_aggregate_operands(Row** rows)
    {
        Variant p;
        m_param[0]->evaluate(rows, p);
        float_column val = p.get_float();

        acc_sum.value(rows[m_row_index]) = val;
        acc_sum_sq.value(rows[m_row_index]) = val * val;
        acc_count.value(rows[m_row_index]) = 1;
    }
    virtual void combine_aggregate(Row* base_row, Row* next_row)
    {
        acc_sum.value(base_row) = acc_sum.value(base_row) + acc_sum.value(next_row);
        acc_sum_sq.value(base_row) = acc_sum_sq.value(base_row) + acc_sum_sq.value(next_row);
        acc_count.value(base_row) = acc_count.value(base_row) + acc_count.value(next_row);
    }
    void evaluate(Row** rows, Variant& v)
    {
        Row* row = rows[m_row_index];
        int c = acc_count.value(row);
        if (c == 0)
            c = 1;
        double mean = acc_sum.value(row) / c;
        double variance = acc_sum_sq.value(row) / c - mean * mean;

        v = sqrt(variance);
    }

    Float_accessor acc_sum, acc_sum_sq;
    Int_accessor acc_count;
};

class Avg_func : public OP {
public:
    Avg_func(const OP& op, Table* dest_table)
        : OP(op)
    {
        m_has_aggregate_function = true;
        acc_sum = add_intermediate_column<Float_accessor>(dest_table, ".sum", Coltype::_float);
        acc_count = add_intermediate_column<Int_accessor>(dest_table, ".count", Coltype::_int);
    }
    virtual void evaluate_aggregate_operands(Row** rows)
    {
        Variant p;
        m_param[0]->evaluate(rows, p);
        acc_sum.value(rows[m_row_index]) = p.get_float();
        acc_count.value(rows[m_row_index]) = 1;
    }
    virtual void combine_aggregate(Row* base_row, Row* next_row)
    {
        acc_sum.value(base_row) = acc_sum.value(base_row) + acc_sum.value(next_row);
        acc_count.value(base_row) = acc_count.value(base_row) + acc_count.value(next_row);
    }
    void evaluate(Row** rows, Variant& v)
    {
        v = acc_sum.value(rows[m_row_index]) / acc_count.value(rows[m_row_index]);
    }

    Float_accessor acc_sum;
    Int_accessor acc_count;
};

class Sum_func_int : public OP {
public:
    Sum_func_int(const OP& op, Table* dest_table)
        : OP(op)
    {
        m_has_aggregate_function = true;
        acc_sum = add_intermediate_column<Int_accessor>(dest_table, ".sum", Coltype::_int);
    }
    virtual void evaluate_aggregate_operands(Row** rows)
    {
        Variant p;
        m_param[0]->evaluate(rows, p);
        acc_sum.value(rows[m_row_index]) = p.get_int();
    }
    virtual void combine_aggregate(Row* base_row, Row* next_row)
    {
        acc_sum.value(base_row) = acc_sum.value(base_row) + acc_sum.value(next_row);
    }
    void evaluate(Row** rows, Variant& v)
    {
        v = acc_sum.value(rows[m_row_index]);
    }

    Int_accessor acc_sum;
};

class Sum_func_float : public OP {
public:
    Sum_func_float(const OP& op, Table* dest_table)
        : OP(op)
    {
        m_has_aggregate_function = true;
        acc_sum = add_intermediate_column<Float_accessor>(dest_table, ".sum", Coltype::_float);
    }
    virtual void evaluate_aggregate_operands(Row** rows)
    {
        Variant p;
        m_param[0]->evaluate(rows, p);
        acc_sum.value(rows[m_row_index]) = p.get_float();
    }
    virtual void combine_aggregate(Row* base_row, Row* next_row)
    {
        acc_sum.value(base_row) = acc_sum.value(base_row) + acc_sum.value(next_row);
    }
    void evaluate(Row** rows, Variant& v)
    {
        v = acc_sum.value(rows[m_row_index]);
    }

    Float_accessor acc_sum;
};

class Count_func : public OP {
public:
    Count_func(const OP& op, Table* dest_table)
        : OP(op)
    {
        m_has_aggregate_function = true;
        acc_count = add_intermediate_column<Int_accessor>(dest_table, ".count", Coltype::_int);
    }
    virtual void evaluate_aggregate_operands(Row** rows)
    {
        acc_count.value(rows[m_row_index]) = 1;
    }
    virtual void combine_aggregate(Row* base_row, Row* next_row)
    {
        acc_count.value(base_row) = acc_count.value(base_row) + acc_count.value(next_row);
    }
    void evaluate(Row** rows, Variant& v)
    {
        v = acc_count.value(rows[m_row_index]);
    }

    Int_accessor acc_count;
};

//////////////// Binary ops

class Bin_op_eq : public OP {
public:
    Bin_op_eq(const OP& op)
        : OP(op)
    {
    }
    void evaluate(Row** rows, Variant& v)
    {
        Variant lhs, rhs;
        m_left->evaluate(rows, lhs);
        m_right->evaluate(rows, rhs);
        v = bool(lhs == rhs);
    }
};
class Bin_op_not_eq : public OP {
public:
    Bin_op_not_eq(const OP& op)
        : OP(op)
    {
    }
    void evaluate(Row** rows, Variant& v)
    {
        Variant lhs, rhs;
        m_left->evaluate(rows, lhs);
        m_right->evaluate(rows, rhs);
        v = !bool(lhs == rhs);
    }
};
class Bin_op_or : public OP {
public:
    Bin_op_or(const OP& op)
        : OP(op)
    {
    }
    void evaluate(Row** rows, Variant& v)
    {
        m_left->evaluate(rows, v);
        if (v.get_bool()) {
            v = true;
            return;
        }
        m_right->evaluate(rows, v);
        v = v.get_bool();
    }
};

class Bin_op_and : public OP {
public:
    Bin_op_and(const OP& op)
        : OP(op)
    {
    }
    void evaluate(Row** rows, Variant& v)
    {
        m_left->evaluate(rows, v);
        if (!v.get_bool()) {
            v = false;
            return;
        }
        m_right->evaluate(rows, v);
        v = v.get_bool();
    }
};
class Bin_op_lt : public OP {
public:
    Bin_op_lt(const OP& op)
        : OP(op)
    {
    }
    void evaluate(Row** rows, Variant& v)
    {
        Variant lhs, rhs;
        m_left->evaluate(rows, lhs);
        m_right->evaluate(rows, rhs);
        v = bool(lhs < rhs);
    }
};
class Bin_op_gt : public OP {
public:
    Bin_op_gt(const OP& op)
        : OP(op)
    {
    }
    void evaluate(Row** rows, Variant& v)
    {
        Variant lhs, rhs;
        m_left->evaluate(rows, lhs);
        m_right->evaluate(rows, rhs);
        v = bool(rhs < lhs);
    }
};
class Bin_op_lteq : public OP {
public:
    Bin_op_lteq(const OP& op)
        : OP(op)
    {
    }
    void evaluate(Row** rows, Variant& v)
    {
        Variant lhs, rhs;
        m_left->evaluate(rows, lhs);
        m_right->evaluate(rows, rhs);
        v = !bool(rhs < lhs);
    }
};
class Bin_op_gteq : public OP {
public:
    Bin_op_gteq(const OP& op)
        : OP(op)
    {
    }
    void evaluate(Row** rows, Variant& v)
    {
        Variant lhs, rhs;
        m_left->evaluate(rows, lhs);
        m_right->evaluate(rows, rhs);
        v = !bool(lhs < rhs);
    }
};
class Bin_op_add : public OP {
public:
    Bin_op_add(const OP& op)
        : OP(op)
    {
    }
    void evaluate(Row** rows, Variant& v)
    {
        Variant lhs, rhs;
        m_left->evaluate(rows, lhs);
        m_right->evaluate(rows, rhs);
        v = lhs.get_int() + rhs.get_int();
    }
};
class Bin_op_add_float : public OP {
public:
    Bin_op_add_float(const OP& op)
        : OP(op)
    {
    }
    void evaluate(Row** rows, Variant& v)
    {
        Variant lhs, rhs;
        m_left->evaluate(rows, lhs);
        m_right->evaluate(rows, rhs);
        v = lhs.get_float() + rhs.get_float();
    }
};
class Bin_op_sub : public OP {
public:
    Bin_op_sub(const OP& op)
        : OP(op)
    {
    }
    void evaluate(Row** rows, Variant& v)
    {
        Variant lhs, rhs;
        m_left->evaluate(rows, lhs);
        m_right->evaluate(rows, rhs);
        v = lhs.get_int() - rhs.get_int();
    }
};
class Bin_op_sub_float : public OP {
public:
    Bin_op_sub_float(const OP& op)
        : OP(op)
    {
    }
    void evaluate(Row** rows, Variant& v)
    {
        Variant lhs, rhs;
        m_left->evaluate(rows, lhs);
        m_right->evaluate(rows, rhs);
        v = lhs.get_float() - rhs.get_float();
    }
};

class Bin_op_mul : public OP {
public:
    Bin_op_mul(const OP& op)
        : OP(op)
    {
    }
    void evaluate(Row** rows, Variant& v)
    {
        Variant lhs, rhs;
        m_left->evaluate(rows, lhs);
        m_right->evaluate(rows, rhs);
        v = lhs.get_int() * rhs.get_int();
    }
};
class Bin_op_mul_float : public OP {
public:
    Bin_op_mul_float(const OP& op)
        : OP(op)
    {
    }
    void evaluate(Row** rows, Variant& v)
    {
        Variant lhs, rhs;
        m_left->evaluate(rows, lhs);
        m_right->evaluate(rows, rhs);
        v = lhs.get_float() * rhs.get_float();
    }
};
class Bin_op_div : public OP {
public:
    Bin_op_div(const OP& op)
        : OP(op)
    {
    }
    void evaluate(Row** rows, Variant& v)
    {
        Variant lhs, rhs;
        m_left->evaluate(rows, lhs);
        m_right->evaluate(rows, rhs);
        v = lhs.get_float() / rhs.get_float();
    }
};
class Bin_op_modulo : public OP {
public:
    Bin_op_modulo(const OP& op)
        : OP(op)
    {
    }
    void evaluate(Row** rows, Variant& v)
    {
        Variant lhs, rhs;
        m_left->evaluate(rows, lhs);
        m_right->evaluate(rows, rhs);
        v = fmod(lhs.get_float(), rhs.get_float());
    }
};
class Bin_op_arithmetic_shift_left : public OP {
public:
    Bin_op_arithmetic_shift_left(const OP& op)
        : OP(op)
    {
    }
    void evaluate(Row** rows, Variant& v)
    {
        Variant lhs, rhs;
        m_left->evaluate(rows, lhs);
        m_right->evaluate(rows, rhs);
        v = lhs.get_int() << rhs.get_int();
    }
};
class Bin_op_arithmetic_shift_right : public OP {
public:
    Bin_op_arithmetic_shift_right(const OP& op)
        : OP(op)
    {
    }
    void evaluate(Row** rows, Variant& v)
    {
        Variant lhs, rhs;
        m_left->evaluate(rows, lhs);
        m_right->evaluate(rows, rhs);
        v = lhs.get_int() >> rhs.get_int();
    }
};
class Bin_op_bitwise_and : public OP {
public:
    Bin_op_bitwise_and(const OP& op)
        : OP(op)
    {
    }
    void evaluate(Row** rows, Variant& v)
    {
        Variant lhs, rhs;
        m_left->evaluate(rows, lhs);
        m_right->evaluate(rows, rhs);
        v = lhs.get_int() & rhs.get_int();
    }
};
class Bin_op_bitwise_or : public OP {
public:
    Bin_op_bitwise_or(const OP& op)
        : OP(op)
    {
    }
    void evaluate(Row** rows, Variant& v)
    {
        Variant lhs, rhs;
        m_left->evaluate(rows, lhs);
        m_right->evaluate(rows, rhs);
        v = lhs.get_int() | rhs.get_int();
    }
};
class Bin_op_concatenate : public OP {
public:
    Bin_op_concatenate(const OP& op)
        : OP(op)
    {
    }
    void evaluate(Row** rows, Variant& v)
    {
        Variant lhs, rhs;
        m_left->evaluate(rows, lhs);
        m_right->evaluate(rows, rhs);
        RefCountStringHandle lhandle(lhs.get_text()), rhandle(rhs.get_text());
        const char* lhs_str = (*lhandle)->data;
        const char* rhs_str = (*rhandle)->data;

        int l = (int)strlen(lhs_str);
        int r = (int)strlen(rhs_str);

        RefCountStringHandle res = RefCountString::allocate(l + r + 1);
        memcpy((*res)->data, lhs_str, l);
        memcpy((*res)->data + l, rhs_str, r + 1); // copy the zero terminator

        v = *res;
    }
};
class Bin_op_like : public OP {
private:
    regex_t m_re;
    char m_re_str[RE_LEN];
    bool m_compiled;
    int m_err;

public:
    Bin_op_like(const OP& op)
        : OP(op)
        , m_re()
    {
        m_err = 0;
        m_compiled = false;
    }
    void regex_from_like(const char* s, char* r, int l)
    {
        char* stop = r + l - 4;
        if (r < stop) {
            *r++ = '^';
            while (r < stop and *s) {
                //		    printf("s: %s\n", s);
                if (*s == '\\') {
                    s++;
                    if (*s) {
                        *r = *s;
                    } else {
                        s--;
                    }
                } else if (*s == '.') {
                    *r++ = '\\';
                    *r = '.';
                } else if (*s == '*') {
                    *r++ = '\\';
                    *r = '*';
                } else if (*s == '%') {
                    *r++ = '.';
                    *r = '*';
                } else if (*s == '_') {
                    *r = '.';
                } else {
                    *r = *s;
                }
                s++;
                r++;
                //		    printf("r: %s\n\n", start);
            }
            *r++ = '$';
            *r = '\0';
        }
        //	    printf("r: %s\n\n", start);
        //	    printf("Done\n\n");
    }
    void evaluate(Row** rows, Variant& v)
    {
        Variant lhs, rhs;
        m_left->evaluate(rows, lhs);
        m_right->evaluate(rows, rhs);
        RefCountStringHandle lhandle(lhs.get_text()), rhandle(rhs.get_text());
        const char* lstr = (*lhandle)->data;
        const char* rstr = (*rhandle)->data;
        if (!m_compiled) {
            m_compiled = true; // Set this before we try; no need to try again if we fail
            regex_from_like(rstr, m_re_str, RE_LEN);
            m_err = regcomp(&m_re, m_re_str, REG_NOSUB);
            if (m_err) {
                char errstr[RE_LEN];
                regerror(m_err, &m_re, errstr, RE_LEN);
                printf("Error compiling regex: %d: %s", m_err, errstr);
            }
        }
        if (m_err)
            v = false;
        else
            v = regexec(&m_re, lstr, 0, 0, 0) == 0;
    }
    ~Bin_op_like()
    {
        if (m_compiled) {
            regfree(&m_re);
        }
    }
};
class Bin_op_not_like : public Bin_op_like {
public:
    Bin_op_not_like(const OP& op)
        : Bin_op_like(op)
    {
    }
    void evaluate(Row** rows, Variant& v)
    {
        Bin_op_like::evaluate(rows, v);
        v = !v.get_bool();
    }
};
////////////////// unary ops

class Un_op_not : public OP {
public:
    Un_op_not(const OP& op)
        : OP(op)
    {
    }
    void evaluate(Row** rows, Variant& v)
    {
        Variant rhs;
        m_right->evaluate(rows, rhs);
        v = !rhs.get_bool();
    }
};

class Un_op_neg : public OP {
public:
    Un_op_neg(const OP& op)
        : OP(op)
    {
    }
    void evaluate(Row** rows, Variant& v)
    {
        Variant rhs;
        m_right->evaluate(rows, rhs);
        v = -rhs.get_int();
    }
};

class Un_op_neg_float : public OP {
public:
    Un_op_neg_float(const OP& op)
        : OP(op)
    {
    }
    void evaluate(Row** rows, Variant& v)
    {
        Variant rhs;
        m_right->evaluate(rows, rhs);
        v = -rhs.get_float();
    }
};

class Un_op_ones_complement : public OP {
public:
    Un_op_ones_complement(const OP& op)
        : OP(op)
    {
    }
    void evaluate(Row** rows, Variant& v)
    {
        Variant rhs;
        m_right->evaluate(rows, rhs);
        v = ~rhs.get_int();
    }
};

class Ordering_terms {
public:
    Ordering_terms()
    {
        m_terms.clear();
    }
    ~Ordering_terms()
    {
        std::vector<OP_dir>::iterator it = m_terms.begin();
        while (it != m_terms.end()) {
            delete it->m_op;
            it->m_op = 0;
            it++;
        }
    }
    class OP_dir {
    public:
        OP_dir(OP* op, bool asc)
        {
            m_op = op;
            m_asc = asc;
        }
        OP* m_op;
        bool m_asc;
    };
    bool exist()
    {
        return !m_terms.empty();
    }
    void compile(const std::vector<Table*>& tables, const std::vector<int>& search_order, Query& q);

    std::vector<OP_dir> m_terms;
};

class Reader;

class Query {
public:
    Query(const char* name, const char* query)
    {
        m_sample = 0;
        m_where = 0;
        m_having = 0;
        m_from = 0;
        m_limit = -1;
        m_offset = 0;
        m_result = new Table(name, query);
        m_sql = query;
    }

    ~Query()
    {
        if (m_from)
            delete m_from;
        if (m_result)
            delete m_result;
        if (m_where)
            delete m_where;
        if (m_having)
            delete m_having;
        for (auto i = m_select.begin(); i != m_select.end(); ++i)
            delete *i;
    }

    void parse();
    void execute(Reader& reader);

    std::vector<OP*> m_select;
    OP* m_where;
    OP* m_having;
    Ordering_terms m_order_by;
    Ordering_terms m_group_by;

    int m_limit;
    int m_offset;
    int m_sample;

    std::string m_from_name;
    std::vector<int> m_used_from_column_ids;

    Table* m_from;
    Table* m_result;

private:
    void replace_star_column_with_all_columns();

    void process_from();
    void process_select(Row** rows, Row* dest, GenericAccessor dest_accessors[]);
    void combine_aggregates_in_select(Row* base_row, Row* other_row);
    void process_aggregates_in_select(Row** rows, Row* dest, GenericAccessor dest_accessors[]);
    bool process_where(Row** rows);
    bool process_having(Row** rows);
    bool has_aggregate_functions();

    std::string m_sql;
};

} // namespace packetq

namespace std {

// support for hashing std::vector<packetq::Variant>
template <>
struct hash<std::vector<packetq::Variant> > {
    size_t operator()(const std::vector<packetq::Variant>& seq) const
    {
        // combination procedure from boost::hash_combine
        std::size_t accumulator = 0;
        for (auto i = seq.begin(), end = seq.end(); i != end; ++i)
            accumulator ^= i->hash() + 0x9e3779b9 + (accumulator << 6) + (accumulator >> 2);
        return accumulator;
    }
};

} // namespace std

#endif // __packetq_sql_h
