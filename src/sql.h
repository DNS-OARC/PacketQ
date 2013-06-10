/*
 Copyright (c) 2011, .SE - The Internet Infrastructure Foundation
 All rights reserved.
 
 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:
 1. Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.
 3. All advertising materials mentioning features or use of this software
    must display the following acknowledgement:
    This product includes software developed by the .SE - The Internet 
    Infrastructure Foundation.
 4. Neither the name of .SE - The Internet Infrastructure Foundation nor the
    names of its contributors may be used to endorse or promote products
    derived from this software without specific prior written permission.
 
 THIS SOFTWARE IS PROVIDED BY .SE - THE INTERNET INFRASTRUCTURE FOUNDATION 
 ''AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, 
 THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 ARE DISCLAIMED. IN NO EVENT SHALL .SE - The Internet Infrastructure Foundation
 BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE 
 GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
 HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, 
 STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY 
 WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY 
 OF SUCH DAMAGE.
 */
#ifndef SQL_H
#define SQL_H
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <math.h>
#include <list>
#include <vector>
#include <stack>
#include <set>
#include <map>
#include <algorithm>
#include <functional>
#include <stdexcept>
#include <sys/types.h>
#include <regex.h>
#include "string.h"
#include "stdarg.h"
#include "MurmurHash3.h"


#ifdef WIN32
#define snprintf _snprintf
#endif

#define RE_LEN	64

namespace se {

inline std::size_t hash_bytes(const char *bytes, int len)
{
    uint32_t result = 0;
    MurmurHash3_x86_32(bytes, len, 0, &result);
    return result;
}


extern int g_allocs;
static const int max_func_param=4;

// must be defined in this order - see the "if" statement
namespace Coltype
{
    enum Type
    {
        _bool,
        _int,
        _float,
        _text,
        _max
    };
};

extern bool verbose;

inline void vlog(const char *fmt,...)
{
    if (!verbose)
        return;

    char string[1024];
    va_list ap;

    va_start(ap,fmt);
    vsnprintf(string,sizeof(string),fmt,ap);
    va_end(ap);

    fprintf(stderr,"%s",string);
}

class Error
{
    public:
        Error(const char *fmt,...)
        {
            char string[1024];
            va_list ap;

            va_start(ap,fmt);
            vsnprintf(string,sizeof(string),fmt,ap);
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
class Accessor;
class Int_accessor;
class String_accessor;
class Bool_accessor;
class Float_accessor;


class Variant
{
public:
    Variant()
    {
        m_val.m_int     = 0;
        m_type    = Coltype::_int;
        m_free_str = 0;
    }

    Variant(int val)
    {
        m_val.m_int = val;
        m_type = Coltype::_int;
        m_free_str = 0;
    }
    Variant(double val)
    {
        m_val.m_float = val;
        m_type = Coltype::_float;
        m_free_str = 0;
    }

    Variant(const char *val, bool copy)
    {
        m_free_str = 0;
        m_type = Coltype::_text;
        if (copy)
            set_copy(val);
        else
            set_no_copy(val);
    }

    Variant(const Variant &other)
    {
        m_type = other.m_type;
        m_free_str = 0;
        switch(other.m_type)
        {
            case(Coltype::_int):    m_val.m_int = other.m_val.m_int;          break;
            case(Coltype::_float):  m_val.m_float = other.m_val.m_float;      break;
            case(Coltype::_bool):   m_val.m_int = other.m_val.m_int;          break;
            case(Coltype::_text):   
                if (other.m_free_str)
                    set_copy(other.m_val.m_str);
                else
                    m_val.m_str = other.m_val.m_str;
            break;
        }
    }

    // move constructor
    Variant(Variant &&other)
    {
        m_val.m_int     = 0;
        m_type    = Coltype::_int;
        m_free_str = 0;
        swap(*this, other);
    }

    ~Variant()
    {
        if (m_type == Coltype::_text)
            freestr();
    }

    Variant &operator = (Variant other)
    {
        swap(*this, other);     // copy and swap idiom
        return *this;
    }

    friend void swap(Variant& first, Variant& second)
    {
        using std::swap;
        swap(first.m_type, second.m_type);
        swap(first.m_val, second.m_val);
        swap(first.m_free_str, second.m_free_str);
    }

    inline void freestr()
    {
        if (m_free_str)
            delete []m_free_str;
        m_free_str = 0;
    }

    void set_copy(const char *val)
    {
        freestr();
        m_type = Coltype::_text;
        g_allocs++;
        char *str = new char[strlen(val)+1];
        strcpy(str,val);
        m_val.m_str = str;
        m_free_str = str;
    }
    void set_no_copy(const char *val)
    {
        m_type = Coltype::_text;
        m_val.m_str = (char *)val;
    }
    void set_no_copy_free(const char *val) // take over responsibility of freeing without copying
    {
        m_type      = Coltype::_text;
        m_val.m_str = (char *)val;
        m_free_str  = (char *)val;
    }

    inline void make_float_valid() const  
    {
        if (m_type == Coltype::_float)
            return;

        switch(m_type)
        {
            case(Coltype::_int):   m_val.m_float = (double)m_val.m_int; break;
            case(Coltype::_bool):  m_val.m_float = (double)m_val.m_int; break;
            case(Coltype::_text):  m_val.m_float = atof(m_val.m_str); break;
        }
        m_type = Coltype::_float;
    }

    inline void make_bool_valid() const  
    {
        if (m_type == Coltype::_bool)
            return;
        if (m_type == Coltype::_int)
        {

            return;
        }

        switch(m_type)
        {
            case(Coltype::_float):  m_val.m_int = (int)m_val.m_float; break;
            case(Coltype::_text):   m_val.m_int = atoi(m_val.m_str); break;
            case(Coltype::_int):    m_val.m_int = -(0-(m_val.m_int>>31)); break;
        }
        m_type = Coltype::_int;
    }

    inline void make_int_valid() const  
    {
        if (m_type == Coltype::_int)
            return;

        switch(m_type)
        {
            case(Coltype::_float):  m_val.m_int = (int)m_val.m_float; break;
            case(Coltype::_text):   m_val.m_int = atoi(m_val.m_str); break;
        }
        m_type = Coltype::_int;
    }

    inline void make_string_valid() const
    {
        if (m_type == Coltype::_text)
            return;

        char buffer[64];
        switch(m_type)
        {
            case(Coltype::_float):  snprintf(buffer,sizeof(buffer),"%f",m_val.m_float); break;
            case(Coltype::_int):    snprintf(buffer,sizeof(buffer),"%d",m_val.m_int); break;
            case(Coltype::_bool):   snprintf(buffer,sizeof(buffer),"%d",m_val.m_int); break;
        }
        const_cast<Variant *>(this)->set_copy(buffer);
    }

    int get_int() const
    {
        make_int_valid();
        return m_val.m_int;
    }

    double get_float() const
    {
        make_float_valid();
        return m_val.m_float;
    }

    const char *get_string() const 
    {
        make_string_valid();
        return m_val.m_str;
    }

    bool get_bool() const
    {
        make_bool_valid();
        return m_val.m_int != 0;
    }
    inline int cmp(const Variant &rhs) const
    {
        switch(m_type)
        {
            case(Coltype::_float):  
                {
                double r = rhs.get_float();
                if (m_val.m_float<r)
                    return -1;
                return m_val.m_float>r?1:0;
                }
            case(Coltype::_int):    return m_val.m_int-rhs.get_int();
            case(Coltype::_bool):   return m_val.m_int-rhs.get_int();
            case(Coltype::_text):   return strcmp(m_val.m_str, rhs.get_string());
        }
        return 0;
    }

    bool operator < (const Variant &rhs) const
    {
        switch(m_type)
        {
            case(Coltype::_float):  return m_val.m_float < rhs.get_float();
            case(Coltype::_int):    return m_val.m_int < rhs.get_int();
            case(Coltype::_bool):   return m_val.m_int < rhs.get_int();
            case(Coltype::_text):   return strcmp(m_val.m_str, rhs.get_string())<0;
        }
        return 0;
    }
    bool operator == (const Variant &rhs) const
    {
        switch(m_type)
        {
            case(Coltype::_float):  return m_val.m_float == rhs.get_float();
            case(Coltype::_int):    return m_val.m_int == rhs.get_int();
            case(Coltype::_bool):   return m_val.m_int == rhs.get_int();
            case(Coltype::_text):   return strcmp(m_val.m_str, rhs.get_string())==0;
        }
        return false;
    }

    inline std::size_t hash() const
    {
        switch(m_type)
        {
        case(Coltype::_float):  return std::hash<float>()(m_val.m_float);
        case(Coltype::_int):    return std::hash<int>()(m_val.m_int);
        case(Coltype::_bool):   return std::hash<bool>()(m_val.m_int);
        case(Coltype::_text):   return hash_bytes(m_val.m_str, strlen(m_val.m_str));
        }
        return 0;
    }

    mutable Coltype::Type m_type;
private:
    union VariantUnion {
        mutable const char *m_str;
        mutable int m_int;
        mutable double m_float;
    } m_val;
    mutable const char *m_free_str;
};

inline std::string lower(const char *s)
{
    std::string str=s;
    transform(str.begin(), str.end(),str.begin(), tolower );
    return str;
}

inline bool cmpi(const std::string &i_a, const char *b)
{
    std::string str=i_a;
    transform(str.begin(), str.end(),str.begin(), tolower );
    return (str.compare(b)==0);
}

inline bool cmpii(const std::string &i_a, const char *b)
{
    std::string stra=i_a;
    transform(stra.begin(), stra.end(),stra.begin(), tolower );
    std::string strb=b;
    transform(strb.begin(), strb.end(),strb.begin(), tolower );
    return (stra.compare(strb)==0);
}

inline const char *ind(int in)
{
    static const char spc[]="                                                                                                    ";
    if (in<0) in =0 ;
    if (in>sizeof(spc)-2) in = sizeof(spc)-2;
    return &spc[sizeof(spc)-1-in];
}

class DB
{
    private:
    class Item
    {
        public:
        std::string m_function;
        int         m_key;
        bool operator < (const Item &r) const 
        {
            if (m_key<r.m_key)
                return true;
            if (m_key>r.m_key)
                return false;
            if (m_function< r.m_function)
                return true;
            return false;
        }
    };
    public:
    DB();
    ~DB();

    bool query(const char *q);

    Table *create_table(const char *name);
    Table *create_or_use_table(const char *name);
    Table *get_table(const char *name);
    void add_lut(const char *table, int key, const char * value)
    {
        Item i;
        i.m_function = table;
        i.m_key      = key;
        m_lut[i]     = value;
    }
    const char *get_value( const char *table, int key )
    {
        Item i;
        i.m_function = table;
        i.m_key      = key;
        std::map< Item, std::string >::iterator it = m_lut.find(i);
        if (it!= m_lut.end())
        {
            const char *str = it->second.c_str();
            return str;
        }
        return 0;
    }


    private:
    std::map< std::string, Table * > m_tables;
    std::map< Item, std::string > m_lut;
};


extern DB g_db;

class Coldef
{
    public: 
    int m_size;
    int m_align;
};


class Text_col
{
    public:
        static void init(Coldef &def)
        {
            def.m_size = sizeof(Text_col);
            def.m_align = sizeof(const char *);
        }
        inline void set(const char *str)
        {
            if (m_is_ptr)
                destroy();
            int n=0;
            while(str[n] && n<sizeof(m_inline)-1)
            {
                m_inline[n] = str[n];
                n++;
            }
            m_inline[n] = str[n];
            if (!str[n])
                return;
            n = (int)strlen(&str[n])+n;
            m_is_ptr=1;
            g_allocs++;
            char *t = new char[n+1];
            strcpy(t,str);
            m_text = t;
        }
        void set(int i)
        {
            destroy();
            m_is_ptr=0;
            snprintf(m_inline,sizeof(m_inline-1),"%d",i);
        }

        void set(Variant &iset)
        {
            set(iset.get_string());
        }

        const char *get()
        {
            if (m_is_ptr)
                return m_text;
            else
                return m_inline;
        }
        inline void destroy()
        {
            if (m_is_ptr)
            {
                m_is_ptr=0;
                delete []m_text;
            }
            m_inline[0]=0;
        }
        union
        {
            const char *m_text;
            struct
            {
                char m_inline[23]; // must be minimun of pointersize +1
//            char m_inline[128]; // must be minimun of pointersize +1
                char m_is_ptr;
            };
        };
};

class Int_col
{
    public:
        static void init(Coldef &def)
        {
            def.m_size = sizeof(int);
            def.m_align = sizeof(int);
        }
        void set(int i)
        {
            m_val=i;
        }
        void set(Variant &set)
        {
            m_val=set.get_int();
        }
        int get()
        {
            return m_val;
        }
        void destroy()
        {
        }
        int m_val;
};

class Float_col
{
    public:
        static void init(Coldef &def)
        {
            def.m_size = sizeof(Float_col);
            def.m_align = sizeof(Float_col);
        }
        void set(int i)
        {
            m_val=i;
        }
        void set(double i)
        {
            m_val=i;
        }
        void set(Variant &set)
        {
            m_val=set.get_float();
        }
        double get()
        {
            return m_val;
        }
        void destroy()
        {
        }
        double m_val;
};

class Bool_col
{
    public:
        static void init(Coldef &def)
        {
            def.m_size = sizeof(Bool_col);
            def.m_align = sizeof(Bool_col);
        }
        void set(Variant &set)
        {
            m_val=set.get_int()!=0;
        }
        void set(bool i)
        {
            m_val=i;
        }
        bool get()
        {
            return m_val;
        }
        void destroy()
        {
        }
        bool m_val;
};



template <typename T>
class Allocator
{
    public:
    Allocator(int size, int buffersize): m_buffersize(buffersize), m_size(size)
    {
        add_buffer();
    }
    ~Allocator()
    {
        typename std::list< Buffer * >::iterator it = m_buffers.begin();
        while (it!=m_buffers.end())
        {
            delete *it;
            m_buffers.erase(it);
            it = m_buffers.begin();
        }
    }

    void add_buffer()
    {
        m_curr_buffer=new Buffer(*this);
        m_buffers.push_back(m_curr_buffer);
    }
    T *allocate()
    {
    
        T *obj = m_curr_buffer->allocate();
        if (!obj)
        {
            for(typename std::list< Buffer * >::iterator it = m_buffers.begin() ; 
                it != m_buffers.end() ; 
                it++ )
            {
               if ((*it)->m_has_space)
                   obj = (*it)->allocate();
               if (obj)
               {
                   m_curr_buffer = *it;
                   break;
               }
            }
        }
        if (!obj)
        {
            add_buffer();
            obj = m_curr_buffer->allocate();
        }
        return obj;
    }
    void deallocate(T *item)
    {
        Buffer **buffptr = (Buffer **)item;
        buffptr[-1]->deallocate(item);
    }

    private:
    class Buffer
    {
        public:
        friend class Allocator;
        Buffer(Allocator & allocator) : m_allocator(allocator)
        {
            m_has_space=true;
            m_used=0;
            m_stride = (sizeof(Buffer *)+m_allocator.m_size);
            m_memory = (char *)malloc(m_stride*m_allocator.m_buffersize );
        }
        ~Buffer()
        {
            free(m_memory);
        }

        T *allocate()
        {
            T * obj = 0;
            if (m_free_list.size()>0)
            {
                obj=m_free_list.top();
                m_free_list.pop();
            }
            if (!obj && m_used<m_allocator.m_buffersize)
            {
                char *ptr = &m_memory[m_stride*m_used++];
                Buffer **b=(Buffer**)ptr;
                *b=this;
                obj = (T*)(&b[1]);
            }
            m_has_space=true;
            if (!obj)
                m_has_space=false;
            return obj;
        }
        void deallocate(T *item)
        {
            m_has_space = true;
            memset(item,0,m_allocator.m_size);
            m_free_list.push(item);  
        }

        bool            m_has_space;
        int             m_stride;
        std::stack<T *> m_free_list;
        Allocator       &m_allocator;
        int             m_used;
        char            *m_memory;
    };



    Buffer              *m_curr_buffer;
    std::list< Buffer * >   m_buffers;

    int                 m_buffersize;
    int                 m_size;
};

class Column
{
    public:
        static const bool HIDDEN = true;

        static Coldef m_coldefs[Coltype::_max];
        Column(const char *name,Coltype::Type type, int id, bool hidden);
        ~Column();
        // called at startup by DB
        static void init_defs()
        {
            Int_col::init (m_coldefs[Coltype::_int]);
            Text_col::init(m_coldefs[Coltype::_text]);
            Bool_col::init(m_coldefs[Coltype::_bool]);
            Float_col::init(m_coldefs[Coltype::_float]);
        }
        void set_offset(int o);
        inline int get_offset()
        {
            return m_offset;
        }
        std::string m_name;
        Coltype::Type        m_type;
        Coldef      &m_def;
        Accessor    *m_accessor;
        bool m_hidden;
        int m_id;           // numeric id used by parsers for speed
    private:
        int         m_offset;
};



class Table
{
    public:
    Table(const char *name = 0, const char *query = 0)
    {
        m_row_allocator = 0;
        m_name = name?name:"result";
        m_qstring = query?query:"";
        m_curpos  = 0;
        m_clear_list[0]=0;
    }
    ~Table()
    {
        limit(0);
        std::vector<Column *>::iterator it=m_cols.begin();
        while ( it!=m_cols.end() )
        {
            delete *it;
            m_cols.erase(it);
            it=m_cols.begin();
        }
        delete m_row_allocator;
    }
    static int align(int pos,int align)
    {
        int res = pos;
        int rem = pos%align;
        if (rem)
            res = pos+align-rem;
        return res;
    }
    int get_col_index(const char *col)
    {
        int i=0;
        for (std::vector<Column *>::iterator it=m_cols.begin(); it!=m_cols.end();it++)
        {
            if (cmpii(m_cols[i]->m_name,col))
                return i;
            i++;
        }
        return -1;
    }
    int get_column_id(const char *col)
    {
        for (auto i = m_cols.begin(); i != m_cols.end(); ++i)
        {
            if (cmpii((*i)->m_name, col))
                return (*i)->m_id;
        }
        return -1;
    }

    String_accessor *get_string_accessor(const char *col)
    {
        int i=0;
        for (std::vector<Column *>::iterator it=m_cols.begin(); it!=m_cols.end();it++)
        {
            Column *c = *it;
            if (cmpi(c->m_name,col) && c->m_type ==Coltype::_text)
                return (String_accessor *)c->m_accessor;
            i++;
        }
        return 0;
    }
    Int_accessor *get_int_accessor(const char *col)
    {
        int i=0;
        for (std::vector<Column *>::iterator it=m_cols.begin(); it!=m_cols.end();it++)
        {
            Column *c = *it;
            if (cmpi(c->m_name,col) && c->m_type ==Coltype::_int)
                return (Int_accessor *)c->m_accessor;
            i++;
        }
        return 0;
    }
    Bool_accessor *get_bool_accessor(const char *col)
    {
        int i=0;
        for (std::vector<Column *>::iterator it=m_cols.begin(); it!=m_cols.end();it++)
        {
            Column *c = *it;
            if (cmpi(c->m_name,col) && c->m_type ==Coltype::_bool)
                return (Bool_accessor *)c->m_accessor;
            i++;
        }
        return 0;
    }
    Accessor *get_accessor(const char *col)
    {
        int i=0;
        for (std::vector<Column *>::iterator it=m_cols.begin(); it!=m_cols.end();it++)
        {
            Column *c = *it;
            if (cmpi(c->m_name,col))
                return c->m_accessor;
            i++;
        }
        return 0;
    }
    void dump();
    void json(bool trailing_comma);
    void csv(bool format = false);
    void xml();

    Column *add_column(const char *name, Coltype::Type type, int id=-1, bool hidden=false);
    Column *add_column(const char *name, const char *type, int id=-1, bool hidden=false);
    void merge_sort(Ordering_terms &order);
    void per_sort(Ordering_terms &order);
    void group(Ordering_terms &order,Table *source);
    Row *create_row(bool auto_commit=true);
    void delete_row(Row *row);
    void commit_row(Row *row);
    void limit(int limit,int offset=0);

    std::vector<Column *> m_cols;
    std::list<Row *> m_rows;
    int m_curpos;
    std::string m_name;
    std::string m_qstring;
    Allocator<Row>      *m_row_allocator;
    int m_rsize;
    int m_dsize;
    int m_clear_list[128];
};

class Row
{
    public:
        Row(Table &table) : m_table(table)
        {
            clear();
        }
        ~Row()
        {
            for (unsigned int i=0; i<m_table.m_cols.size(); i++)
                destroy(i);
         //   delete []m_data;
        }

        void clear()
        {
            int *p = m_table.m_clear_list;
            while(*p)
                m_data[*p++]=0;
        }

        Row &cleared()
        {
            // make sure text columns are whacked
            for (unsigned int i=0; i<m_table.m_cols.size(); i++)
                destroy(i);
            clear();
            return *this;
        }

        void operator delete (void* ptr, void* voidptr2) throw()
        {
        }
        void del()
        {
            m_table.delete_row(this);
        }
        void destroy(int icol)
        {
            Column &col=*m_table.m_cols[icol];
            int offs=col.get_offset();
            void *ptr = (void *)&m_data[offs];
            if (col.m_type == Coltype::_text)
            {
                Text_col *t=(Text_col *)ptr;
                t->destroy();
            }
            else if (col.m_type == Coltype::_int)
            {
                Int_col *t=(Int_col *)ptr;
                t->destroy();
            }
            else if (col.m_type == Coltype::_bool)
            {
                Bool_col *t=(Bool_col *)ptr;
                t->destroy();
            }
        }
        void get(int icol, Variant &v);

        void set(int icol,int n);
        void set(int icol,const char *s);

        void set(int icol,Variant &data);


    Table  &m_table;
    char   m_data[4];
};

class Accessor
{
public:
    Accessor() : m_v(0)
    {
    }
    virtual ~Accessor() { }
    
    inline char *get_ptr(Row *row) 
    {
        return row->m_data+m_offset;   
    }
    virtual int   get_int(Row *row)
    {
        return atoi(get_string(row));
    }
    virtual const char    *get_string(Row *row)
    {
        m_v=get_int(row);
        return m_v.get_string();
    }
    inline void set(Row *row, unsigned int i)
    {
        set(row,int(i));
    }
    virtual void get(Row *row, Variant &v) = 0;
    virtual void set(Row *row, int i) = 0;
    virtual void set(Row *row, const char *s) = 0;
    virtual void set(Row *row, Variant &v) = 0;
    virtual void set(Row *row, bool b) = 0;
    int     m_offset;
    Variant m_v;
};

inline void Row::get(int icol, Variant &v)
{
    Column &col=*m_table.m_cols[icol];
    col.m_accessor->get(this,v);
}


inline void Row::set(int icol,int n)
{
    if (icol<0)
        throw Error("illegal column");
    Column &col=*m_table.m_cols[icol];
    col.m_accessor->set(this,n);
}
inline void Row::set(int icol,const char *s)
{
    if (icol<0)
        throw Error("illegal column");
    Column &col=*m_table.m_cols[icol];
    col.m_accessor->set(this,s);
}

inline void Row::set(int icol,Variant &data)
{
    if (icol<0)
        throw Error("illegal column");
    Column &col=*m_table.m_cols[icol];
    col.m_accessor->set(this,data);
}

class Int_accessor : public Accessor
{
public:
    void get(Row *row, Variant &v)
    {
        v=get_int(row);
    }
    int     get_int(Row *row)
    {
        Int_col *t=(Int_col *)this->get_ptr(row);
        return t->get();
    }
    inline void set(Row *row, int i)
    {
        Int_col *t=(Int_col *)this->get_ptr(row);
        t->set(i);
    }
    inline void set_i(Row *row, int i)
    {
        Int_col *t=(Int_col *)this->get_ptr(row);
        t->set(i);
    }
    void set(Row *row, const char *s)
    {
        Int_col *t=(Int_col *)this->get_ptr(row);
        t->set(atoi(s));
    }
    void set(Row *row, Variant &v)
    {
        Int_col *t=(Int_col *)this->get_ptr(row);
        t->set(v.get_int());
    }
    void set(Row *row, bool b)
    {
        Int_col *t=(Int_col *)this->get_ptr(row);
        t->set((int)b);
    }
    inline void set(Row *row, unsigned int i)
    {
        set(row,int(i));
    }
};

class Float_accessor : public Accessor
{
public:
    void get(Row *row, Variant &v)
    {
        v=get_float(row);
    }
    double get_float(Row *row)
    {
        Float_col *t=(Float_col *)this->get_ptr(row);
        return t->get();
    }
    inline void set(Row *row, int i)
    {
        Float_col *t=(Float_col *)this->get_ptr(row);
        t->set(i);
    }
    inline void set_i(Row *row, int i)
    {
        Float_col *t=(Float_col *)this->get_ptr(row);
        t->set(i);
    }
    void set(Row *row, const char *s)
    {
        Float_col *t=(Float_col *)this->get_ptr(row);
        t->set(atof(s));
    }
    void set(Row *row, Variant &v)
    {
        Float_col *t=(Float_col *)this->get_ptr(row);
        t->set(v.get_float());
    }
    void set(Row *row, bool b)
    {
        Float_col *t=(Float_col *)this->get_ptr(row);
        t->set((int)b);
    }
    inline void set(Row *row, unsigned int i)
    {
        set(row,int(i));
    }
    inline void set(Row *row, double f)
    {
        Float_col *t=(Float_col *)this->get_ptr(row);
        t->set(f);
    }
};
class Bool_accessor : public Accessor
{
public:
    void get(Row *row, Variant &v)
    {
        v=get_int(row);
    }
    int     get_int(Row *row)
    {
        Bool_col *t=(Bool_col *)this->get_ptr(row);
        return t->get();
    }
    inline void set(Row *row, int i)
    {
        Bool_col *t=(Bool_col *)this->get_ptr(row);
        t->set(i>0);
    }
    inline void set_i(Row *row, bool i)
    {
        Bool_col *t=(Bool_col *)this->get_ptr(row);
        t->set(i);
    }
    void set(Row *row, const char *s)
    {
        Bool_col *t=(Bool_col *)this->get_ptr(row);
        t->set(atoi(s)>0);
    }
    void set(Row *row, Variant &v)
    {
        Bool_col *t=(Bool_col *)this->get_ptr(row);
        t->set(v);
    }
    void set(Row *row, bool b)
    {
        Bool_col *t=(Bool_col *)this->get_ptr(row);
        t->set((int)b);
    }
    inline void set(Row *row, unsigned int i)
    {
        set(row,int(i));
    }
};
class String_accessor : public Accessor
{
public:
    virtual void get(Row *row, Variant &v)
    {
        v.set_no_copy(get_string(row));
    }
    virtual const char    *get_string(Row *row)
    {
        return get_string_i(row);
    }

    inline const char    *get_string_i(Row *row)
    {
        Text_col *t=(Text_col *)this->get_ptr(row);
        return t->get();
    }

    virtual void set(Row *row, int i)
    {
        Text_col *t=(Text_col *)this->get_ptr(row);
        t->set(i);
    }
    virtual void set(Row *row, const char *s)
    {
        Text_col *t=(Text_col *)get_ptr(row);
        t->set(s);
    }
    inline void set_i(Row *row, const char *s)
    {
        Text_col *t=(Text_col *)get_ptr(row);
        t->set(s);
    }
    virtual void set(Row *row, Variant &v)
    {
        Text_col *t=(Text_col *)this->get_ptr(row);
        t->set(v);
    }
    virtual void set(Row *row, bool b)
    {
        set(row,b?1:0);
    }
};

class Token
{
    public:
        enum Type 
        {
            _invalid    =0,
            _label      =1,
            _number     =2,
            _op         =3,
            _uop        =4,
            _string     =5,
            _column     =6,
            _paren      =7,
            _function   =8,
            _semicolon  =9,
            _end        =10
        };

        Token(const Type type,const char *token)
        {
            m_type	= type;
            m_token	= token;
        }
        const char *get_token() const            { return m_token.c_str();} 
        void        set_token(const char *istr)  { m_token = istr; } 
        const Type  get_type()  const            { return m_type;} 
        void        set_type(const Type type)    { m_type=type;} 
    private:
        Type		m_type;
        std::string	m_token;
};

class OP : public Token
{
    public:
        static int is_binary(const char *str)
        {
            const char *bin_ops[]={"||","*","/","%","+","-","<<",">>","&","|","<","<=",">",">=","=","==","!=","<>","is","is not","in","like","not like","or","and"};
            int         pre_ops[]={ 8  ,7  ,7  ,7  ,6  ,6  ,5   ,5   ,5  ,5  ,4  ,4   ,4  ,4   ,3  ,3   ,3   ,3   ,3   ,3       ,3   ,3     ,3         ,2   ,1    };
            int len = sizeof(bin_ops)/sizeof(const char *);
            int idx = len-1;
            while(idx>=0)
            {
                if (cmpi(std::string(str),bin_ops[idx]))
                {
                    return pre_ops[idx];
                }
                idx--;
            }
            return 0;
        }

        OP(const OP &op) : Token(op.get_type(),op.get_token())
        {
            for ( int i = 0 ; i < max_param() ; i++ )
                m_param[i] =op.m_param[i];
            m_left      =op.m_left;
            m_right     =op.m_right;
            m_row_index   =op.m_row_index;
            m_t         =op.m_t;
            m_name      =op.m_name;
            m_has_aggregate_function = op.m_has_aggregate_function;

            precedence();
        }
        OP(const Token &tok) : Token(tok.get_type(),tok.get_token())
        {
            for ( int i = 0 ; i < max_param() ; i++ )
                m_param[i] = 0;
            m_left = m_right = 0;
            m_row_index   = -1;
            m_t         = Coltype::_int;
            m_name      = "";
            m_has_aggregate_function = false;

            precedence();
        }
        virtual ~OP()
        {
            for ( int i = 0 ; i < max_param(); i++ )
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
            for ( int i = 0 ; i < max_param() ; i++ )
                m_param[i] = 0;
            m_left = m_right = 0;
        }
        void precedence()
        {
            m_precedence = is_binary(get_token());
        }
        const char *get_name()
        {
            if (m_name.length()>0)
                return m_name.c_str();

            m_name="";
            if (m_left)
            {
                m_name+="(";
                m_name+=m_left->get_name();
            }
            m_name+=get_token();
            if (m_right)
            {
                if (!m_left)
                    m_name+="(";
                m_name+=m_right->get_name();
                m_name+=")";
            }
            if (m_param[0])
            {
                m_name+="(";
                for ( int i = 0 ; i < max_param() ; i++ )
                    if (m_param[i])
                    {
                        if (i>0)
                            m_name+=",";
                        m_name+=m_param[i]->get_name();
                    }
                m_name+=")";
            }
            //m_name+=")";
            return m_name.c_str();
        }
        Coltype::Type ret_type() {return m_t;}

        // add a hidden column for storing intermediate results
        Accessor *add_intermediate_column(Table * table, std::string name, Coltype::Type type);

        virtual void evaluate(Row **rows, Variant &v);
        virtual void evaluate_aggregate_operands(Row **rows);
        virtual void combine_aggregate(Row *base_row, Row *other_row);
        OP *compile(const std::vector<Table *> &tables,
                    const std::vector<int> &search_order, Query &q);
        int             m_row_index;
        std::string     m_name;
        int             m_precedence;
        OP              *m_param[max_func_param];
        OP              *m_left;
        OP              *m_right;
        Coltype::Type    m_t;
        bool             m_has_aggregate_function;
};

////////////////// column accessors

class Column_access_int : public OP
{
public:
    Column_access_int(const OP &op, int offset): OP(op)
    {
        m_accessor.m_offset = offset;
    }
    void evaluate(Row **rows, Variant &v)
    {
        m_accessor.get(rows[m_row_index], v);
    }
    Int_accessor m_accessor;
};

class Column_access_bool : public OP
{
public:
    Column_access_bool(const OP &op, int offset): OP(op)
    {
        m_accessor.m_offset = offset;
    }
    void evaluate(Row **rows, Variant &v)
    {
        m_accessor.get(rows[m_row_index], v);
    }
    Bool_accessor m_accessor;
};

class Column_access_float : public OP
{
public:
    Column_access_float(const OP &op, int offset): OP(op)
    {
        m_accessor.m_offset = offset;
    }
    void evaluate(Row **rows, Variant &v)
    {
        m_accessor.get(rows[m_row_index], v);
    }
    Float_accessor m_accessor;
};

class Column_access_string : public OP
{
public:
    Column_access_string(const OP &op, int offset): OP(op)
    {
        m_accessor.m_offset = offset;
    }
    void evaluate(Row **rows, Variant &v)
    {
        v.set_no_copy(m_accessor.get_string_i(rows[m_row_index]));
    }
    String_accessor m_accessor;
};

///////////////// Static numbers

class Static_int : public OP
{
public:
    Static_int(const OP &op): OP(op)
    {
        m_val = atoi(get_token());
    }
    int m_val;
    void evaluate(Row **rows, Variant &v)
    {
        v = m_val;
        return;
    }
};

class Static_float : public OP
{
public:
    Static_float(const OP &op): OP(op)
    {
        m_val = atof(get_token());
    }
    double m_val;
    void evaluate(Row **rows, Variant &v)
    {
        v = m_val;
        return;
    }
};


///////////////// Functions
class Truncate_func : public OP
{
public:
    Truncate_func(const OP &op): OP(op)
    {
    }
    void evaluate(Row **rows, Variant &v)
    {
        Variant val; 
        m_param[0]->evaluate(rows, val);
        v = val.get_int();
        return;
    }
};

class Name_func : public OP
{
public:
    Name_func(const OP &op): OP(op)
    {
    }
    void evaluate(Row **rows, Variant &v)
    {
        Variant str,num; 
        m_param[0]->evaluate(rows, str);
        m_param[1]->evaluate(rows, num);
       
        int n=num.get_int();
        const char *s = str.get_string();
        const char *r = g_db.get_value( s, n );
        if (!r)
        {
            v=num;
            return;
        }

        Variant res( r, false );
        v=res;
        return;
    }
};

class Lower_func : public OP
{
public:
    Lower_func(const OP &op): OP(op)
    {
    }
    void evaluate(Row **rows, Variant &v)
    {
        Variant str; 
        m_param[0]->evaluate(rows, str);
        const char *src = str.get_string();
        int l = strlen(src);
        char *s = new char[l+1];
        int p=0;
        while(src[p])
        {
            char c=src[p];
            if( c>='A' && c<='Z')
                c=c-'A'+'a';
            s[p]=c;
            p++;
        }
        s[p]=0;
        v.set_no_copy_free(s);
        return;
    }
};

class Rsplit_func : public OP
{
public:
    Rsplit_func(const OP &op): OP(op)
    {
    }
    void evaluate(Row **rows, Variant &v)
    {
        char sep='.';
        Variant str,num; 
        m_param[0]->evaluate(rows, str);
        m_param[1]->evaluate(rows, num);
        if (m_param[2])
        {
            Variant vsep;
            m_param[2]->evaluate(rows, vsep);
            const char *s = vsep.get_string();
            if (s)
                sep=s[0];
        }

        int n=num.get_int();
        const char *s = str.get_string();
        int l = strlen(s);
        if (!l)
        {
            Variant null( "",false);
            v=null;
            return;
        }
        int p=l-1;
        int found = 0,end=l,start=0;
        if (n==0)
            end=p+1;
        while(p>=0)
        {
            char c = s[p];
            if (c==sep)
            {
                found++;
                if (found==n)
                    end = p;
                if (found==n+1)
                    start = p+1;
            }
            p--;
        }
        char buff[256];
        if ( found<n || start>=l || end-start > sizeof(buff) )
        {
            Variant null( "",false);
            v=null;
            return;
        }
        p=0;
        while (start<end)
            buff[p++]=s[start++];
        buff[p]=0;

        Variant res( buff,true);
        v=res;
        return;
    }
};

class Len_func : public OP
{
    public:
	Len_func(const OP &op): OP(op)
	{
	}
	void evaluate(Row **rows, Variant &v)
	{
	    Variant str; 
	    m_param[0]->evaluate(rows, str);
	    const char *src = str.get_string();
	    int l = strlen(src);
	    Variant res(l);
	    v = res;
	    return;
	}
};

class Trim_func : public OP
{
public:
    Trim_func(const OP &op): OP(op)
    {
    }
    void evaluate(Row **rows, Variant &v);
};

class If_func : public OP
{
public:
    If_func(const OP &op): OP(op)
    {
    }
    void evaluate(Row **rows, Variant &v)
    {
        Variant cond; 
        m_param[0]->evaluate(rows, cond);
        if (cond.get_bool())
            m_param[1]->evaluate(rows, v);
        else
            m_param[2]->evaluate(rows, v);
        return;
    }
};

// Aggregate functions, generally these store their calculations in hidden
// columns

class Min_func_int : public OP
{
public:
    Min_func_int(const OP &op, Table *dest_table): OP(op)
    {
        m_has_aggregate_function = true;
        min_accessor = static_cast<Int_accessor *>(add_intermediate_column(dest_table, ".min", Coltype::_int));
    }
    virtual void evaluate_aggregate_operands(Row **rows)
    {
        Variant p;
        m_param[0]->evaluate(rows, p);
        min_accessor->set(rows[m_row_index], p.get_int());
    }
    virtual void combine_aggregate(Row *base_row, Row *next_row)
    {
        int min = std::min(min_accessor->get_int(base_row), min_accessor->get_int(next_row));
        min_accessor->set(base_row, min);
    }
    void evaluate(Row **rows, Variant &v)
    {
        min_accessor->get(rows[m_row_index], v);
    }

    Int_accessor *min_accessor;
};

class Min_func_float : public OP
{
public:
    Min_func_float(const OP &op, Table *dest_table): OP(op)
    {
        m_has_aggregate_function = true;
        min_accessor = static_cast<Float_accessor *>(add_intermediate_column(dest_table, ".min", Coltype::_float));
    }
    virtual void evaluate_aggregate_operands(Row **rows)
    {
        Variant p;
        m_param[0]->evaluate(rows, p);
        min_accessor->set(rows[m_row_index], p);
    }
    virtual void combine_aggregate(Row *base_row, Row *next_row)
    {
        float min = std::min(min_accessor->get_float(base_row), min_accessor->get_float(next_row));
        min_accessor->set(base_row, min);
    }
    void evaluate(Row **rows, Variant &v)
    {
        min_accessor->get(rows[m_row_index], v);
    }

    Float_accessor *min_accessor;
};

class Max_func_int : public OP
{
public:
    Max_func_int(const OP &op, Table *dest_table): OP(op)
    {
        m_has_aggregate_function = true;
        max_accessor = static_cast<Int_accessor *>(add_intermediate_column(dest_table, ".max", Coltype::_int));
    }
    virtual void evaluate_aggregate_operands(Row **rows)
    {
        Variant p;
        m_param[0]->evaluate(rows, p);
        max_accessor->set(rows[m_row_index], p.get_int());
    }
    virtual void combine_aggregate(Row *base_row, Row *next_row)
    {
        int max = std::max(max_accessor->get_int(base_row), max_accessor->get_int(next_row));
        max_accessor->set(base_row, max);
    }
    void evaluate(Row **rows, Variant &v)
    {
        max_accessor->get(rows[m_row_index], v);
    }

    Int_accessor *max_accessor;
};

class Max_func_float : public OP
{
public:
    Max_func_float(const OP &op, Table *dest_table): OP(op)
    {
        m_has_aggregate_function = true;
        max_accessor = static_cast<Float_accessor *>(add_intermediate_column(dest_table, ".max", Coltype::_float));
    }
    virtual void evaluate_aggregate_operands(Row **rows)
    {
        Variant p;
        m_param[0]->evaluate(rows, p);
        max_accessor->set(rows[m_row_index], p);
    }
    virtual void combine_aggregate(Row *base_row, Row *next_row)
    {
        float max = std::max(max_accessor->get_float(base_row), max_accessor->get_float(next_row));
        max_accessor->set(base_row, max);
    }
    void evaluate(Row **rows, Variant &v)
    {
        max_accessor->get(rows[m_row_index], v);
    }

    Float_accessor *max_accessor;
};

class Stdev_func : public OP
{
public:
    Stdev_func(const OP &op, Table *dest_table): OP(op)
    {
        m_has_aggregate_function = true;
        sum_accessor = static_cast<Float_accessor *>(add_intermediate_column(dest_table, ".sum", Coltype::_float));
        sum_squared_accessor = static_cast<Float_accessor *>(add_intermediate_column(dest_table, ".sumsquared", Coltype::_float));
        count_accessor = static_cast<Int_accessor *>(add_intermediate_column(dest_table, ".count", Coltype::_int));
    }
    virtual void evaluate_aggregate_operands(Row **rows)
    {
        Variant p;
        m_param[0]->evaluate(rows, p);
        double val = p.get_float();

        sum_accessor->set(rows[m_row_index], val);
        sum_squared_accessor->set(rows[m_row_index], val * val);
        count_accessor->set(rows[m_row_index], 1);
    }
    virtual void combine_aggregate(Row *base_row, Row *next_row)
    {
        float sum = sum_accessor->get_float(base_row) + sum_accessor->get_float(next_row);
        sum_accessor->set(base_row, sum);

        float sum_squared = sum_squared_accessor->get_float(base_row) + sum_squared_accessor->get_float(next_row);
        sum_squared_accessor->set(base_row, sum_squared);

        int count = count_accessor->get_int(base_row) + count_accessor->get_int(next_row);
        count_accessor->set(base_row, count);
    }
    void evaluate(Row **rows, Variant &v)
    {
        int c = count_accessor->get_int(rows[m_row_index]);
        if (c == 0)
            c = 1;
        double mean = sum_accessor->get_float(rows[m_row_index]) / c;
        double variance = sum_squared_accessor->get_float(rows[m_row_index]) / c - mean * mean;

        v = sqrt(variance);
    }

    Float_accessor *sum_accessor, *sum_squared_accessor;
    Int_accessor *count_accessor;
};

class Avg_func : public OP
{
public:
    Avg_func(const OP &op, Table *dest_table): OP(op)
    {
        m_has_aggregate_function = true;
        sum_accessor = static_cast<Float_accessor *>(add_intermediate_column(dest_table, ".sum", Coltype::_float));
        count_accessor = static_cast<Int_accessor *>(add_intermediate_column(dest_table, ".count", Coltype::_int));
    }
    virtual void evaluate_aggregate_operands(Row **rows)
    {
        Variant p;
        m_param[0]->evaluate(rows, p);
        sum_accessor->set(rows[m_row_index], p.get_float());

        count_accessor->set(rows[m_row_index], 1);
    }
    virtual void combine_aggregate(Row *base_row, Row *next_row)
    {
        float sum = sum_accessor->get_float(base_row) + sum_accessor->get_float(next_row);
        sum_accessor->set(base_row, sum);

        int count = count_accessor->get_int(base_row) + count_accessor->get_int(next_row);
        count_accessor->set(base_row, count);
    }
    void evaluate(Row **rows, Variant &v)
    {
        v = sum_accessor->get_float(rows[m_row_index]) / count_accessor->get_int(rows[m_row_index]);
    }

    Float_accessor *sum_accessor;
    Int_accessor *count_accessor;
};

class Sum_func_int : public OP
{
public:
    Sum_func_int(const OP &op, Table *dest_table): OP(op)
    {
        m_has_aggregate_function = true;
        sum_accessor = static_cast<Int_accessor *>(add_intermediate_column(dest_table, ".sum", Coltype::_int));
    }
    virtual void evaluate_aggregate_operands(Row **rows)
    {
        Variant p;
        m_param[0]->evaluate(rows, p);

        sum_accessor->set(rows[m_row_index], p.get_int());
    }
    virtual void combine_aggregate(Row *base_row, Row *next_row)
    {
        int sum = sum_accessor->get_int(base_row) + sum_accessor->get_int(next_row);
        sum_accessor->set(base_row, sum);
    }
    void evaluate(Row **rows, Variant &v)
    {
        v = sum_accessor->get_int(rows[m_row_index]);
    }

    Int_accessor *sum_accessor;
};

class Sum_func_float : public OP
{
public:
    Sum_func_float(const OP &op, Table *dest_table): OP(op)
    {
        m_has_aggregate_function = true;
        sum_accessor = static_cast<Float_accessor *>(add_intermediate_column(dest_table, ".sum", Coltype::_float));
    }
    virtual void evaluate_aggregate_operands(Row **rows)
    {
        Variant p;
        m_param[0]->evaluate(rows, p);

        sum_accessor->set(rows[m_row_index], p.get_float());
    }
    virtual void combine_aggregate(Row *base_row, Row *next_row)
    {
        float sum = sum_accessor->get_float(base_row) + sum_accessor->get_float(next_row);
        sum_accessor->set(base_row, sum);
    }
    void evaluate(Row **rows, Variant &v)
    {
        v = sum_accessor->get_float(rows[m_row_index]);
    }

    Float_accessor *sum_accessor;
};

class Count_func : public OP
{
public:
    Count_func(const OP &op, Table *dest_table): OP(op)
    {
        m_has_aggregate_function = true;
        count_accessor = static_cast<Int_accessor *>(add_intermediate_column(dest_table, ".count", Coltype::_int));
    }
    virtual void evaluate_aggregate_operands(Row **rows)
    {
        count_accessor->set(rows[m_row_index], 1);
    }
    virtual void combine_aggregate(Row *base_row, Row *next_row)
    {
        int count = count_accessor->get_int(base_row) + count_accessor->get_int(next_row);
        count_accessor->set(base_row, count);
    }
    void evaluate(Row **rows, Variant &v)
    {
        v = count_accessor->get_int(rows[m_row_index]);
    }

    Int_accessor *count_accessor;
};

//////////////// Binary ops


class Bin_op_eq : public OP
{
public:
    Bin_op_eq(const OP &op): OP(op){}
    void evaluate(Row **rows, Variant &v)
    {
        Variant lhs,rhs; 
        m_left ->evaluate(rows, lhs);
        m_right->evaluate(rows, rhs);
        v = bool(lhs==rhs);
        return;
    }
};
class Bin_op_not_eq : public OP
{
public:
    Bin_op_not_eq(const OP &op):OP(op){}
    void evaluate(Row **rows, Variant &v)
    {
        Variant lhs,rhs; 
        m_left ->evaluate(rows, lhs);
        m_right->evaluate(rows, rhs);
        v = !bool(lhs==rhs);
        return;
    }
};
class Bin_op_or : public OP
{
public:
    Bin_op_or(const OP &op): OP(op){}
    void evaluate(Row **rows, Variant &v)
    {
        v=false;
        m_left->evaluate(rows, v);
        if (v.get_bool())
        {
            v = true;
            return;
        }
        m_right->evaluate(rows, v);
        if(v.get_bool())
            v = true;
        return;
    }
};

class Bin_op_and : public OP
{
public:
    Bin_op_and(const OP &op): OP(op){}
    void evaluate(Row **rows, Variant &v)
    {
        v=false;
        m_left->evaluate(rows, v);
        if (!v.get_bool())
        {
            v = false;
            return;
        }
        m_right->evaluate(rows, v);
        if(v.get_bool())
            v = true;
        return;
    }
};
class Bin_op_lt : public OP
{
public:
    Bin_op_lt(const OP &op): OP(op){}
    void evaluate(Row **rows, Variant &v)
    {
        Variant lhs,rhs; 
        m_left ->evaluate(rows, lhs);
        m_right->evaluate(rows, rhs);
        v = bool(lhs < rhs);
        return;
    }
};
class Bin_op_gt : public OP
{
public:
    Bin_op_gt(const OP &op): OP(op){}
    void evaluate(Row **rows, Variant &v)
    {
        Variant lhs,rhs; 
        m_left ->evaluate(rows, lhs);
        m_right->evaluate(rows, rhs);
        v = bool(rhs < lhs);
        return;
    }
};
class Bin_op_lteq : public OP
{
public:
    Bin_op_lteq(const OP &op): OP(op){}
    void evaluate(Row **rows, Variant &v)
    {
        Variant lhs,rhs; 
        m_left ->evaluate(rows, lhs);
        m_right->evaluate(rows, rhs);
        v = !bool(rhs < lhs);
        return;
    }
};
class Bin_op_gteq : public OP
{
public:
    Bin_op_gteq(const OP &op): OP(op){}
    void evaluate(Row **rows, Variant &v)
    {
        Variant lhs,rhs; 
        m_left ->evaluate(rows, lhs);
        m_right->evaluate(rows, rhs);
        v = !bool(lhs < rhs);
        return;
    }
};
class Bin_op_add : public OP
{
public:
    Bin_op_add(const OP &op): OP(op){}
    void evaluate(Row **rows, Variant &v)
    {
        Variant lhs,rhs; 
        m_left ->evaluate(rows, lhs);
        m_right->evaluate(rows, rhs);
        v = int(lhs.get_int() + rhs.get_int());
        return;
    }
};
class Bin_op_add_float : public OP
{
public:
    Bin_op_add_float(const OP &op): OP(op){}
    void evaluate(Row **rows, Variant &v)
    {
        Variant lhs,rhs; 
        m_left ->evaluate(rows, lhs);
        m_right->evaluate(rows, rhs);
        v = lhs.get_float() + rhs.get_float();
        return;
    }
};
class Bin_op_sub : public OP
{
public:
    Bin_op_sub(const OP &op): OP(op){}
    void evaluate(Row **rows, Variant &v)
    {
        Variant lhs,rhs; 
        m_left ->evaluate(rows, lhs);
        m_right->evaluate(rows, rhs);
        v = int(lhs.get_int() - rhs.get_int());
        return;
    }
};
class Bin_op_sub_float : public OP
{
public:
    Bin_op_sub_float(const OP &op): OP(op){}
    void evaluate(Row **rows, Variant &v)
    {
        Variant lhs,rhs; 
        m_left ->evaluate(rows, lhs);
        m_right->evaluate(rows, rhs);
        v = lhs.get_float() - rhs.get_float();
        return;
    }
};

class Bin_op_mul : public OP
{
public:
    Bin_op_mul(const OP &op): OP(op){}
    void evaluate(Row **rows, Variant &v)
    {
        Variant lhs,rhs; 
        m_left ->evaluate(rows, lhs);
        m_right->evaluate(rows, rhs);
        v = int(lhs.get_int() * rhs.get_int());
        return;
    }
};
class Bin_op_mul_float : public OP
{
public:
    Bin_op_mul_float(const OP &op): OP(op){}
    void evaluate(Row **rows, Variant &v)
    {
        Variant lhs,rhs; 
        m_left ->evaluate(rows, lhs);
        m_right->evaluate(rows, rhs);
        v = lhs.get_float() * rhs.get_float();
        return;
    }
};
class Bin_op_div : public OP
{
public:
    Bin_op_div(const OP &op): OP(op){}
    void evaluate(Row **rows, Variant &v)
    {
        Variant lhs,rhs; 
        m_left ->evaluate(rows, lhs);
        m_right->evaluate(rows, rhs);
        v = lhs.get_float() / rhs.get_float();
        return;
    }
};
class Bin_op_modulo : public OP
{
public:
    Bin_op_modulo(const OP &op): OP(op){}
    void evaluate(Row **rows, Variant &v)
    {
        Variant lhs,rhs; 
        m_left ->evaluate(rows, lhs);
        m_right->evaluate(rows, rhs);
        v = fmod(lhs.get_float(), rhs.get_float());
        return;
    }
};
class Bin_op_arithmetic_shift_left : public OP
{
public:
    Bin_op_arithmetic_shift_left(const OP &op): OP(op){}
    void evaluate(Row **rows, Variant &v)
    {
        Variant lhs,rhs; 
        m_left ->evaluate(rows, lhs);
        m_right->evaluate(rows, rhs);
        v = lhs.get_int() << rhs.get_int();
        return;
    }
};
class Bin_op_arithmetic_shift_right : public OP
{
public:
    Bin_op_arithmetic_shift_right(const OP &op): OP(op){}
    void evaluate(Row **rows, Variant &v)
    {
        Variant lhs,rhs; 
        m_left ->evaluate(rows, lhs);
        m_right->evaluate(rows, rhs);
        v = lhs.get_int() >> rhs.get_int();
        return;
    }
};
class Bin_op_bitwise_and : public OP
{
public:
    Bin_op_bitwise_and(const OP &op): OP(op){}
    void evaluate(Row **rows, Variant &v)
    {
        Variant lhs,rhs; 
        m_left ->evaluate(rows, lhs);
        m_right->evaluate(rows, rhs);
        v = lhs.get_int() & rhs.get_int();
        return;
    }
};
class Bin_op_bitwise_or : public OP
{
public:
    Bin_op_bitwise_or(const OP &op): OP(op){}
    void evaluate(Row **rows, Variant &v)
    {
        Variant lhs,rhs; 
        m_left ->evaluate(rows, lhs);
        m_right->evaluate(rows, rhs);
        v = lhs.get_int() | rhs.get_int();
        return;
    }
};
class Bin_op_concatenate : public OP
{
public:
    Bin_op_concatenate(const OP &op): OP(op){}
    void evaluate(Row **rows, Variant &v)
    {
        Variant lhs,rhs; 
        m_left ->evaluate(rows, lhs);
        m_right->evaluate(rows, rhs);
        const char *lhs_str = lhs.get_string();
        const char *rhs_str = rhs.get_string();
        if (!lhs_str)
        {
            if (rhs_str)
                v = rhs;
            else
                v.set_no_copy("");
            return;
        }
        int l = (int)strlen(lhs_str);
        int r = (int)strlen(rhs_str);
        char *str = new char[ l+r+1 ];
        strcpy( str, lhs_str );
        strcat( str, rhs_str );
        v.set_no_copy_free(str);
        return;
    }
};
class Bin_op_like : public OP
{
    private:
	regex_t m_re;	
	char	m_re_str[RE_LEN];
	bool	m_compiled;
	int	m_err;
    public:
	Bin_op_like(const OP &op): OP(op){
	    m_err = 0;
	    m_compiled = false;
	}
	void regex_from_like(const char* s, char* r, int l)
	{
	    char* stop = r+l-4;
	    if ( r < stop ) {
		*r++ = '^';
		while ( r < stop and *s)
		{
//		    printf("s: %s\n", s);
		    if (*s == '\\') {
			s++;
			if (*s) {
			    *r = *s;
			} else {
			    s--;
			}
		    } else if ( *s == '.' ) {
			*r++ = '\\'; *r = '.';		    
		    } else if ( *s == '*' ) {
			*r++ = '\\'; *r = '*';		    
		    } else if ( *s == '%' ) {
			*r++ = '.'; *r = '*';		    
		    } else if ( *s == '_' ) {
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
	void evaluate(Row **rows, Variant &v)
	{
	    Variant lhs,rhs;
	    m_left ->evaluate(rows, lhs);
	    m_right->evaluate(rows, rhs);
	    const char* lstr = lhs.get_string();
	    const char* rstr = rhs.get_string();
	    if (!m_compiled) {
		m_compiled = true;	// Set this before we try; no need to try again if we fail
		regex_from_like(rstr, m_re_str, RE_LEN);
		m_err = regcomp(&m_re, m_re_str, REG_NOSUB);
		if (m_err) {
		    char errstr[RE_LEN];
		    regerror(m_err, &m_re, errstr, RE_LEN);
		    printf("Error compiling regex: %d: %s", m_err, errstr);
		}
	    }
	    if (m_err) {
		v = false;
	    } else {
		v = bool(regexec(&m_re, lstr, 0, 0, 0) == 0);
	    }
	    return;
	}
	~Bin_op_like()
	{
	    if (m_compiled) {
		regfree(&m_re);
	    }
	}

};
class Bin_op_not_like : public Bin_op_like
{
    public:
	Bin_op_not_like(const OP &op): Bin_op_like(op){}
	void evaluate(Row **rows, Variant &v)
	{
	    Bin_op_like::evaluate(rows, v);
	    v = !bool(v.get_bool());
	    return;
	}
};
////////////////// unary ops

class Un_op_not : public OP
{
public:
    Un_op_not(const OP &op): OP(op){}
    void evaluate(Row **rows, Variant &v)
    {
        Variant rhs; 
        m_right->evaluate(rows, rhs);
        v = !rhs.get_bool();
        return;
    }
};

class Un_op_neg : public OP
{
public:
    Un_op_neg(const OP &op): OP(op){}
    void evaluate(Row **rows, Variant &v)
    {
        Variant rhs; 
        m_right->evaluate(rows, rhs);
        v = -rhs.get_int();
        return;
    }
};

class Un_op_neg_float : public OP
{
public:
    Un_op_neg_float(const OP &op): OP(op){}
    void evaluate(Row **rows, Variant &v)
    {
        Variant rhs; 
        m_right->evaluate(rows, rhs);
        v = -rhs.get_float();
        return;
    }
};

class Un_op_ones_complement : public OP
{
public:
    Un_op_ones_complement(const OP &op): OP(op){}
    void evaluate(Row **rows, Variant &v)
    {
        Variant rhs; 
        m_right->evaluate(rows, rhs);
        v = ~rhs.get_int();
        return;
    }
};


class Ordering_terms
{
    public:
        Ordering_terms()
        {
            m_terms.clear();
        }
        ~Ordering_terms()
        {
            std::vector<OP_dir>::iterator it=m_terms.begin();
            while ( it != m_terms.end() )
            {
                delete it->m_op;
                it->m_op=0;
                it++;
            }

        }
        class OP_dir
        {
            public:
            OP_dir(OP *op,bool asc)
            {
                m_op=op;
                m_asc=asc;
            }
            OP *m_op;
            bool m_asc;
        };
        bool exist()
        {
            return !m_terms.empty();
        }
        void compile(const std::vector<Table *> &tables, const std::vector<int> &search_order, Query &q);

        std::vector<OP_dir>   m_terms;
};

class Reader;

class Query
{
public:
    Query(const char *name, const char *query)
    {
        m_sample    =  0;
        m_where     =  0;
        m_having    =  0;
        m_from      =  0;
        m_limit     = -1;
        m_offset    =  0;
        m_result    = new Table(name, query);
        m_sql = query;
    }

    ~Query()
    {
        if (m_result) delete m_result;
        if (m_where ) delete m_where;
        if (m_having) delete m_having;
        for (auto i = m_select.begin(); i != m_select.end(); ++i)
            delete *i;
        m_select.clear();
    }

    void parse();
    void execute(Reader &reader);

    std::vector<OP *>   m_select;
    OP                  *m_where;
    OP                  *m_having;
    Ordering_terms      m_order_by;
    Ordering_terms      m_group_by;
    
    int                 m_limit;
    int                 m_offset;
    int                 m_sample;

    std::string         m_from_name;
    std::vector<int>    m_used_from_column_ids;

    Table               *m_from;
    Table               *m_result;

private:
    void replace_star_column_with_all_columns();

    void process_from();
    void process_select(Row **rows, Row *dest, Accessor **result_accessors);
    void combine_aggregate_in_select(Row *base_row, Row *other_row);
    void process_aggregate_in_select(Row **rows, Row *dest, Accessor **result_accessors);
    bool process_where(Row **rows);
    bool process_having(Row **rows);
    bool has_aggregate_functions();

    std::string         m_sql;
};

};

// support for hashing std::vector<Variant>
namespace std {
    template <> struct hash<std::vector<se::Variant>>
    {
        size_t operator()(const std::vector<se::Variant> &seq) const
        {
            // combination procedure from boost::hash_combine
            std::size_t accumulator = 0;
            for(auto i = seq.begin(), end = seq.end(); i != end; ++i)
                accumulator ^= i->hash() + 0x9e3779b9 + (accumulator << 6) + (accumulator >> 2);
            return accumulator;
        }
    };
}


#endif

