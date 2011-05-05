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
#include <stdexcept>
#include "string.h"
#include "stdarg.h"

#ifdef WIN32
#define snprintf _snprintf
#endif

namespace se {


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
        m_int     = 0;
        m_type    = Coltype::_int;
        m_free_str = 0;
    }
    Variant(const Variant &var)
    {
        m_free_str = 0;
        switch(var.m_type)
        {
            case(Coltype::_int):    m_int = var.m_int;          break;
            case(Coltype::_float):  m_float = var.m_float;      break;
            case(Coltype::_bool):   m_int = var.m_int;          break;
            case(Coltype::_text):   
                if (var.m_free_str)
                    set_copy(var.m_str);
                else
                    m_str = var.m_str;    
            break;
        }
    }
    Variant &operator = (const Variant &rhs)
    {
        m_free_str = 0;
        m_type = rhs.m_type;
        switch(rhs.m_type)
        {
            case(Coltype::_int):    m_int = rhs.m_int;          break;
            case(Coltype::_float):  m_float = rhs.m_float;      break;
            case(Coltype::_bool):   m_int = rhs.m_int;          break;
            case(Coltype::_text):   
                if (rhs.m_free_str)
                    set_copy(rhs.m_str);
                else
                    m_str = rhs.m_str;    
            break;
        }
        return *this;
    }
    Variant(int val)
    {
        m_int = val;
        m_type = Coltype::_int;
        m_free_str = 0;
    }
    Variant(double val)
    {
        m_float = val;
        m_type = Coltype::_float;
        m_free_str = 0;
    }
    inline void freestr()
    {
        if (m_free_str)
            delete []m_free_str;
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
    void set_copy(const char *val)
    {
        freestr();
        m_type = Coltype::_text;
        g_allocs++;
        char *str = new char[strlen(val)+1];
        strcpy(str,val);
        m_str      = str;
        m_free_str = str;
    }
    void set_no_copy(const char *val)
    {
        m_type = Coltype::_text;
        m_str = (char *)val;
    }
    void set_no_copy_free(const char *val)
    {
        m_type      = Coltype::_text;
        m_str       = (char *)val;
        m_free_str  = m_str;
    }

    inline void make_float_valid() const  
    {
        if (m_type == Coltype::_float)
            return;

        switch(m_type)
        {
            case(Coltype::_int):   m_float = (double)m_int; break;
            case(Coltype::_bool):  m_float = (double)m_int; break;
            case(Coltype::_text):  m_float = atof(m_str); break;
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
            case(Coltype::_float):  m_int = (int)m_float; break;
            case(Coltype::_text):   m_int = atoi(m_str); break;
            case(Coltype::_int):    m_int = -(0-(m_int>>31)); break;
        }
        m_type = Coltype::_int;
    }

    inline void make_int_valid() const  
    {
        if (m_type == Coltype::_int)
            return;

        switch(m_type)
        {
            case(Coltype::_float):  m_int = (int)m_float; break;
            case(Coltype::_text):   m_int = atoi(m_str); break;
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
            case(Coltype::_float):  snprintf(buffer,sizeof(buffer),"%f",m_float); break;
            case(Coltype::_int):    snprintf(buffer,sizeof(buffer),"%d",m_int  ); break;
            case(Coltype::_bool):   snprintf(buffer,sizeof(buffer),"%d",m_int  ); break;
        }
        const_cast<Variant *>(this)->set_copy(buffer);
    }

    int get_int() const
    {
        make_int_valid();
        return m_int;
    }

    double get_float() const
    {
        make_float_valid();
        return m_float;
    }

    const char *get_string() const 
    {
        make_string_valid();
        return m_str;
    }

    bool get_bool() const
    {
        make_bool_valid();
        return m_int!=0;
    }
    inline int cmp(const Variant &rhs) const
    {
        switch(m_type)
        {
            case(Coltype::_float):  
                {
                double r = rhs.get_float();
                if (m_float<r)
                    return -1;
                return m_float>r?1:0;
                }
            case(Coltype::_int):    return m_int-rhs.get_int();
            case(Coltype::_bool):   return m_int-rhs.get_int();
            case(Coltype::_text):   return strcmp(m_str, rhs.get_string());
        }
        return 0;
    }

    bool operator < (const Variant &rhs) const
    {
        switch(m_type)
        {
            case(Coltype::_float):  return m_float<rhs.get_float();
            case(Coltype::_int):    return m_int<rhs.get_int();
            case(Coltype::_bool):   return m_int<rhs.get_int();
            case(Coltype::_text):   return strcmp(m_str, rhs.get_string())<0;
        }
        return 0;
    }
    bool operator == (const Variant &rhs) const
    {
        switch(m_type)
        {
            case(Coltype::_float):  return m_float==rhs.get_float();
            case(Coltype::_int):    return m_int==rhs.get_int();
            case(Coltype::_bool):   return m_int==rhs.get_int();
            case(Coltype::_text):   return strcmp(m_str, rhs.get_string())==0;
        }
        return false;
    }
    
    private:
        union {
            mutable const char *m_str;
            mutable int  m_int;
            mutable double  m_float;
        };
        mutable const char *m_free_str;
        mutable Coltype::Type m_type;
};


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
    Allocator(int size, int buffersize): m_size(size),m_buffersize(buffersize)
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
        static Coldef m_coldefs[Coltype::_max];
        Column(const char *name,Coltype::Type type);
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
    private:
        int         m_offset;
};



class Table
{
    public:
    Table(const char *name = 0)
    {
        m_row_allocator = 0;
        m_name =  name?name:"result";
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
    void json();
    void csv(bool format = false);
    void xml();

    void add_column(const char *name, Coltype::Type type);
    void add_column(const char *name, const char *type);
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
            int *p=m_table.m_clear_list;
            while(*p)
                m_data[*p++]=0;
            m_source = 0;
        }
        ~Row()
        {
            for (unsigned int i=0; i<m_table.m_cols.size(); i++)
                destroy(i);
         //   delete []m_data;
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
    Row    *m_source;
    char   m_data[4];
};

class Accessor
{
public:
    Accessor() : m_v(0)
    {
    }
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
        t->set(atoi(s));
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
            const char *bin_ops[]={"||","*","/","%","+","-","<<",">>","&","|","<","<=",">",">=","=","==","!=","<>","is","is not","in","like","or","and"};
            int len = sizeof(bin_ops)/sizeof(const char *);
            int idx = len-1;
            while(idx>=0)
            {
                if (cmpi(std::string(str),bin_ops[idx--]))
                {
                    idx = len-1-idx;
                    return idx;
                }
            }
            return 0;
        }

        OP(const OP &op) : Token(op.get_type(),op.get_token())
        {
            for ( int i = 0 ; i < max_param() ; i++ )
                m_param[i] =op.m_param[i];
            m_left      =op.m_left;
            m_right     =op.m_right;
            m_src_idx   =op.m_src_idx;
            m_src_row   =op.m_src_row;
            m_t         =op.m_t;
            m_name      =op.m_name;

            precedence();
        }
            OP(const Token &tok) : Token(tok.get_type(),tok.get_token())
        {
            for ( int i = 0 ; i < max_param() ; i++ )
                m_param[i] = 0;
            m_left = m_right = 0;
            m_src_idx   = -1;
            m_src_row   = 0;
            m_t         = Coltype::_int;
            m_name      = "";

            precedence();
        }
        ~OP()
        {
            for ( int i = 0 ; i < max_param(); i++ )
                if (m_param[i]    ) delete m_param[i];
            if (m_left    ) delete m_left;
            if (m_right   ) delete m_right;
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

        virtual void evaluate(Row *row, Variant &v);
        virtual void reset_op()
        {
        }
        void reset();
        OP *compile(Table **tabs, Query &q);
        int             m_src_idx;
        int             m_src_row;
        std::string     m_name;
        int             m_precedence;
        OP              *m_param[max_func_param];
        OP              *m_left;
        OP              *m_right;
        Coltype::Type    m_t;
};

////////////////// column accessors

class Column_access_int : public OP
{
public:
    Column_access_int(const OP &op,Int_accessor *a): OP(op),m_accessor(a)
    {
    }
    void evaluate(Row *row, Variant &v)
    {
        if (m_src_row)
            m_accessor->get(row,v);
        else
            m_accessor->get(row->m_source,v);
        return;
    }
    Int_accessor *m_accessor;
};

class Column_access_bool : public OP
{
public:
    Column_access_bool(const OP &op,Bool_accessor *a): OP(op),m_accessor(a)
    {
    }
    void evaluate(Row *row, Variant &v)
    {
        if (m_src_row)
            m_accessor->get(row,v);
        else
            m_accessor->get(row->m_source,v);
        return;
    }
    Bool_accessor *m_accessor;
};

class Column_access_float : public OP
{
public:
    Column_access_float(const OP &op,Float_accessor *a): OP(op),m_accessor(a)
    {
    }
    void evaluate(Row *row, Variant &v)
    {
        if (m_src_row)
            m_accessor->get(row,v);
        else
            m_accessor->get(row->m_source,v);
        return;
    }
    Float_accessor *m_accessor;
};

class Column_access_string : public OP
{
public:
    Column_access_string(const OP &op,String_accessor *a): OP(op),m_accessor(a)
    {
    }
    void evaluate(Row *row, Variant &v)
    {
        if (!m_src_row)
            row = row->m_source;
        v.set_no_copy(m_accessor->get_string_i(row));
        return;
    }
    String_accessor *m_accessor;
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
    void evaluate(Row *row, Variant &v)
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
    void evaluate(Row *row, Variant &v)
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
    void evaluate(Row *row, Variant &v)
    {
        Variant val; 
        m_param[0]->evaluate(row, val);
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
    void evaluate(Row *row, Variant &v)
    {
        char sep='.';
        Variant str,num; 
        m_param[0]->evaluate(row, str);
        m_param[1]->evaluate(row, num);
       
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
    void evaluate(Row *row, Variant &v)
    {
        Variant str; 
        m_param[0]->evaluate(row, str);
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
    void evaluate(Row *row, Variant &v)
    {
        char sep='.';
        Variant str,num; 
        m_param[0]->evaluate(row, str);
        m_param[1]->evaluate(row, num);
        if (m_param[2])
        {
            Variant vsep;
            m_param[2]->evaluate(row, vsep);
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
class Trim_func : public OP
{
public:
    Trim_func(const OP &op): OP(op)
    {
    }
    void evaluate(Row *row, Variant &v);
};

class If_func : public OP
{
public:
    If_func(const OP &op): OP(op)
    {
    }
    void evaluate(Row *row, Variant &v)
    {
        Variant cond; 
        m_param[0]->evaluate(row, cond);
        if (cond.get_bool())
            m_param[1]->evaluate(row, v);
        else
            m_param[2]->evaluate(row, v);
        return;
    }
};

class Min_func_int : public OP
{
public:
    Min_func_int(const OP &op): OP(op)
    {
    }
    virtual void reset_op()
    {
        m_min=0;
        m_set=false;
    }
    int     m_min;
    bool    m_set;
    void evaluate(Row *row, Variant &v)
    {
        Variant rhs; 
        m_param[0]->evaluate(row, rhs);
        int val =rhs.get_int();
        if (!m_set || val < m_min)
            m_min = val;
        m_set = true;
        v = m_min;
        return;
    }
};

class Max_func_int : public OP
{
public:
    Max_func_int(const OP &op): OP(op)
    {
    }
    virtual void reset_op()
    {
        m_max=0;
        m_set=false;
    }
    int     m_max;
    bool    m_set;
    void evaluate(Row *row, Variant &v)
    {
        Variant rhs; 
        m_param[0]->evaluate(row, rhs);
        int val =rhs.get_int();
        if (!m_set || val > m_max)
            m_max = val;
        m_set = true;
        v = m_max;
        return;
    }
};

class Min_func_float : public OP
{
public:
    Min_func_float(const OP &op): OP(op)
    {
    }
    virtual void reset_op()
    {
        m_min = 0.;
        m_set = false;
    }
    double  m_min;
    bool    m_set;
    void evaluate(Row *row, Variant &v)
    {
        Variant rhs; 
        m_param[0]->evaluate(row, rhs);
        double val =rhs.get_float();
        if (!m_set || val < m_min)
            m_min = val;
        m_set = true;
        v = m_min;
        return;
    }
};

class Max_func_float : public OP
{
public:
    Max_func_float(const OP &op): OP(op)
    {
    }
    virtual void reset_op()
    {
        m_max = 0.;
        m_set = false;
    }
    double  m_max;
    bool    m_set;
    void evaluate(Row *row, Variant &v)
    {
        Variant rhs; 
        m_param[0]->evaluate(row, rhs);
        double val =rhs.get_float();
        if (!m_set || val > m_max)
            m_max = val;
        m_set = true;
        v = m_max;
        return;
    }
};

class Stdev_func : public OP
{
public:
    Stdev_func(const OP &op): OP(op)
    {
    }
    virtual void reset_op()
    {
        m_counter   = 0 ;
        m_sum       = 0.;
        m_sum_sq    = 0.;
    }
    void evaluate(Row *row, Variant &v)
    {
        m_counter++;
        Variant rhs; 
        m_param[0]->evaluate(row, rhs);

        double r    =  rhs.get_float();
        m_sum       += r;
        m_sum_sq    += r*r;
        double c    =  m_counter;
        double mean =  m_sum / c ;
        double var  =  m_sum_sq / c - mean*mean;
        v = sqrt(var);
        return;
    }
private:
    int     m_counter;
    double  m_sum;
    double  m_sum_sq;
};

class Avg_func : public OP
{
public:
    Avg_func(const OP &op): OP(op)
    {
    }
    virtual void reset_op()
    {
        m_counter   = 0 ;
        m_sum       = 0.;
    }
    void evaluate(Row *row, Variant &v)
    {
        m_counter++;
        Variant rhs; 
        m_param[0]->evaluate(row, rhs);
        m_sum+=rhs.get_float();
        v = m_sum / double(m_counter);
        return;
    }
private:
    int     m_counter;
    double  m_sum;
};

class Sum_func_int : public OP
{
public:
    Sum_func_int(const OP &op): OP(op)
    {
    }
    virtual void reset_op()
    {
        m_sum = 0;
    }
    int m_sum;
    void evaluate(Row *row, Variant &v)
    {
        Variant rhs; 
        m_param[0]->evaluate(row, rhs);
        m_sum += rhs.get_int();
        v = m_sum;
        return;
    }
};

class Sum_func_float : public OP
{
public:
    Sum_func_float(const OP &op): OP(op)
    {
    }
    virtual void reset_op()
    {
        m_sum=0;
    }
    double m_sum;
    void evaluate(Row *row, Variant &v)
    {
        Variant rhs; 
        m_param[0]->evaluate(row, rhs);
        m_sum+=rhs.get_float();
        v = m_sum;
        return;
    }
};

class Count_func : public OP
{
public:
    Count_func(const OP &op): OP(op)
    {
    }
    virtual void reset_op()
    {
        m_counter=0;
    }
    int m_counter;
    void evaluate(Row *row, Variant &v)
    {
        m_counter++;
        v = m_counter;
        return;
    }
};

//////////////// Binary ops


class Bin_op_eq : public OP
{
public:
    Bin_op_eq(const OP &op): OP(op){}
    void evaluate(Row *row, Variant &v)
    {
        Variant lhs,rhs; 
        m_left ->evaluate(row, lhs);
        m_right->evaluate(row, rhs);
        v = bool(lhs==rhs);
        return;
    }
};
class Bin_op_not_eq : public OP
{
public:
    Bin_op_not_eq(const OP &op):OP(op){}
    void evaluate(Row *row, Variant &v)
    {
        Variant lhs,rhs; 
        m_left ->evaluate(row, lhs);
        m_right->evaluate(row, rhs);
        v = !bool(lhs==rhs);
        return;
    }
};
class Bin_op_or : public OP
{
public:
    Bin_op_or(const OP &op): OP(op){}
    void evaluate(Row *row, Variant &v)
    {
        v=false;
        m_left->evaluate(row, v);
        if (v.get_bool())
        {
            v = true;
            return;
        }
        m_right->evaluate(row, v);
        if(v.get_bool())
            v = true;
        return;
    }
};

class Bin_op_and : public OP
{
public:
    Bin_op_and(const OP &op): OP(op){}
    void evaluate(Row *row, Variant &v)
    {
        v=false;
        m_left->evaluate(row, v);
        if (!v.get_bool())
        {
            v = false;
            return;
        }
        m_right->evaluate(row, v);
        if(v.get_bool())
            v = true;
        return;
    }
};
class Bin_op_lt : public OP
{
public:
    Bin_op_lt(const OP &op): OP(op){}
    void evaluate(Row *row, Variant &v)
    {
        Variant lhs,rhs; 
        m_left ->evaluate(row, lhs);
        m_right->evaluate(row, rhs);
        v = bool(lhs < rhs);
        return;
    }
};
class Bin_op_gt : public OP
{
public:
    Bin_op_gt(const OP &op): OP(op){}
    void evaluate(Row *row, Variant &v)
    {
        Variant lhs,rhs; 
        m_left ->evaluate(row, lhs);
        m_right->evaluate(row, rhs);
        v = bool(rhs < lhs);
        return;
    }
};
class Bin_op_lteq : public OP
{
public:
    Bin_op_lteq(const OP &op): OP(op){}
    void evaluate(Row *row, Variant &v)
    {
        Variant lhs,rhs; 
        m_left ->evaluate(row, lhs);
        m_right->evaluate(row, rhs);
        v = !bool(rhs < lhs);
        return;
    }
};
class Bin_op_gteq : public OP
{
public:
    Bin_op_gteq(const OP &op): OP(op){}
    void evaluate(Row *row, Variant &v)
    {
        Variant lhs,rhs; 
        m_left ->evaluate(row, lhs);
        m_right->evaluate(row, rhs);
        v = !bool(lhs < rhs);
        return;
    }
};
class Bin_op_add : public OP
{
public:
    Bin_op_add(const OP &op): OP(op){}
    void evaluate(Row *row, Variant &v)
    {
        Variant lhs,rhs; 
        m_left ->evaluate(row, lhs);
        m_right->evaluate(row, rhs);
        v = int(lhs.get_int() + rhs.get_int());
        return;
    }
};
class Bin_op_add_float : public OP
{
public:
    Bin_op_add_float(const OP &op): OP(op){}
    void evaluate(Row *row, Variant &v)
    {
        Variant lhs,rhs; 
        m_left ->evaluate(row, lhs);
        m_right->evaluate(row, rhs);
        v = lhs.get_float() + rhs.get_float();
        return;
    }
};
class Bin_op_sub : public OP
{
public:
    Bin_op_sub(const OP &op): OP(op){}
    void evaluate(Row *rows, Variant &v)
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
    void evaluate(Row *rows, Variant &v)
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
    void evaluate(Row *rows, Variant &v)
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
    void evaluate(Row *rows, Variant &v)
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
    void evaluate(Row *rows, Variant &v)
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
    void evaluate(Row *rows, Variant &v)
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
    void evaluate(Row *rows, Variant &v)
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
    void evaluate(Row *rows, Variant &v)
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
    void evaluate(Row *rows, Variant &v)
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
    void evaluate(Row *rows, Variant &v)
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
    void evaluate(Row *rows, Variant &v)
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

////////////////// unary ops

class Un_op_not : public OP
{
public:
    Un_op_not(const OP &op): OP(op){}
    void evaluate(Row *rows, Variant &v)
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
    void evaluate(Row *rows, Variant &v)
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
    void evaluate(Row *rows, Variant &v)
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
    void evaluate(Row *rows, Variant &v)
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
            return m_terms.size()>0;
        }
        void compile(Table *t, Table *s, Query &q);

        std::vector<OP_dir>   m_terms;
};


class Query
{
public:

    Query()
    {
        init();
    };
    ~Query()
    {
        if (m_result) delete m_result;
        if (m_where ) delete m_where;
        if (m_having) delete m_having;
        std::vector<OP *>::iterator it=m_result_set.begin();
        while ( it != m_result_set.end() )
        {
            delete *it;
            m_result_set.erase(it);
            it = m_result_set.begin();
        }
    }
    void set_sample(int s) { m_sample = s;    }
    int  get_sample()      { return m_sample; }
    void ask( const char *sql, bool first_pass=false )
    {
        m_first_pass = first_pass;
        m_query      = sql;
		parse();
    }
    void init()
    {
        m_first_pass=  false;
        m_sample    =  0;
        m_where     =  0;
        m_having    =  0;
        m_from      =  0;
        m_limit     = -1;
        m_offset    =  0;
        m_aggregate_functions = false;
        m_result    = new Table();
    };
    void set_aggregate( bool val = true )   { m_aggregate_functions = val;  }
    bool get_aggregate()                    { return m_aggregate_functions; }
	bool parse();
    bool is_streamable();
    bool execute();
    void reset();                           // resets op's
    Row *process_select( Row *dest );
    bool process_where(  Row *dest );
    bool process_having( Row *dest );
    Table *get_result()                     { return m_result; }

    std::vector<OP *>   m_result_set;
    OP                  *m_where;
    OP                  *m_having;
    Ordering_terms      m_order_by;
    Ordering_terms      m_group_by;
    
    int                 m_limit;
    int                 m_offset;
   
    Table               *m_from;

    bool                m_first_pass;
private:
  
    Table               *m_result;
    int                 m_sample;
	std::string         m_query;
    bool                m_aggregate_functions;
};

};

#endif

