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

#include "sql.h"
#include "packetq.h"
#include "output.h"
#include "reader.h"
#include "packet_handler.h"
#include <vector>
#include <unordered_map>
#include <utility>
#ifdef WIN32
#include <windows.h>
#endif

namespace packetq {

bool verbose = false;

int g_allocs=0;

Column *Table::add_column(const char *name, const char *type, int id, bool hidden)
{
    if (!type)
        return add_column(name,Coltype::_text, id, hidden);
    else if (strcmp(type,"bool") == 0)
        return add_column(name,Coltype::_bool, id, hidden);
    else if (strcmp(type,"int") == 0)
        return add_column(name,Coltype::_int, id, hidden);
    else if (strcmp(type,"float") == 0)
        return add_column(name,Coltype::_float, id, hidden);
    else
        return add_column(name,Coltype::_text, id, hidden);
}

Column *Table::add_column(const char *name, Coltype::Type type, int id, bool hidden)
{
    Column *col = new Column(name, type, id, hidden);
    col->m_offset = Table::align(m_curpos, col->m_def.m_align);
    m_curpos = col->m_offset + col->m_def.m_size;
    if (type==Coltype::_text)
        m_text_column_offsets.push_back(col->m_offset);
    m_cols.push_back(col);
    return col;
}

void Table::delete_row(Row *row)
{
    row->decref_text_columns(m_text_column_offsets);
    m_row_allocator->deallocate(row);
}

Row *Table::create_row()
{
    if (!m_row_allocator)
    {
        m_rsize = sizeof(Row) - sizeof(Row::m_data); // exclude the dummy
        m_dsize = m_curpos;
        m_row_allocator = new Allocator<Row>(m_rsize+m_dsize,10000);
    }

    Row *r = m_row_allocator->allocate();
    r->zero_text_columns(m_text_column_offsets);
    return r;
}

void Table::add_row(Row *row)
{
    m_rows.push_back(row);
}

int g_comp =0;

void Ordering_terms::compile(const std::vector<Table *> &tables, const std::vector<int> &search_order, Query &q)
{
    for (std::vector<Ordering_terms::OP_dir>::iterator it=m_terms.begin(); it!= m_terms.end(); it++)
    {
        OP *op = it->m_op;
        it->m_op = op->compile(tables, search_order, q);
    }
}

class Sorter
{
    public:
        Sorter(Ordering_terms &order): m_order(order)
        {
        }
        bool operator() (Row *ia, Row *ib)
        {
            // this works under the assumption that the ordering terms have
            // been compiled with only one table so the row index i is 0
            Row **ia_rows = &ia;
            Row **ib_rows = &ib;

            for (std::vector<Ordering_terms::OP_dir>::iterator it=m_order.m_terms.begin(); it!= m_order.m_terms.end(); it++)
            {
                g_comp++;

                OP *op = it->m_op;
                op->evaluate(it->m_asc?ia_rows:ib_rows, m_a);
                op->evaluate(it->m_asc?ib_rows:ia_rows, m_b);
                int res = m_a.cmp(m_b);
                if (res<0)
                    return true;
                if (res>0)
                    return false;
            }
            return false;
        }
        bool eq(Row *ia, Row *ib)
        {
            Row **ia_rows = &ia;
            Row **ib_rows = &ib;

            for (std::vector<Ordering_terms::OP_dir>::iterator it=m_order.m_terms.begin(); it!= m_order.m_terms.end(); it++)
            {
                g_comp++;

                OP *op = it->m_op;
                op->evaluate(it->m_asc?ia_rows:ib_rows,m_a);
                op->evaluate(it->m_asc?ib_rows:ia_rows,m_b);
                int res = m_a.cmp(m_b);
                if (res!=0)
                    return false;
            }
            return true;
        }
        int cmp(Row *ia, Row *ib)
        {
            Row **ia_rows = &ia;
            Row **ib_rows = &ib;

            for (std::vector<Ordering_terms::OP_dir>::iterator it=m_order.m_terms.begin(); it!= m_order.m_terms.end(); it++)
            {
                g_comp++;

                OP *op = it->m_op;
                op->evaluate(it->m_asc?ia_rows:ib_rows,m_a);
                op->evaluate(it->m_asc?ib_rows:ia_rows,m_b);
                int res = m_a.cmp(m_b);
                if (res!=0)
                    return res;
            }
            return 0;
        }
        Ordering_terms  &m_order;
        Variant m_a,m_b;
};

struct Stki
{
    int     s;
    int     l;
    int     b;
};

struct Spkt
{
    Variant cache;
    int row;
};

class Per_sort
{
public:
    struct Tlink
    {
        Tlink() : m_next(0), row(0), m_eq(0)
        {
        }

        Tlink *get_eq() {return m_eq;}
        void reset()
        {
            m_next = 0;
            row = 0;
            m_eq =0;
        }
        void add_eq(Tlink *o)
        {
            if (!o->m_eq)
            {
                // add single
                if (!m_eq)
                {
                    // as first
                    m_eq = o;
                    o->m_eq_last = o;
                    return;
                }
                // to list
                m_eq->m_eq_last->m_eq = o;
                m_eq->m_eq_last = o;
                return;
            }
            else
            {
                // add list
                if (!m_eq)
                {
                    // as first
                    m_eq = o;
                    o->m_eq_last=o->m_eq->m_eq_last;
                    return;
                }
                // to list
                m_eq->m_eq_last->m_eq = o;
                m_eq->m_eq_last = o->m_eq->m_eq_last;
            }
        }
        union {
        Tlink    *m_next;
        Tlink    *m_eq_last;
        };
        Row      *row;
        Variant  cache;
        private:
        Tlink    *m_eq;
    };
    struct List
    {
    public:
        void reset()
        {
            m_size  =0;
            m_fl[0] =0;
            m_fl[1] =0;
        }
        int     m_size;
        Tlink   *m_fl[2];
    };
    Per_sort(Table &table,Ordering_terms &order) : m_sorter(order),m_table(table)
    {
        m_escalate_sort=order.m_terms.size()>1;
        m_asc = order.m_terms.begin()->m_asc?1:-1;
        m_op =  order.m_terms.begin()->m_op;
        memset(m_groups,0,sizeof(m_groups));
        m_current.reset();
    }
    inline bool add_to_list(List &list,Tlink *t)
    {
        if (list.m_fl[0]==0)
        {
            list.m_fl[0]=list.m_fl[1]=t;
            list.m_size = 1;
            return true;
        }
        list.m_fl[1]->m_next = t;
        list.m_fl[1] = t;
        list.m_size++;
        return true;
    }
    inline bool insert_into_list(List &list,Tlink *t)
    {
        if (list.m_fl[0]==0)
        {
            list.m_fl[0]=list.m_fl[1]=t;
            list.m_size = 1;
            return true;
        }
        int cmp0=cmp(t,list.m_fl[0]);
        if (cmp0==0)
        {
            list.m_fl[0]->add_eq(t);
            return true;
        }
        if (cmp0<0)
        {
            t->m_next = list.m_fl[0];
            list.m_fl[0] = t;
            list.m_size++;
            return true;
        }
        int cmp1=cmp(t,list.m_fl[1]);
        if (cmp1==0)
        {
            list.m_fl[1]->add_eq(t);
            return true;
        }
        if (cmp1>0)
        {
            list.m_fl[1]->m_next = t;
            list.m_fl[1] = t;
            list.m_size++;
            return true;
        }
        return false;
    }
    int cmp(Tlink *a,Tlink *b)
    {
        int cmp = a->cache.cmp(b->cache)*m_asc;
        if( cmp!=0 || !m_escalate_sort)
            return cmp;
        return m_sorter.cmp(a->row,b->row);
    }
    inline void add(Tlink *t)
    {
        if (!insert_into_list(m_current, t))
        {
            insert_list(m_current);
            m_current.reset();
            insert_into_list(m_current, t);
        }
    }
    inline void insert_list(List &l)
    {
        unsigned int size = l.m_size;
        int offs = 0;
        size >>=1;
        while (size != 0)
        {
            offs++;
            size>>=1;
        }
        if (m_groups[offs].m_size!=0)
        {
            List m = merge(m_groups[offs],l);
            m_groups[offs].reset();
            insert_list(m);
        }
        else
            m_groups[offs]=l;
    }
    List merge(List &l1, List &l2)
    {
        List r;
        r.reset();
        Tlink *a=l1.m_fl[0];
        Tlink *b=l2.m_fl[0];
        if (!a)
            return l2;
        if (!b)
            return l1;

        int size = l1.m_size+l2.m_size;

        while(a && b)
        {
            int c = cmp(a,b);
            if (c==0)
            {
                Tlink *a2=a;
                Tlink *b2=b;
                a=a->m_next;
                b=b->m_next;
                a2->m_next = 0;
                b2->m_next = 0;
                a2->add_eq(b2);
                add_to_list(r,a2);
                size--;
            }
            else if (c<0)
            {
                Tlink *a2=a;
                a=a->m_next;
                a2->m_next = 0;
                add_to_list(r,a2);
            }
            else
            {
                Tlink *b2=b;
                b=b->m_next;
                b2->m_next = 0;
                add_to_list(r,b2);
            }
        }
        if(a)
        {
            r.m_fl[1]->m_next = a;
            r.m_fl[1]=l1.m_fl[1];
        }
        if(b)
        {
            r.m_fl[1]->m_next = b;
            r.m_fl[1]=l2.m_fl[1];
        }


        l1.reset();
        l2.reset();
        r.m_size = size;
        return r;
    }

    void sort()
    {
        int table_size = (int)m_table.m_rows.size();
        if ( table_size <= 1 )
            return;
        std::list<Row *>::iterator it = m_table.m_rows.begin();
        Tlink *links = new Tlink[table_size];

        int i;
        for (i=0;i<table_size;i++)
        {
            Tlink &r = links[i];
            r.reset();
            r.row    = *it;
            // &row works under the assumption that m_op has been compiled with
            // this table only so row index is 0
            m_op->evaluate(&r.row,r.cache);
            it++;
            add(&r);
        }
        if (m_current.m_size)
            insert_list(m_current);
        List result;
        result.reset();
        for (i=0;i<sizeof(m_groups)/sizeof(List);i++)
        {
            if (m_groups[i].m_size>0)
            {
                result = merge( result, m_groups[i] );
                m_groups[i].reset();
            }
        }
        Tlink *p=result.m_fl[0];
        it = m_table.m_rows.begin();
        int cnt =0;
        while(p)
        {
            *it++ = p->row;
            cnt++;
            Tlink *e = p->get_eq();
            while(e)
            {
                cnt++;
                *it++ = e->row;
                e = e->get_eq();
            }
            p = p->m_next;
        };
        // CID 1436254 Dereference after null check
        // Code disabled, it makes no sense
        // if(cnt != table_size)
        // {
        //     p++;
        // }

        delete []links;
    }

    OP      *m_op;
    Sorter  m_sorter;
    bool    m_escalate_sort;
    int     m_asc;
    Table   &m_table;
    List    m_groups[32];
    List    m_current;
};

void Table::per_sort(Ordering_terms &order)
{
    Per_sort sort(*this, order);

    sort.sort();

    return;
}

void Table::merge_sort(Ordering_terms &order)
{
    Sorter sorter(order);

    bool escalate_sort=order.m_terms.size()>1;
    int asc = order.m_terms.begin()->m_asc?1:-1;
    OP *op   = order.m_terms.begin()->m_op;

    int table_size=(int)m_rows.size();
    if (table_size<=1)
        return;
    Row **row_ptrs=new Row *[table_size];
    Spkt *spktpool=new Spkt[table_size*2];
    Spkt *rows[2];
    rows[0]=spktpool;
    rows[1]=&spktpool[table_size];
    std::list<Row *>::iterator it=m_rows.begin();

    int i=0;
    Spkt *r = rows[0];
    for (i=0;i<table_size;i+=2)
    {

        row_ptrs[i]=*it++;
        r[i].row=i;
        // &row works under the assumption that m_op has been compiled with
        // this table only so row index is 0
        op->evaluate(&row_ptrs[r[i].row],r[i].cache);
        if (i+1<table_size)
        {
            row_ptrs[i+1]=*it++;
            r[i+1].row=i+1;
            op->evaluate(&row_ptrs[r[i+1].row],r[i+1].cache);
        }
    }
    int swap=0;

    Stki stack[64];
    Stki *sp = stack;
    sp->s = 0;
    sp->l = 2;
    sp->b = 1;
    rows[1][0]=rows[0][1];
    rows[1][1]=rows[0][0];

    sp--;

    int npos=0 ;
    while(true)
    {
        int start,len;
        if (sp>stack && sp->l == sp[-1].l)
        {
            // two equal size -> merge

            len= sp->l<<=1;
            start = sp[-1].s;
            swap = sp[-1].b;
            sp--;
            sp--;
        }
        else
        {
            start=npos;
            npos+=2;
            swap=0;
            len =2;
        }

        int cnt = start+len>table_size?table_size-start:len;
        Spkt *s=rows[swap];
        Spkt *d=rows[1-swap];
        if (cnt>0)
        {
            int p1 = start;
            int p2 = start+(len>>1);
            int l1 = len>>1;
            int l2 = l1;
            if (p1+l1>table_size)
                l1 = table_size-p1;
            if (p2+l2>table_size)
                l2 = table_size-p2;

            int i = start;

            while(cnt-->0)
            {
                if (l1<=0)
                {
                    d[i++] = s[p2++];
                }
                else if (l2<=0)
                {
                    d[i++] = s[p1++];
                }
                else
                {
                    int cmp = s[p1].cache.cmp(s[p2].cache)*asc;
                    if( cmp<0 || (cmp==0  && escalate_sort && sorter(row_ptrs[s[p1].row],row_ptrs[s[p2].row]) ) )
                    {
                        l1--;
                        d[i++] = s[p1++];
                    }
                    else
                    {
                        l2--;
                        d[i++] = s[p2++];
                    }
                }
            }
        }
        ++sp;
        sp->l=len;
        sp->s=start;
        sp->b=1-swap;
        if (len>table_size)
        {
            for ( it=m_rows.begin();it!=m_rows.end();it++)
            {
                *it=row_ptrs[(d++)->row];
            }

            break;
        }
    }
    delete []row_ptrs;
    delete []spktpool;
    return;
}

void Table::limit(int limit,int offset)
{
    int count = 0;
    std::list<Row *>::iterator e=m_rows.end();
    for (std::list<Row *>::iterator it=m_rows.begin();it!=m_rows.end();it++)
    {
        if (e!=m_rows.end())
        {
            delete_row(*e);
            m_rows.erase(e);
            e=m_rows.end();
        }

        int l = count++;
        if (l<offset || l>=offset+limit)
        {
            e=it;
        }
    }
    if (e!=m_rows.end())
    {
        delete_row(*e);
        m_rows.erase(e);
    }
}

void printrep(int n,char c)
{
    if (n>=3000)
        return;
    char buf[3000];
    int i;
    for(i=0;i<n;i++)
        buf[i]=c;
    buf[i]=0;
    printf("%s",buf);
}

void Table::xml()
{
    g_output.reset();
    int cols = (int)m_cols.size();

    g_output.add_string("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    g_output.add_string("<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">\n");
    g_output.add_string("<html  xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\" lang=\"en\">\n<head>\n  <title>");
    g_output.add_string(m_name.c_str());
    g_output.add_string("</title>\n");
    g_output.add_string("<style type=\"text/css\">\n");
    g_output.add_string("    th.int   { color: #0F0C00; }\n");
    g_output.add_string("    th.float { color: #0F0900; }\n");
    g_output.add_string("    th.text  { color: #0F0600; }\n");
    g_output.add_string("    th.bool  { color: #0C0900; }\n");
    g_output.add_string("</style>\n");
    g_output.add_string("</head>\n");
    g_output.add_string("<body>\n");
    g_output.add_string("<table>\n");


    g_output.add_string("<tr>");

    for (int i=0;i<cols;i++)
    {
        if (m_cols[i]->m_hidden)
            continue;

        const char *t="";
        switch (m_cols[i]->m_type)
        {
            case(Coltype::_float):
                t="float";
                break;
            case(Coltype::_int):
                t="int";
                break;
            case(Coltype::_text):
                t="text";
                break;
            case(Coltype::_bool):
                t="bool";
                break;
        }
        g_output.add_string("<th class=\"");
        g_output.add_string( t );
        g_output.add_string("\">");
        g_output.add_string( m_cols[i]->m_name.c_str() );
        g_output.add_string("</th>");
    }
    g_output.add_string("</tr>\n");
    for (std::list<Row *>::iterator it=m_rows.begin(); it!=m_rows.end();it++)
    {
        g_output.add_string("<tr>");
        Row *r = *it;

        Variant v;
        for ( int i = 0; i < cols; i++ )
        {
            Column *c = m_cols[i];

            if (c->m_hidden)
                continue;

            int offset = c->m_offset;

            static const int bufsize = 100;
            char buf[bufsize];

            g_output.add_string("<td>");
            switch(c->m_type)
            {
            case Coltype::_bool:
                g_output.add_string(r->access_column<bool_column>(offset) ? "1" : "0");
                break;
            case Coltype::_int:
                snprintf(buf, bufsize, "%i", r->access_column<int_column>(offset));
                g_output.add_string(buf);
                break;
            case Coltype::_float:
                snprintf(buf, bufsize, "%g", r->access_column<float_column>(offset));
                g_output.add_string(buf);
                break;
            case Coltype::_text:
                g_output.add_string(r->access_column<text_column>(offset)->data);
                break;
            }
            g_output.add_string("</td> ");
        }

        g_output.add_string("</tr>\n");
    }
    g_output.add_string("</table>\n");
    g_output.add_string("</body>\n");
    g_output.add_string("</html>\n");
    g_output.print();
}

void Table::json(bool trailing_comma)
{
    g_output.reset();
    int cols = (int)m_cols.size();

    g_output.add_string("  {\n    ");

    g_output.add_q_string("table_name");
    g_output.add_string(": ");
    g_output.add_q_string(m_name.c_str());
    g_output.add_string(",\n    ");

    g_output.add_q_string("query");
    g_output.add_string(": ");
    g_output.add_q_string(m_qstring.c_str());
    g_output.add_string(",\n    ");

    g_output.add_q_string("head");
    g_output.add_string(": [");

    bool append_comma = false;
    for (int i=0;i<cols;i++)
    {
        if (m_cols[i]->m_hidden)
            continue;

        if (append_comma)
            g_output.add_string(",\n");
        else
            g_output.add_string("\n");
	    append_comma = true;
        g_output.add_string("      { ");
        g_output.add_q_string("name");
        g_output.add_string(": ");
        g_output.add_q_string( m_cols[i]->m_name.c_str() );
        g_output.add_string(",");
        g_output.add_q_string("type");
        g_output.add_string(": ");
        const char *t="";
        switch (m_cols[i]->m_type)
        {
            case(Coltype::_float):
                t="float";
                break;
            case(Coltype::_int):
                t="int";
                break;
            case(Coltype::_text):
                t="text";
                break;
            case(Coltype::_bool):
                t="bool";
                break;
        }
        g_output.add_q_string( t );
        g_output.add_string(" }");
    }
    g_output.add_string("\n    ],\n    ");
    g_output.add_q_string("data");
    g_output.add_string(": [");
    bool outer_comma=false;
    for (std::list<Row *>::iterator it=m_rows.begin(); it!=m_rows.end();it++)
    {
        if (outer_comma)
            g_output.add_string(",\n      [");
        else
            g_output.add_string("\n      [");
        outer_comma = true;
        bool comma  = false;
        Row *r = *it;

        for ( int i = 0; i < cols; i++ )
        {
            Column *c = m_cols[i];

            if (c->m_hidden)
                continue;

            if (comma)
                g_output.add_string(",");

            comma = true;

            int offset = c->m_offset;
            static const int bufsize = 100;
            char buf[bufsize];

            switch(c->m_type)
            {
            case Coltype::_bool:
                g_output.add_string(r->access_column<bool_column>(offset) ? "1" : "0");
                break;
            case Coltype::_int:
                snprintf(buf, bufsize, "%i", r->access_column<int_column>(offset));
                g_output.add_string(buf);
                break;
            case Coltype::_float:
                snprintf(buf, bufsize, "%g", r->access_column<float_column>(offset));
                g_output.add_string(buf);
                break;
            case Coltype::_text:
                g_output.add_q_string(r->access_column<text_column>(offset)->data);
                break;
            }
        }

        g_output.add_string("]");
    }
    g_output.add_string("\n    ]\n");
    if (trailing_comma) {
	g_output.add_string("  },\n");
    } else {
	g_output.add_string("  }\n");
    }
    g_output.print();
}

std::string qoute_string(const std::string &s)
{
    std::string r="\"";
    int len = s.length();
    for (int i=0; i<len; i++)
    {
        if (s[i]== '"' || s[i]== '\\' )
        {
            r+='\\';
        }
        r+=s[i];
    }
    r+='"';
    return r;
}


void Table::csv(bool format)
{
    int cols = (int)m_cols.size();
    std::vector<int> col_len( cols );

    for ( int i = 0; i < cols; i++ )
        col_len[i] = 0;
    int max=0;
    char *tmp = 0;
    if (format)
    {
        for (std::list<Row *>::iterator it=m_rows.begin(); it!=m_rows.end();it++)
        {
            Row *r = *it;

            for (int i = 0; i < cols; i++)
            {
                Column *c = m_cols[i];

                if (c->m_hidden)
                    continue;

                int len = 0;

                int offset = c->m_offset;
                static const int bufsize = 100;
                char buf[bufsize];

                switch(c->m_type)
                {
                case Coltype::_bool:
                    len = 1;
                    break;
                case Coltype::_int:
                    snprintf(buf, bufsize, "%i", r->access_column<int_column>(offset));
                    len = strlen(buf);
                    break;
                case Coltype::_float:
                    snprintf(buf, bufsize, "%g", r->access_column<float_column>(offset));
                    len = strlen(buf);
                    break;
                case Coltype::_text:
                    len = qoute_string(r->access_column<text_column>(offset)->data).length();
                    break;
                }
                len++;
                if ( len > col_len[i] )
                    col_len[i] = len;
                if ( len > max )
                    max = len;
            }
        }
        for (int i=0;i<cols;i++)
        {
            if (m_cols[i]->m_hidden)
                continue;

            int l = qoute_string(m_cols[i]->m_name).length();
            l++;
            if ( l > col_len[i] )
                col_len[i] = l;
            if ( l > max )
                max = l;
        }

        tmp = new char[max+1];
        for (int i = 0; i < max; i++)
            tmp[i] = 32;
        tmp[max] = 0;
    }

    for (int i=0;i<cols;i++)
    {
        if (m_cols[i]->m_hidden)
            continue;

        printf("%s", qoute_string(m_cols[i]->m_name).c_str());
        if (i<cols-1)
            if (format)
                printf("%s,", &tmp[ qoute_string(m_cols[i]->m_name).length()+max-col_len[i]+1]);
            else
                printf(",");
    }
    printf("\n");
    for (std::list<Row *>::iterator it=m_rows.begin(); it!=m_rows.end();it++)
    {
        Row *r = *it;

        for ( int i = 0; i < cols; i++ )
        {
            Column *c = m_cols[i];

            if (c->m_hidden)
                continue;

            int offset = c->m_offset;
            static const int bufsize = 100;
            char buf[bufsize];

            std::string out;

            switch(c->m_type)
            {
            case Coltype::_bool:
                out = r->access_column<bool_column>(offset) ? "1" : "0";
                break;
            case Coltype::_int:
                snprintf(buf, bufsize, "%i", r->access_column<int_column>(offset));
                out = buf;
                break;
            case Coltype::_float:
                snprintf(buf, bufsize, "%g", r->access_column<float_column>(offset));
                out = buf;
                break;
            case Coltype::_text:
                out = qoute_string(r->access_column<text_column>(offset)->data);
                break;
            }

            fputs(out.c_str(), stdout);
            if (i<cols-1)
                if (format)
                    printf("%s,", &tmp[ out.length() + max - col_len[i] + 1 ] );
                else
                    printf(",");

        }

        printf("\n");
    }
    delete []tmp;
}

void Table::dump()
{
    int cols = (int)m_cols.size();
    int width = 25;
    char fmti[40];
    snprintf(fmti, sizeof(fmti) - 1, "%%%dd |", width);
    fmti[39] = 0;
    char fmtd[40];
    snprintf(fmtd, sizeof(fmtd) - 1, "%%%dg |", width);
    fmtd[39] = 0;
    char fmts[40];
    snprintf(fmts, sizeof(fmts) - 1, "%%%ds |", width);
    fmts[39] = 0;


    printf("Table::dump() table:%s cols:%d\n",m_name.c_str(),cols);
    printrep((width+2)*cols+1,'-'); printf("\n");
    printf("|");
    for (int i=0;i<cols;i++)
        printf(fmti,m_cols[i]->m_type);
    printf("\n");
    printf("|");
    for (int i=0;i<cols;i++)
        printf(fmts,m_cols[i]->m_name.c_str());
    printf("\n");
    printrep((width+2)*cols+1,'*'); printf("\n");
    for (std::list<Row *>::iterator it=m_rows.begin(); it!=m_rows.end();it++)
    {
        printf("|");
        Row *r = *it;

        for ( int i = 0; i < cols; i++ )
        {
            Column *c = m_cols[i];
            int offset = c->m_offset;

            switch(c->m_type)
            {
            case Coltype::_bool:
                printf(fmts, r->access_column<bool_column>(offset) ? "1" : "0");
                break;
            case Coltype::_int:
                printf(fmti, r->access_column<int_column>(offset));
                break;
            case Coltype::_float:
                printf(fmtd, r->access_column<float_column>(offset));
                break;
            case Coltype::_text:
                printf(fmts, r->access_column<text_column>(offset));
                break;
            }
        }

        printf("\n");
    }
    printrep((width+2)*cols+1,'-'); printf("\n");
}


class Parser
{
    private:
        Token::Type m_last;
    public:
        std::list<Token> m_tokens;
        typedef std::list<Token>::iterator Lit;

        Parser()
        {
            m_last=Token::_invalid;
        }

        void push(Token::Type type, const char *string)
        {
            if (!(type == Token::_semicolon && m_last == Token::_semicolon))
                m_tokens.push_back(Token(type,string));
            m_last = type;
        }


        void dump()
        {
            for (std::list<Token>::iterator it = m_tokens.begin(); it !=m_tokens.end(); it++)
            {
                printf ("Type %d: %s\n", it->get_type(), it->get_token());
            }
        }

        bool analyze(Query &q)
        {
            std::list<Token>::iterator it = m_tokens.begin();
            bool ok = true;
            while(ok)
            {
                ok = false;
                if (get_sample_stmt(q,it))
                    ok = true;

                if (get_select_stmt(q,it))
                    ok = true;
            }

            return true;
        }

        bool get_sample_stmt(Query &q,Lit &i_iter)
        {
            Lit it = i_iter;
            if (!is (it,Token::_label,"sample"))
                return false;
            it++;
            if (!is (it,Token::_number))
                return false;
            int sample = atoi(it->get_token());
            it++;
            if (!is (it,Token::_semicolon))
                return false;

            it++;
            q.m_sample = sample;
            i_iter = it;
            return true;
        }

        bool get_select_stmt(Query &q,Lit &i_iter)
        {
            Lit it = i_iter;
            if (!get_select_core(q,it))
            {
                return false;
            }

            get_from(q,it);
            get_where(q,it);
            get_group_by(q,it);
            get_order_by(q,it);
            get_limit(q,it);
            get_as(q,it);
            if (!is( it, Token::_semicolon ))
            {
                throw Error("Expected ';' but found '%s' !",it->get_token());
            }
            it++;
            i_iter=it;
            return true;
        }

        bool is(Lit &it, Token::Type type, const char *str=0 )
        {
            if (!str)
                return (it->get_type() == type );

            return (it->get_type() == type && cmpi(it->get_token(),str));
        }

        OP *get_result_column(std::list<Token>::iterator &it)
        {
            OP *res = 0;
            Lit save = it;
            if (is (it,Token::_op,"*"))
            {
                it++;
                return new OP(Token(Token::_column,"*"));
            }
            if ( it->get_type() == Token::_label )
            {
                std::string table = it->get_token();
                it++;
                if ( is(it, Token::_op, "." ) )
                {
                    it++;
                    if ( is(it, Token::_op, "*" ) )
                    {
                        it++;
                        std::string c = table+".*";
                        return new OP(Token(Token::_column,c.c_str()));
                    }
                    it=save;
                    return 0;
                }
            }
            it=save;
            if (res = get_expr(it,0))
            {
                save=it;

                if (is (it,Token::_label,"as"))
                {
                    it++;
                    if (is (it,Token::_label))
                    {
                        res->m_name=it->get_token();
                        it++;
                    }
                    else
                        it=save;
                }
            }
            return res;

            // check for valid table

        }

        bool get_select_core(Query &q, Lit &it)
        {
            Lit save = it;
            if (!is (it,Token::_label,"select"))
                return false;
            it++;
            bool again = true;
            bool success=true;
            while(again)
            {
                OP *op;
                if (op = get_result_column(it))
                {
                    q.m_select.push_back(op);
                }
                else
                {
                    success=false;
                    break;
                }

                if (is (it,Token::_op,","))
                    it++;
                else
                    again=false;
            }
            if (success)
                return true;

            it=save;
            return false;
        }

        bool get_ordering_terms(Ordering_terms &ordering, std::list<Token>::iterator &it)
        {
            OP *op;
            while(op=get_expr(it,0))
            {
                bool asc=true;
                if (it->get_type() == Token::_label)
                {
                    if (cmpi(it->get_token(),"asc"))
                    {
                    }
                    else if (cmpi(it->get_token(),"desc"))
                    {
                        asc=false;
                    }
                    else if (cmpi(it->get_token(),"collate"))
                    {
                        throw Error("unhandled option:collate");
                    }
                    else
                    {
                        ordering.m_terms.push_back(Ordering_terms::OP_dir(op,asc));
                        break;
                    }

                    it++;
                }

                ordering.m_terms.push_back(Ordering_terms::OP_dir(op,asc));

                if(!is(it, Token::_op,","))
                    break;
                it++;
            }
            return true;
        }
        bool get_group_by( Query &q, Lit &it )
        {
            if (!is (it,Token::_label,"group"))
            {
                return true;
            }
            it++;
            if (!is (it,Token::_label,"by"))
                return false;
            it++;
            bool res = get_ordering_terms(q.m_group_by,it);
            get_having(q,it);
            return res;
        }
        bool get_as( Query &q, Lit &it )
        {
            if (!is (it,Token::_label,"as"))
            {
                return true;
            }
            it++;
            if (!is (it,Token::_label))
                return false;
            q.m_result->m_name = it->get_token();
            it++;
            return true;
        }

        bool get_order_by( Query &q, Lit &it )
        {
            if (!is (it,Token::_label,"order"))
            {
                return true;
            }
            it++;
            if (!is (it,Token::_label,"by"))
                return false;
            it++;
            return get_ordering_terms(q.m_order_by,it);
        }

        bool get_limit( Query &q, Lit &it )
        {
            Lit save = it;
            if (!is (it,Token::_label,"limit"))
            {
                return true;
            }
            it++;
            if (!is (it,Token::_number))
            {
                it=save;
                throw Error("non numeric operand to limit");
            }
            q.m_limit = atoi(it->get_token());
            it++;
            save = it;

            if (!is (it,Token::_label,"offset"))
            {
                return true;
            }
            it++;
            if (!is (it,Token::_number))
            {
                it=save;
                throw Error("non numeric operand to offset");
            }
            q.m_offset = atoi(it->get_token());
            it++;
            return true;
        }

        bool get_having(Query &q, Lit &it)
        {
            Lit save = it;
            if (!is (it,Token::_label,"having"))
                return true;
            it++;
            OP *res=0;
            if (res = get_expr(it,0))
            {
                q.m_having=res;
                return true;
            }
            it=save;
            return false;
        }

        bool get_where(Query &q, Lit &it)
        {
            Lit save = it;
            if (!is (it,Token::_label,"where"))
                return true;
            it++;
            OP *res=0;
            if (res = get_expr(it,0))
            {
                q.m_where=res;
                return true;
            }
            it=save;
            return false;
        }

        bool get_from(Query &q, Lit &it)
        {
            if (!is(it, Token::_label, "from"))
                return false;
            it++;
            if (it->get_type() == Token::_label)
            {
                const char *name = it->get_token();
                if (get_packet_handler(name))
                {
                    q.m_from_name = name;
                    it++;
                    return true;
                }
                else
                    throw Error("Error in from statement, table '%s' not found", name);
            }
            throw Error("Error in from statement");
        }


        int get_stack_precedence(std::stack<OP *> &operator_stack)
        {
            int pre = 0;
            if (!operator_stack.empty())
                pre = operator_stack.top()->m_precedence;
            return pre;
        }

        // using The shunting yard algorithm
        OP *get_expr(Lit &it, int rec)
        {
            std::stack<OP *> operator_stack;
            std::stack<OP *> operand_stack;
            bool success=true;
            bool expect_expr=true;
            while(success)
            {
                success = false;
                Lit save = it;
                Lit next = it;
                next++;

                // match literal
                if (expect_expr && is_literal(it))
                {
                    OP *op = new OP(*it);
                    it++;
                    operand_stack.push(op);
                    success = true;
                    expect_expr = false;
                    continue;
                }
                // match literal
                if (expect_expr && is_unary_op(it))
                {
                    OP *op = new OP(*it);
                    op->set_type(Token::_uop);
                    it++;
                    if (!(op->m_right = get_expr(it,rec+1)))
                        throw Error("Got unary '%s' but could not parse following expression",op->get_token() );

                    operand_stack.push(op);
                    success = true;
                    expect_expr = false;
                    continue;
                }
                // match function-name (
                if (expect_expr && is(it,Token::_label) &&  is(next,Token::_paren,"("))
                {
                    OP *func = new OP(*it);
                    func->set_type( Token::_function );
                    it++;
                    it++;
                    if (is(it,Token::_op,"*"))
                    {
                        it->set_type(Token::_number);
                        it->set_token("1");
                    }
                    func->m_param[0] = get_expr(it,rec+1);
                    if (!func->m_param[0])
                        throw Error("Missing operand to function");
                    operand_stack.push(func);
                    int n=1;
                    while (n<OP::max_param() && is(it,Token::_op,","))
                    {

                        it++;
                        func->m_param[n++] = get_expr(it,rec+1);
                    }
                    if (!is(it,Token::_paren,")"))
                        throw Error("Expected ) after %s",func->get_token());
                    it++;
                    expect_expr=false;
                    success=true;
                    continue;
                }
                // match [[databasename .] table-name . ] column name
                if (expect_expr &&  is(it,Token::_label))
                {
                    OP *op = new OP(*it);
                    it++;
                    success=true;
                    op->set_type(Token::_column);
                    operand_stack.push(op);
                    expect_expr = false;
                    continue;
                }
                // match ( expr )
                if (!expect_expr && is(it,Token::_paren,","))
                {
                    break;
                }
                if (!expect_expr && is(it,Token::_paren,")"))
                {
                    break;
                }
                if (expect_expr && is(it,Token::_paren,"("))
                {
                    it++;
                    OP *op=0;
                    if (op = get_expr(it,rec+1))
                    {
                        if (is(it,Token::_paren,")"))
                        {
                            it++;
                            operand_stack.push(op);
                            expect_expr = false;
                            success=true;
                            continue;
                        }
                        throw Error("Error in expression no )");

                    }
                    it=save;
                    throw Error("Error in expression");
                }
                // bin op
                if (!expect_expr && is(it,Token::_op,"is") && is(next,Token::_op,"not")  )
                {
                    it++;
                    it->set_token("is not");

                }
		// bin op
		if (!expect_expr && is(it,Token::_op,"not") && is(next,Token::_op,"like")  )
		{
		    it++;
		    it->set_token("not like");

		}
                if (!expect_expr && is(it,Token::_op) && OP::is_binary(it->get_token()))
                {
                    OP *bop=new OP(*it);
                    while (bop->m_precedence <= get_stack_precedence(operator_stack) )
                    {

                        OP *stack_op = operator_stack.top();
                        operator_stack.pop();
                        if (operand_stack.size()>=2)
                        {

                            OP *stk1 = operand_stack.top();
                            stack_op->m_right=stk1;
                            operand_stack.pop();
                            OP *stk2 = operand_stack.top();
                            stack_op->m_left=stk2;
                            operand_stack.pop();
                            operand_stack.push(stack_op);
                        }
                    }

                    operator_stack.push(bop);
                    it++;
                    success=true;
                    expect_expr = true;
                    continue;

                }

            }
            while(!operator_stack.empty())
            {
                OP *bop = operator_stack.top();
                operator_stack.pop();
                if (bop)
                {
                    if (operand_stack.size()>=2)
                    {
                        OP *stk = operand_stack.top();
                        bop->m_right=stk;
                        operand_stack.pop();
                        OP *stk2 = operand_stack.top();
                        bop->m_left=stk2;
                        operand_stack.pop();
                        operand_stack.push(bop);
                    }
                }
            }
            if (operand_stack.size()==0)
                return 0;
            return operand_stack.top();
        }

        bool is_unary_op(Lit &it)
        {
            if (is (it,Token::_op,"-"))
                return true;
            if (is (it,Token::_op,"+"))
                return true;
            if (is (it,Token::_op,"~"))
                return true;
            if (is (it,Token::_op,"not"))
                return true;
            return false;
        }
        bool is_literal(Lit &it)
        {
            if (it->get_type() == Token::_number || it->get_type() == Token::_string)
                return true;
            if (it->get_type() == Token::_label && cmpi(it->get_token(),"null"))
                return true;
            return false;
        }
};


class Lexer
{
public:
	Lexer(Parser &p) : m_parser(p),num_state(_nan)
	{

	}

	Parser &m_parser;

	enum State
	{
		_unknown,
		_white,
		_label,
		_number,
		_op,
		_paren,
		_string
	};
	bool is_white		(const char c) {return (c==' '||c==9 || c==10||c==13); }
	bool is_char 		(const char c) {return ((c>='A' && c<='Z')||(c>='a' && c<='z')); }
	bool is_num 		(const char c) {return ((c>='0' && c<='9')); }
	bool is_op 			(const char c) {return (c=='*' ||c==','||c=='='||c=='<'||c=='>'||c=='/'||c=='|'||c=='%'||c=='+'||c=='-'||c=='&'||c=='~'||c=='!'); }
	bool is_paren       (const char c) {return (c=='(' ||c==')'); }
	bool is_termination (const char c) {return (c==0 ||c==';'); }
	bool is_quote 		(const char c) {return (c=='\''); }
	bool is_label_start	(const char c) {return (is_char(c)); }
	bool is_label_part 	(const char c) {return (is_num(c)||is_char(c)||c=='_' ); }

	bool lex(const char * i_str)
	{
		const char 	*p 			= i_str;
		State 		state 		= _white;
		const char 	*strstart 	= 0;
		bool 		is_escaped  = false;
		std::string	str			= "";

		while (true)
		{
			switch(state)
			{
				case(_unknown):
					{
						if (is_white(*p))
							state=_white;
						else if (is_label_start(*p))
							state = _label;
						else if ( is_num(*p) || ( *p == '.' && is_num( p[1] ) ) )
							state = _number;
						else if (is_quote(*p))
							state = _string;
						else if (is_paren(*p))
							state = _paren;
						else if (is_op(*p))
							state = _op;
						else if (is_termination(*p))
						{
							    m_parser.push(Token::_semicolon,";");
                                if (*p++==0)
                                {
                                    m_parser.push(Token::_end,"END");
							        return true;
                                }
						}
						else
						{
                            m_parser.push(Token::_end,"END");
							printf("Unknown char %c (%d) at %d! in statement %s\n",*p,*p,int(p-i_str),i_str);
							return false;
						}
					}
					break;
				case(_white):
					{
						if (is_white(*p))
							p++;
						else
						{
							state = _unknown;
						}
					}
					break;
				case(_string):
					{
						if ( (!is_escaped) && is_quote(*p))
						{
							if (!strstart)
							{
                                strstart=p;
								str="";
							}
							else
							{
								m_parser.push(Token::_string,str.c_str());

                                str="";
								strstart=0;
								state=_unknown;
								is_escaped=false;
							}
							p++;
						}
						else
						{
							if (is_escaped)
							{
								if(!is_quote(*p))
									str+='\\';
								is_escaped=false;
							}

							if (*p==0)
							{
								printf("Unexpected end of string in statement %s\n",strstart);
                                m_parser.push(Token::_end,"END");
								return false;

							}
							if (*p=='\\')
								is_escaped=true;
							else
								str+=(*p);
							p++;
						}

					}
					break;
				case(_number):
					{
						if (parse_num(*p))
                        {
                            if (!strstart)
                                strstart=p;
                            p++;
                        }
                        else
						{
                            if (!strstart)
                                throw Error("Numeric problem");
                            std::string label=strstart;
                            label=label.substr(0,p-strstart);
                            m_parser.push(Token::_number,label.c_str());

                            strstart=0;
                            state=_unknown;
						}
					}
					break;
				case(_label):
					{
						if (!strstart)
						{
							strstart=p++;
						}
						else if ( is_label_part(*p) )
						{
							p++;
						}
						else
						{
							std::string label=strstart;
							label=label.substr(0,p-strstart);

                            Token::Type type=Token::_label;
                            if (cmpi(label,"is"))       type=Token::_op;
                            if (cmpi(label,"not"))      type=Token::_op;
                            if (cmpi(label,"in"))       type=Token::_op;
                            if (cmpi(label,"like"))     type=Token::_op;
                            if (cmpi(label,"glob"))     type=Token::_op;
                            if (cmpi(label,"match"))    type=Token::_op;
                            if (cmpi(label,"regexp"))   type=Token::_op;
                            if (cmpi(label,"and"))      type=Token::_op;
                            if (cmpi(label,"or"))       type=Token::_op;

							m_parser.push(type,label.c_str());

							strstart=0;
							state=_unknown;
						}

					}
					break;
				case(_paren):
					{
						std::string s;
						s = *p;
						m_parser.push( Token::_paren, s.c_str() );
						p++;
						state=_unknown;
					}
					break;
				case(_op):
					{
						std::string s;
						s = *p;
                        char n=p[1];
                        switch(*p)
                        {
                            case('|'): if (n=='|') {p++;s+=*p;}  break;
                            case('>'): if (n=='=') {p++;s+=*p;}
                                       if (n=='>') {p++;s+=*p;}  break;
                            case('<'): if (n=='<') {p++;s+=*p;}
                                       if (n=='=') {p++;s+=*p;}
                                       if (n=='>') {p++;s+=*p;}  break;
                            case('='): if (n=='=') {p++;s+=*p;}  break;
                            case('!'): if (n=='=') {p++;s+=*p;}  break;
                        }
						m_parser.push( Token::_op, s.c_str() );
						p++;
						state=_unknown;
					}
					break;
				default:
					{
						printf("Missing impl char %c at %d! in statement %s\n",*p,int(p-i_str),i_str);
                        m_parser.push(Token::_end,"END");
						return false;
					}
					break;
			}


		}
	}
    bool parse_num(const char p)
    {
        switch(num_state)
        {
            case(_nan):
                num_state=_int;
                if (p=='.') num_state=_dot;
                break;
            case(_int):
                if (p=='.') num_state = _dot;
                else if (!is_num(p))
                {
                    num_state=_nan;
                    return false;
                }
                break;
            case(_dot):
                if(p=='E' || p=='e')
                num_state = _e;
                else if ( !is_num(p) )
                {
                    num_state=_nan;
                    return false;
                }
                break;
            case(_dec):
                if(p=='E' || p=='e')
                num_state = _e;
                else if ( !is_num(p) )
                {
                    num_state=_nan;
                    return false;
                }
                break;
            case(_e):
                if (p=='+'||p=='-')
                    num_state=_sign;
                else if (is_num(p))
                    num_state=_exp;
                else
                {
                    throw Error("expected number digit after E");
                }
                break;
            case(_sign):
                if ( !is_num(p) )
                    throw Error("expected number digit after E");
                num_state=_exp;
                break;
            case(_exp):
                if ( !is_num(p) )
            {
                num_state=_nan;
                return false;
            }
                break;
        }
        return true;
    }
    enum Num_state
    {
        _nan,_int,_dot,_dec,_e,_sign,_exp,_exit
    };

    Num_state num_state;
};

void Query::parse()
{
    Parser p;
    Lexer l(p);
    l.lex(m_sql.c_str());
//		p.dump();
    if (!p.analyze(*this))
        throw Error("error parsing select statement");
}

// return column and index in tables, or 0 for column if column isn't found
std::pair<Column *, int> lookup_column_in_tables(const std::vector<Table *> &tables,
                                                  const std::vector<int> &search_order,
                                                  const char *name)
{
    if (strcmp(name, "*") == 0)
        return std::pair<Column *, int>(0, 0);

    for (auto i = search_order.begin(); i != search_order.end(); ++i)
    {
        Table *table = tables[*i];
        int col_index = table->get_col_index(name);
        if (col_index >= 0)
            return std::pair<Column *, int>(table->m_cols[col_index], *i);
    }

    return std::pair<Column *, int>(0, 0);
}

OP* OP::compile(const std::vector<Table *> &tables, const std::vector<int> &search_order, Query &q)
{
    OP *ret=0;
    for (int i=0 ; i<max_param(); i++)
    {
        if (m_param[i])
        {
            m_param[i] = m_param[i]->compile(tables, search_order, q);
            if (m_param[i]->m_has_aggregate_function)
                m_has_aggregate_function = true;
        }
    }

    if (m_left)
    {
        m_left = m_left->compile(tables, search_order, q);
        if (m_left->m_has_aggregate_function)
            m_has_aggregate_function = true;
    }

    if (m_right)
    {
        m_right = m_right->compile(tables, search_order, q);
        if (m_right->m_has_aggregate_function)
            m_has_aggregate_function = true;
    }

    // default to destination row
    m_row_index = tables.size() - 1;

    if (get_type()==_column)
    {
        auto lookup = lookup_column_in_tables(tables, search_order, get_token());
        Column *column = lookup.first;
        m_row_index = lookup.second;

        if (!column)
            throw Error("Column '%s' not found", get_token());

        int offset = column->m_offset;

        m_t = column->m_type;

        switch(m_t)
        {
        case Coltype::_int:
            ret = new Column_access_int(*this, offset);
            break;
        case Coltype::_bool:
            ret = new Column_access_bool(*this, offset);
            break;
        case Coltype::_float:
            ret = new Column_access_float(*this, offset);
            break;
        case Coltype::_text:
            ret = new Column_access_text(*this, offset);
            break;
        }
    }
    else if (get_type()==_number)
    {
        const char *p=get_token();
        bool integer = true;
        while (*p!=0)
        {
            if (*p<'0'||*p>'9')
                integer=false;
            p++;
        }
        if (integer)
        {
            m_t = Coltype::_int;
            ret = new Static_int(*this);
        }
        else
        {
            m_t = Coltype::_float;
            ret = new Static_float(*this);
        }
    }
    else if (get_type()==_string)
    {
        m_t = Coltype::_text;
        ret = new Static_text(*this);
    }
    else if ((get_type()==_function)&&m_param[0])
    {
        Table *dest_table = tables[m_row_index];

        m_t = Coltype::_int;
        if ( cmpi(get_token(),"if") && m_param[1] && m_param[2] )
        {
            m_t = m_param[1]->m_t;
            if (m_param[2]->m_t > m_t)
                 m_t = m_param[2]->m_t;
            ret = new If_func(*this);
        }
        else if (cmpi(get_token(),"name") && m_param[1])
        {
            m_t = Coltype::_text;
            ret = new Name_func(*this);
        }
        else if (cmpi(get_token(),"trim") )
        {
            m_t = Coltype::_text;
            ret = new Trim_func(*this);
        }
        else if (cmpi(get_token(),"rsplit") && m_param[1])
        {
            m_t = Coltype::_text;
            ret = new Rsplit_func(*this);
        }
        else if (cmpi(get_token(),"count"))
        {
            m_t = Coltype::_int;
            ret = new Count_func(*this, dest_table);
        }
        else if (m_param[0]->ret_type()==Coltype::_float && cmpi(get_token(),"min"))
        {
            m_t = Coltype::_float;
            ret = new Min_func_float(*this, dest_table);
        }
        else if (m_param[0]->ret_type()==Coltype::_float && cmpi(get_token(),"max"))
        {
            m_t = Coltype::_float;
            ret = new Max_func_float(*this, dest_table);
        }
        else if (m_param[0]->ret_type()==Coltype::_float && cmpi(get_token(),"sum"))
        {
            m_t = Coltype::_float;
            ret = new Sum_func_float(*this, dest_table);
        }
        else if (cmpi(get_token(),"min"))
        {
            m_t = Coltype::_int;
            ret = new Min_func_int(*this, dest_table);
        }
        else if (cmpi(get_token(),"max"))
        {
            m_t = Coltype::_int;
            ret = new Max_func_int(*this, dest_table);
        }
        else if (cmpi(get_token(),"sum"))
        {
            m_t = Coltype::_int;
            ret = new Sum_func_int(*this, dest_table);
        }
        else if (cmpi(get_token(),"lower"))
        {
            m_t = Coltype::_text;
            ret = new Lower_func(*this);
        }
        else if (cmpi(get_token(),"len"))
        {
            m_t = Coltype::_int;
            ret = new Len_func(*this);
        }
        else if (cmpi(get_token(),"truncate"))
        {
            m_t = Coltype::_int;
            ret = new Truncate_func(*this);
        }
        else if (cmpi(get_token(),"stdev"))
        {
            m_t = Coltype::_float;
            ret = new Stdev_func(*this, dest_table);
        }
        else if (cmpi(get_token(),"avg"))
        {
            m_t = Coltype::_float;
            ret = new Avg_func(*this, dest_table);
        }
    }
    else if ((get_type()==_op)&&m_left&&m_right)
    {
        if (cmpi(get_token(),"||"))
        {
            m_t = Coltype::_text;
            ret = new Bin_op_concatenate(*this);
        }
        else if (cmpi(get_token(),"*"))
        {
            if (m_left->ret_type()==Coltype::_float || m_right->ret_type()==Coltype::_float)
            {
                m_t = Coltype::_float;
                ret = new Bin_op_mul_float(*this);
            }
            else
            {
                m_t = Coltype::_int;
                ret = new Bin_op_mul(*this);
            }
        }
        else if (cmpi(get_token(),"/"))
        {
            m_t = Coltype::_float;
            ret = new Bin_op_div(*this);
        }
        else if (cmpi(get_token(),"%"))
        {
            m_t = Coltype::_float;
            ret = new Bin_op_modulo(*this);
        }
        else if (cmpi(get_token(),"+"))
        {
            if (m_left->ret_type()==Coltype::_float || m_right->ret_type()==Coltype::_float)
            {
                m_t = Coltype::_float;
                ret = new Bin_op_add_float(*this);
            }
            else
            {
                m_t = Coltype::_int;
                ret = new Bin_op_add(*this);
            }
        }
        else if (cmpi(get_token(),"-"))
        {
            if (m_left->ret_type()==Coltype::_float || m_right->ret_type()==Coltype::_float)
            {
                m_t = Coltype::_float;
                ret = new Bin_op_sub_float(*this);
            }
            else
            {
                m_t = Coltype::_int;
                ret = new Bin_op_sub(*this);
            }
        }
        else if (cmpi(get_token(),"<<"))
        {
            m_t = Coltype::_int;
            ret = new Bin_op_arithmetic_shift_left(*this);
        }
        else if (cmpi(get_token(),">>"))
        {
            m_t = Coltype::_int;
            ret = new Bin_op_arithmetic_shift_right(*this);
        }
        else if (cmpi(get_token(),"&"))
        {
            m_t = Coltype::_int;
            ret = new Bin_op_bitwise_and(*this);
        }
        else if (cmpi(get_token(),"|"))
        {
            m_t = Coltype::_int;
            ret = new Bin_op_bitwise_or(*this);
        }
        else if (cmpi(get_token(),"<"))
        {
            m_t = Coltype::_bool;
            ret = new Bin_op_lt(*this);
        }
        else if (cmpi(get_token(),"<="))
        {
            m_t = Coltype::_bool;
            ret = new Bin_op_lteq(*this);
        }
        else if (cmpi(get_token(),">"))
        {
            m_t = Coltype::_bool;
            ret = new Bin_op_gt(*this);
        }
        else if (cmpi(get_token(),">="))
        {
            m_t = Coltype::_bool;
            ret = new Bin_op_gteq(*this);
        }
        else if (cmpi(get_token(),"="))
        {
            m_t = Coltype::_bool;
            ret = new Bin_op_eq(*this);
        }
        else if (cmpi(get_token(),"=="))
        {
            m_t = Coltype::_bool;
            ret = new Bin_op_eq(*this);
        }
        else if (cmpi(get_token(),"like"))
    	{
    	    m_t = Coltype::_bool;
    	    ret = new Bin_op_like(*this);
    	}
    	else if (cmpi(get_token(),"not like"))
    	{
    	    m_t = Coltype::_bool;
    	    ret = new Bin_op_not_like(*this);
    	}
        else if (cmpi(get_token(),"!="))
        {
            m_t = Coltype::_bool;
            ret = new Bin_op_not_eq(*this);
        }
        else if (cmpi(get_token(),"<>"))
        {
            m_t = Coltype::_bool;
            ret = new Bin_op_not_eq(*this);
        }
        else if (cmpi(get_token(),"is"))
        {
            m_t = Coltype::_bool;
            ret = new Bin_op_eq(*this);
        }
        else if (cmpi(get_token(),"is not"))
        {
            m_t = Coltype::_bool;
            ret = new Bin_op_not_eq(*this);
        }
        else if (cmpi(get_token(),"and"))
        {
            m_t = Coltype::_bool;
            ret = new Bin_op_and(*this);
        }
        else if (cmpi(get_token(),"or"))
        {
            m_t = Coltype::_bool;
            ret = new Bin_op_or(*this);
        }
    }
    else if ( ( get_type() == _uop ) && m_right )
    {
        if (cmpi(get_token(),"not"))
        {
            m_t = Coltype::_bool;
            ret = new Un_op_not(*this);
        }
        else if (cmpi(get_token(),"+"))
        {
            ret = m_right;
        }
        else if (cmpi(get_token(),"-"))
        {
            if (m_right->ret_type()==Coltype::_float)
            {
                m_t = Coltype::_float;
                ret = new Un_op_neg_float(*this);
            }
            else
            {
                m_t = Coltype::_int;
                ret = new Un_op_neg(*this);
            }
        }
        else if (cmpi(get_token(),"~"))
        {
            m_t = Coltype::_int;
            ret = new Un_op_ones_complement(*this);
        }
    }
    clear_ptr();
    if (!ret)
        throw Error("Unknown operator error '%s' !",get_token());

    delete this;

    return ret;
}

void OP::evaluate_aggregate_operands(Row **rows)
{
    if (m_left)
        m_left->evaluate_aggregate_operands(rows);
    if (m_right)
        m_right->evaluate_aggregate_operands(rows);
    for (int i = 0; i < max_param(); ++i)
        if (m_param[i])
            m_param[i]->evaluate_aggregate_operands(rows);
}

void OP::combine_aggregate(Row *base_row, Row *other_row)
{
    if (m_left)
        m_left->combine_aggregate(base_row, other_row);
    if (m_right)
        m_right->combine_aggregate(base_row, other_row);
    for (int i = 0; i < max_param(); ++i)
        if (m_param[i])
            m_param[i]->combine_aggregate(base_row, other_row);
}

// return any column access ops found in given list of op trees - they don't
// have to be compiled beforehand; duplicate column tokens are skipped
std::vector<OP *> find_unique_column_ops(std::vector<OP *> ops)
{
    std::vector<OP *> res;

    while (!ops.empty())
    {
        OP *op = ops.back();
        ops.pop_back();

        if (op->m_left)
            ops.push_back(op->m_left);
        if (op->m_right)
            ops.push_back(op->m_right);
        for (int i = 0; i < op->max_param(); ++i)
            if (op->m_param[i])
                ops.push_back(op->m_param[i]);

        if (op->get_type() == Token::_column)
        {
            bool found = false;

            for (auto i = res.begin(); i != res.end(); ++i)
            {
                if (cmpii((*i)->get_token(), op->get_token()))
                {
                    found = true;
                    break;
                }
            }

            if (!found)
                res.push_back(op);
        }
    }

    return res;
}

void Query::replace_star_column_with_all_columns()
{
    bool found_star = false;
    for (std::vector<OP *>::iterator i = m_select.begin(); i != m_select.end(); ++i)
    {
        if (strcmp((*i)->get_token(), "*") == 0) {
            found_star = true;
            break;
        }
    }

    if (found_star)
    {
        for (auto i = m_select.begin(); i != m_select.end(); ++i)
            delete *i;
        m_select.clear();

        if (!m_from_name.empty())
        {
            Packet_handler *handler = get_packet_handler(m_from_name);

            for (auto i = handler->packet_columns.begin(); i != handler->packet_columns.end(); ++i)
                m_select.push_back(new OP(Token(Token::_column, i->name)));
        }
    }
}

void Query::process_from()
{
    replace_star_column_with_all_columns();

    if (m_from_name.empty())
        return;

    std::vector<OP *> all_ops;
    all_ops.insert(all_ops.end(), m_select.begin(), m_select.end());
    if (m_where)
        all_ops.push_back(m_where);
    // skip m_having, it can't access source columns
    for (auto i = m_order_by.m_terms.begin(); i != m_order_by.m_terms.end(); ++i)
        all_ops.push_back(i->m_op);
    for (auto i = m_group_by.m_terms.begin(); i != m_group_by.m_terms.end(); ++i)
        all_ops.push_back(i->m_op);

    auto used_columns = find_unique_column_ops(all_ops);

    // add from table with used columns
    Packet_handler *handler = get_packet_handler(m_from_name);
    for (auto j = handler->packet_columns.begin(); j != handler->packet_columns.end(); ++j)
        for (auto i = used_columns.begin(); i != used_columns.end(); ++i)
            if (cmpii(j->name, (*i)->get_token()))
                m_used_from_column_ids.push_back(j->id);

    m_from = handler->create_table(m_used_from_column_ids);
}

void Query::process_select(Row **rows, Row *dest, GenericAccessor *dest_accessors)
{
    for (unsigned int i=0, size = m_select.size(); i < size; ++i)
    {
        OP *op = m_select[i];
        if (!op)
            continue;

        if (op->m_has_aggregate_function)
        {
            // defer evaluating aggregate functions, just eval their operands
            op->evaluate_aggregate_operands(rows);
        }
        else
        {
            Variant v;
            op->evaluate(rows, v);
            dest_accessors[i].set(dest, v);
        }
    }
}

void Query::combine_aggregates_in_select(Row *base_row, Row *other_row)
{
    for (unsigned int i = 0; i < m_select.size(); ++i)
    {
        OP *op = m_select[i];
        if (op && op->m_has_aggregate_function)
            op->combine_aggregate(base_row, other_row);
    }
}

void Query::process_aggregates_in_select(Row **rows, Row *dest, GenericAccessor dest_accessors[])
{
    for (unsigned int i = 0; i < m_select.size(); ++i)
    {
        OP *op = m_select[i];
        if (op && op->m_has_aggregate_function)
        {
            Variant v;
            op->evaluate(rows, v);
            dest_accessors[i].set(dest, v);
        }
    }
}

bool Query::process_where(Row **rows)
{
    if (!m_where)
        return true;

    Variant v;
    m_where->evaluate(rows, v);
    return v.get_bool();
}

bool Query::process_having(Row **rows)
{
    if (!m_having)
        return true;

    Variant v;
    m_having->evaluate(rows, v);
    return v.get_bool();
}

std::vector<Variant> process_group_by_key(Ordering_terms &group_by, Row **rows)
{
    int size = group_by.m_terms.size();

    std::vector<Variant> res(size);

    for (int i = 0; i < size; ++i)
        group_by.m_terms[i].m_op->evaluate(rows, res[i]);

    return res;
}

bool Query::has_aggregate_functions()
{
    // this assumes the ops have been compiled
    for (std::vector<OP *>::iterator it=m_select.begin();it!=m_select.end();it++)
        if ((*it)->m_has_aggregate_function)
            return true;

    return false;
}

void Query::execute(Reader &reader)
{
    std::vector<Table *> tables;
    std::vector<int> search_results_last, search_results_first, search_results_only;

    // set up tables
    process_from();

    if (m_from)
        tables.push_back(m_from);
    tables.push_back(m_result);

    for (int i = 0; i < int(tables.size()); ++i)
        search_results_last.push_back(i);
    for (int i = int(tables.size()) - 1; i >= 0; --i)
        search_results_first.push_back(i);

    search_results_only.push_back(tables.size() - 1);

    std::vector<Row *> row_ptrs(tables.size());
    Row **rows = &row_ptrs[0];

    std::vector<GenericAccessor> result_accessors_vector;

    // compile
    for (auto i = m_select.begin(); i != m_select.end(); ++i)
    {
        *i = (*i)->compile(tables, search_results_last, *this);
        Column *col = m_result->add_column((*i)->get_name(), (*i)->ret_type());
        GenericAccessor a;
        a.m_offset = col->m_offset;
        a.m_type = col->m_type;
        result_accessors_vector.push_back(a);
    }

    if (m_where)
        m_where=m_where->compile(tables, search_results_last, *this);

    if (m_having)
        m_having=m_having->compile(tables, search_results_only, *this);

    if (m_group_by.exist())
        m_group_by.compile(tables, search_results_last, *this);

    if (m_order_by.exist())
    {
        // copy any missing columns to result table as hidden so we can
        // order by them
        std::vector<OP *> ops;
        for (auto i = m_order_by.m_terms.begin(); i != m_order_by.m_terms.end(); ++i)
            ops.push_back(i->m_op);

        std::vector<OP *> column_ops = find_unique_column_ops(ops);

        for (auto i = column_ops.begin(); i != column_ops.end(); ++i)
        {
            const char *name = (*i)->get_token();
            auto lookup = lookup_column_in_tables(tables, search_results_first, name);
            if (lookup.first and lookup.second < int(tables.size()) - 1) {
                // found, but not in result table
                OP *copying_op = new OP(**i);
                copying_op = copying_op->compile(tables, search_results_last, *this);
                m_select.push_back(copying_op);
                Column *col = m_result->add_column(copying_op->get_name(), copying_op->ret_type(), -1, Column::HIDDEN);
                GenericAccessor a;
                a.m_offset = col->m_offset;
                a.m_type = col->m_type;
                result_accessors_vector.push_back(a);
            }
        }

        // we only provide access to result table for "order by"; in order
        // to make the sort thing work correctly the result table currently
        // has to be at index 0
        std::vector<Table *> tables_result_only = { m_result };
        std::vector<int> tables_result_only_search = { 0 };
        m_order_by.compile(tables_result_only, tables_result_only_search, *this);
    }

    // execute
    GenericAccessor *result_accessors = &result_accessors_vector[0];
    bool aggregate_functions = has_aggregate_functions();

    int count=0;
    bool limiter = !m_order_by.exist() && !m_group_by.exist() && !aggregate_functions && m_limit>=0;

    if (m_from)
    {
        bool first_row = true;
        Packet_handler *handler = get_packet_handler(m_from_name);

        reader.seek_to_start();

        const int src_i = 0, dest_i = tables.size() - 1;

        rows[src_i] = m_from->create_row();

        if (m_group_by.exist() || aggregate_functions)
        {
            std::unordered_map<std::vector<Variant>, Row*> groups;

            rows[dest_i] = 0;
            while (reader.read_next(handler, m_used_from_column_ids, *rows[src_i], first_row or m_sample == 0 ? 0 : m_sample - 1))
            {
                // fill in groups
                if (rows[dest_i])
                    rows[dest_i]->reset_text_columns(m_result->m_text_column_offsets);
                else
                    rows[dest_i] = m_result->create_row();

                process_select(rows, rows[dest_i], result_accessors);
                if (process_where(rows))
                {
                    auto key = process_group_by_key(m_group_by, rows);
                    Row* &entry = groups[key];
                    if (entry)
                    {
                        combine_aggregates_in_select(entry, rows[dest_i]);
                    }
                    else
                    {
                        entry = rows[dest_i];
                        rows[dest_i] = 0;
                    }
                }

                first_row = false;
                rows[src_i]->reset_text_columns(m_from->m_text_column_offsets);
            }
            if (rows[dest_i])
                m_result->delete_row(rows[dest_i]);

            // put groups into result
            for (auto i = groups.begin(); i != groups.end(); ++i)
            {
                rows[dest_i] = i->second;
                // propagate the aggregate results through the evaluation tree
                process_aggregates_in_select(rows, rows[dest_i], result_accessors);
                if (process_having(rows))
                    m_result->add_row(rows[dest_i]);
                else
                    m_result->delete_row(rows[dest_i]);
            }
        }
        else
        {
            rows[dest_i] = m_result->create_row();
            while (reader.read_next(handler, m_used_from_column_ids, *rows[src_i], first_row or m_sample == 0 ? 0 : m_sample - 1))
            {
                // fill in result
                process_select(rows, rows[dest_i], result_accessors);
                if (process_where(rows))
                {
                    bool commit = true;
                    if (limiter)
                    {
                        int l = count++;
                        if (m_offset>0)
                            l-=m_offset;
                        if (m_limit>=0 && l>=m_limit)
                            break;

                        if (l<0)
                            commit=false;
                    }

                    if (commit)
                    {
                        m_result->add_row(rows[dest_i]);
                        rows[dest_i] = m_result->create_row();
                    }
                }

                first_row = false;
                rows[src_i]->reset_text_columns(m_from->m_text_column_offsets);
            }
            m_result->delete_row(rows[dest_i]);
        }

        m_from->delete_row(rows[src_i]);
    }
    else
    {
        const int dest_i = tables.size() - 1;
        rows[dest_i] = m_result->create_row();
        process_select(rows, rows[dest_i], result_accessors);
        if (process_where(rows))
            m_result->add_row(rows[dest_i]);
        else
            m_result->delete_row(rows[dest_i]);
    }

    if (m_order_by.exist())
        m_result->per_sort(m_order_by);

    if (m_limit>=0 && !limiter)
        m_result->limit(m_limit,m_offset);
}

DB::DB()
{
    Column::init_defs();
}

DB::~DB()
{
}

bool DB::query(const char *q)
{
    return false;
}

Table *DB::get_table(const char *i_name)
{
    std::string name = lower(i_name);
    Table *t = 0;
    std::map<std::string,Table *>::iterator it = m_tables.find(name);
    if (it!=m_tables.end())
        t=it->second;

    return t;
}
Table *DB::create_or_use_table(const char *i_name)
{
    std::string name = lower(i_name);
    Table *t = get_table(name.c_str());
    if (!t)
        t = create_table(name.c_str());

    return t;
}
Table *DB::create_table(const char *i_name)
{
    std::string name = lower(i_name);
    Table *t = new Table(name.c_str());
    m_tables[std::string(name.c_str())]=t;

    return t;
}
Column::Column(const char *name,Coltype::Type type, int id, bool hidden): m_name(name), m_type(type), m_def(Column::m_coldefs[type]), m_id(id), m_offset(0)
{
    m_hidden = hidden;
}

void Trim_func::evaluate(Row **rows, Variant &v)
{
    Variant str;
    m_param[0]->evaluate(rows, str);
    RefCountStringHandle str_handle(str.get_text());
    const char *s = (*str_handle)->data;

    const char *t;
    RefCountStringHandle trim_handle;
    if (m_param[1])
    {
        Variant trim;
        m_param[1]->evaluate(rows, trim);
        trim_handle.set(trim.get_text());
        t = (*trim_handle)->data;
    }
    else
        t = " ";

    int l = strlen(t);
    if (l <= 0)
    {
        v = *str_handle;
        return;
    }

    int slen = strlen(s);
    int start = 0, end = slen;

    // left trim
    while (end - start >= l && memcmp(s + start, t, l) == 0)
        start += l;

    // right trim
    while (end - start >= l && memcmp(s + end - l, t, l) == 0)
        end -= l;

    if (start == 0 && end == slen)
        v = *str_handle;
    else
    {
        RefCountStringHandle res(RefCountString::construct(s, start, end));
        v = *res;
    }
}

DB g_db;

Coldef Column::m_coldefs[Coltype::_max];

}
