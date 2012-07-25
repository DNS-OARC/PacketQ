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
#include <stdio.h>
#include <stdlib.h>
#include "json.h"

namespace se {

class JParser 
{
    public:
    enum Type
    {
        _end, _op, _string, _num
    };
    enum State
    {
        _value='V',_object='O',_array='A',_prop='P'
    };
    enum Stage
    {
        _root,_rarr,_tableobj, _tablename, _query, _head, _colname, _data, _colval
    };
    JParser()
    {
        m_stage    = _root;
        m_sp       = 0;
        m_st[m_sp] = _value;
        m_table    = 0;
        m_row      = 0;
    }

    void st_pop()
    {
        if (m_sp>0)
            m_sp--;
    }
    void st_push(State st,std::string val="")
    {
        if (m_sp>=31)
            return;
        m_st[++m_sp] = st;
        m_name[m_sp] = val;
        m_num[m_sp]  = 0;
    }
    void push(Type type, const char *string)
    {
        switch (m_st[m_sp])
        {
            case(_value):
                if (type == _op && string[0]=='[')
                {
                    if (m_stage==_root)
                        m_stage = _rarr;
                    st_push(_array);
                    st_push(_value);
                }
                if (type == _op && string[0]=='{')
                {
                    if (m_stage==_rarr)
                        m_stage = _tableobj;
                    st_push(_object);
                    st_push(_prop);
                }
                if (type == _string || type == _num)
                {
                    st_pop();
                    if (m_stage==_head)
                    {
                        if (strcmp(m_name[m_sp].c_str(),"type")==0)
                                m_coltype=string;
                        if (strcmp(m_name[m_sp].c_str(),"name")==0)
                                m_colname=string;
                    }
                    if (m_stage==_data)
                    {
                        int c = m_num[m_sp];
                        if (c==0)
                            m_row = m_table->create_row();
                        if (m_row)
                            m_row->set(c,string);
                    }
		    if (m_stage==_tablename)
                    {
                        m_table = g_db.create_or_use_table(string); 
                        m_stage = _tableobj;
		    }
		    if (m_stage==_query) {
			;
		    }
                }
            break;
            case(_object):
            {
                if (type == _op &&  string[0]==',')
                {
                    st_push(_prop);
                }
                else if (type == _op &&  string[0]=='}')
                {
                    st_pop();
                    st_pop();
                }
            }
            break;
            case(_array):
            {
                    if (m_stage==_head)
                    {
                        if (m_table)
                        {
                            if( m_table->get_col_index( m_colname.c_str() )==-1 )
                                m_table->add_column( m_colname.c_str(), m_coltype.c_str() );
                        }
                    }
                if (type == _op &&  string[0]==',')
                {
                    m_num[m_sp]++;
                    st_push(_value);
                }
                else if (type == _op &&  string[0]==']')
                {
                    if (m_stage==_head)
                    {
                        m_stage = _tableobj;
                    }
                    st_pop();
                    st_pop();
                }
            }
            break;
            case(_prop):
                if (type == _string)
                {
                    if (m_stage==_tableobj && strcmp(string,"data")==0)
                        m_stage=_data;
                    if (m_stage==_tableobj && strcmp(string,"head")==0)
                        m_stage=_head;
		    if (m_stage==_tableobj && strcmp(string,"table_name")==0)
			m_stage=_tablename;
		    if (m_stage==_tableobj && strcmp(string,"query")==0)
			m_stage=_query;
                    m_name[m_sp-1] = string;
                }
                else if (type == _op &&  string[0]==':')
                {
                    st_pop();
                    st_push(_value);
                }
            break;
        }
    }

    int     m_sp;
    std::string m_name[32];
    int         m_num[32];
    State       m_st[32];
    Stage       m_stage;
    std::string m_colname;
    std::string m_coltype;
    Table       *m_table;
    Row         *m_row;
};


class JLexer
{
public:
    JLexer( Json_file &jf) : m_jf(jf), num_state(_nan)
	{
	}

    int peek() { return m_jf.peek();}
    int eat()  { return m_jf.eat(); }

    Json_file &m_jf;
	JParser m_parser;

	enum State
	{
		_unknown,
		_white,
		_number,
		_string,
		_label,
		_op
	};
	bool is_white		(const char c) {return (c==' '||c==9 || c==10||c==13); }
	bool is_char 		(const char c) {return ((c>='A' && c<='Z')||(c>='a' && c<='z')); }
	bool is_num 		(const char c) {return ((c>='0' && c<='9')); }
	bool is_op 			(const char c) {return (c=='{' ||c=='}'||c=='['||c==']'||c==','||c==':'); }
	bool is_termination (const char c) {return (c==0 ||c==';'); }
	bool is_quote 		(const char c) {return (c=='\"'); }
	bool is_label	    (const char c) {return (is_char(c)); }

    enum Num_state
    {
        _nan, _int, _dot, _dec, _e, _sign, _exp, _exit
    };

    bool lex() 
    {
		State 		state = _white;
        
        while(true)
        {
            int c = peek();
            if (c<0)
            {
                break;
            }
            int line = 0;
            switch(state)
            {
                case(_unknown):
                    {
                        if (is_white(c)) 
                            state=_white;
                        else if (is_label(c))
                            state = _label;
                        else if ( is_num(c) || c == '-' )
                            state = _number;
                        else if (is_quote(c))
                            state = _string;
                        else if (is_op(c))
                            state = _op;
                        else if (is_termination(c))
                        {
                            if (c<=0)
                            {
                                m_parser.push(JParser::_end,"END");
                                return true;
                            }
                        }
                        else
                        {
                            m_parser.push(JParser::_end,"END");
                            printf("Unknown char %c (%d) at line %d! in json \n",c,c,line);
                            return false;
                        }
                    }
                    break;
                case(_op):
                    {
                        char str[2];
                        str[0]=c;
                        str[1]=0;
                        m_parser.push(JParser::_op,str);
                        eat();
                        state = _unknown;
                    }
                    break;
                case(_white):
                    {
                        if (is_white(c))
                        {
                            c =eat();
                            if (c==13)
                            {
                                int n =peek();
                                if (n==10)
                                    eat();
                                c=10;
                            }
                            if (c==10)
                                line++;
                        }
                        else
                        {
                            state = _unknown;
                        }
                    }
                    break;
				case(_string):
					{
                        eat();
                        std::string str="";
                        while((c=peek())>0)
                        {
							if (c=='"')
							{
                                eat();
								m_parser.push(JParser::_string,str.c_str());
								state=_unknown;
                                break;
							}
							if (c=='\\')
							{
                                eat();
                                c= peek();
                                if (c=='t') c=9;
                                if (c=='n') c=10;
                                if (c=='r') c=13;
                                if (c=='u') 
                                {
                                    // grab hex code
                                }
							}
                            str+=c;
                            eat();
                        }
					}
					break;
				case(_number):
                    {
                        std::string number="";
                        if (c == '-')
                        {
                            number+=eat();
                            c = peek();
                        }
                        if (c=='0')
                        {
                            number+=eat();
                            c = peek();
                        }
                        else
                        {
                            while (is_num(c))
                            {
                                number+=eat();
                                c=peek();
                            }
                        }
                        if (c=='.')
                        {
                            number+=eat();
                            c=peek();
                            while (is_num(c))
                            {
                                number+=eat();
                                c=peek();
                            }
                        }
                       if (c=='e' || c=='E')
                       {
                            number+=eat();
                            c=peek();
                            if (c=='+' || c=='-')
                            {
                                number+=eat();
                                c=peek();
                                if (!is_num(c))
                                {
                                    printf("bad exponent in number on line %d",line);
                                    return false;
                                }
                                while (is_num(c))
                                {
                                    number+=eat();
                                    c=peek();
                                }
                            }
                        }
                        m_parser.push(JParser::_num,number.c_str());
                        state=_unknown;
                    }
                    break;
                default:
                    return false;
                    break;
            }
        }
    }

    
    Num_state num_state;
};

bool Json_file::read_file()
{

    JParser parse;
    JLexer  lexer(*this);
    lexer.lex();

    return false;
}

}

