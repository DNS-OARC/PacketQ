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
#ifndef OUTPUT_H
#define OUTPUT_H

#include <stdio.h>
#include <stdlib.h>

namespace se {

class Output
{
	char m_buffer[0x10000];
	char m_diglut[0x100][4];
	int m_len;
	int m_tot;
	public:
	Output()
	{
		for(int i=0;i<256;i++)
			sprintf(m_diglut[i],"%d",i);

		m_len=0;
		m_tot=0;
	}
	~Output()
	{
//		print();
	}
    void reset()    { m_len=0;      }
	void print()
	{
		if (!m_len)
			return;
		fwrite(m_buffer,m_len,1,stdout);
		m_tot+=m_len;
		m_len=0;
	}
	void flush()
	{
		print();
		fflush(stdout);
	}
	inline void add_q_string(const char *p)
	{
		m_buffer[m_len++]='"';
		add_string_esc_json(p);
		m_buffer[m_len++]='"';
	}
	inline void add_string_esc_json(const char *p)
	{
		if (m_len>sizeof(m_buffer)/2)
			print();
		char c;
		while(c=*p++)
		{
			if (c=='\\')
			{
				m_buffer[m_len++]='\\';
				c='\\';
			}
			if (c=='"')
			{
				m_buffer[m_len++]='\\';
			}
			m_buffer[m_len++]=c;
		}
	}
	inline void add_string_esc_xml(const char *p)
	{
		if (m_len>sizeof(m_buffer)/2)
			print();
		char c;
		while((c=*p++)>'A')
		{
			m_buffer[m_len++]=c;
		}
		if (c==0)
			return;
		p--;
		while(c=*p++)
		{
			if (c=='>')
			{
				m_buffer[m_len++]='&';
				add_string("gt");
				c=';';
			}
			if (c=='<')
			{
				m_buffer[m_len++]='&';
				add_string("lt");
				c=';';
			}
			if (c=='\'')
			{
				m_buffer[m_len++]='&';
				add_string("apos");
				c=';';
			}
			if (c=='"')
			{
				m_buffer[m_len++]='&';
				add_string("quot");
				c=';';
			}
			m_buffer[m_len++]=c;
			if (c=='&')
			{
				add_string("amp;");
			}
		}
	}
    inline void check()
    {
		if (m_len>sizeof(m_buffer)/2)
			print();
    }
	inline void add_string(const char *p)
	{
        check();
		char c;
		while(c=*p++)
		{
			m_buffer[m_len++]=c;
		}
	}

	inline void add_hex_ushort(unsigned short v)
	{
		static const char lut[]="0123456789abcdef";
		if (v&0xf000)
		{
			m_buffer[m_len++]=lut[v>>12];
			m_buffer[m_len++]=lut[(v>>8)&0xf];
			m_buffer[m_len++]=lut[(v>>4)&0xf];
			m_buffer[m_len++]=lut[v&0xf];
			return;
		}
		if (v&0xf00)
		{
			m_buffer[m_len++]=lut[(v>>8)&0xf];
			m_buffer[m_len++]=lut[(v>>4)&0xf];
			m_buffer[m_len++]=lut[v&0xf];
			return;
		}
		if (v&0xf0)
		{
			m_buffer[m_len++]=lut[(v>>4)&0xf];
			m_buffer[m_len++]=lut[v&0xf];
			return;
		}
		m_buffer[m_len++]=lut[v&0xf];
	}

	inline void add_attr_ipv6(const char *name,unsigned char *addr)
	{
        check();
		add_string_q(name);
		m_buffer[m_len++]='=';
		m_buffer[m_len++]='"';
		
		unsigned short digs[8];
		unsigned char *p=addr;
		int longest_run=0;
		int longest_p=9;
		int cur_run=0;
		for (int i=0;i<8;i++)
		{
			digs[i]= ((unsigned short)(p[0])<<8)|(unsigned short)(p[1]);
			if (digs[i]==0)
			{
				cur_run++;
				if ((cur_run>1) && (cur_run>longest_run))
				{
					longest_run=cur_run;
					longest_p=i+1-cur_run;
				}
			}
			else
				cur_run=0;

			p+=2;
		}

		for (int i=0;i<8;i++)
		{
			if (i>=longest_p && i<longest_p+longest_run)
			{
				if (i==longest_p)
				{
					if (i==0)
						m_buffer[m_len++]=':';
					m_buffer[m_len++]=':';
				}
			}
			else
			{
				add_hex_ushort(digs[i]);
				if (i!=7)
					m_buffer[m_len++]=':';
			}
		}


		m_buffer[m_len++]='"';
		m_buffer[m_len++]=' ';
	}



	inline void add_attr_ipv4(const char *p,unsigned int i)
	{
        check();
		add_string_q(p);
		m_buffer[m_len++]='=';
		m_buffer[m_len++]='"';
		add_string_q(m_diglut[i&255]);
		m_buffer[m_len++]='.';
		add_string_q(m_diglut[(i>>8)&255]);
		m_buffer[m_len++]='.';
		add_string_q(m_diglut[(i>>16)&255]);
		m_buffer[m_len++]='.';
		add_string_q(m_diglut[(i>>24)]);
		m_buffer[m_len++]='"';
		m_buffer[m_len++]=' ';
	}

	inline void add_attr_bool(const char *p,bool i)
	{
		if (!i)
			return;
        check();
		add_string_q(p);
		m_buffer[m_len++]='=';
		m_buffer[m_len++]='"';
		m_buffer[m_len++]=i?'1':'0';
		m_buffer[m_len++]='"';
		m_buffer[m_len++]=' ';
	}

	inline void add_int(unsigned int i)
	{
        check();
		if (i<256)
		{
			add_string_q(m_diglut[i&255]);
		}
		else
		{
			char d[5];

			char *cd=d;
			while(i>0)
			{
				unsigned int n=i;
				i=i/100;
				n=n-(i*100);
				*cd++=n;
			}
			if (cd!=d)
			{
				char t=*--cd;
				add_string_q(m_diglut[t]);
			}
			while(cd!=d)
			{
				char t=*--cd;
				if (t>=10)
					add_string_q(m_diglut[t]);
				else
				{
					m_buffer[m_len++]='0';
					m_buffer[m_len++]='0'+t;
				}
			}
		}
	}
	inline void add_attr_int(const char *p,unsigned int i)
	{
        check();
		if (i==0)
			return;
		add_string_q(p);
		m_buffer[m_len++]='=';
		m_buffer[m_len++]='"';
        add_int(i); 
		m_buffer[m_len++]='"';
		m_buffer[m_len++]=' ';
	}

	inline void add_attr_str(const char *p,const char *t)
	{
		add_string(p);
		m_buffer[m_len++]='=';
		m_buffer[m_len++]='"';
		add_string_esc_json(t);
		m_buffer[m_len++]='"';
		m_buffer[m_len++]=' ';
	}
    private:
	inline void add_string_q(const char *p)
	{
		char c;
		while(c=*p++)
		{
			m_buffer[m_len++]=c;
		}
	}

};


class Str_conv
{
	char m_buffer[0x10000];
	char m_diglut[0x100][4];
	int m_len;
	int m_tot;
	public:
	Str_conv()
	{
		for(int i=0;i<256;i++)
			sprintf(m_diglut[i],"%d",i);

		m_len=0;
		m_tot=0;
	}
	~Str_conv()
	{
//		print();
	}
    const char *get()
    {
        m_buffer[m_len]=0;
        return m_buffer;
    }
    int get_len()   { return m_len; }
    void reset()    { m_len=0;      }
	inline void add_attr_ipv6(unsigned char *addr)
	{
		unsigned short digs[8];
		unsigned char *p = &addr[14];
		int longest_run=0;
		int longest_p=9;
		int cur_run=0;
		for (int i=0;i<8;i++)
		{
			digs[i]= ((unsigned short)(p[1])<<8)|(unsigned short)(p[0]);
			if (digs[i]==0)
			{
				cur_run++;
				if ((cur_run>1) && (cur_run>longest_run))
				{
					longest_run=cur_run;
					longest_p=i+1-cur_run;
				}
			}
			else
				cur_run=0;

			p-=2;
		}

		for (int i=0;i<8;i++)
		{
			if (i>=longest_p && i<longest_p+longest_run)
			{
				if (i==longest_p)
				{
					if (i==0)
						m_buffer[m_len++]=':';
					m_buffer[m_len++]=':';
				}
			}
			else
			{
				add_hex_ushort(digs[i]);
				if (i!=7)
					m_buffer[m_len++]=':';
			}
		}
	}


	inline void add_string_q(const char *p)
	{
		char c;
		while(c=*p++)
		{
			m_buffer[m_len++]=c;
		}
	}

	inline void add_attr_ipv4(unsigned int i)
	{
		add_string_q(m_diglut[(i>>24)]);
		m_buffer[m_len++]='.';
		add_string_q(m_diglut[(i>>16)&255]);
		m_buffer[m_len++]='.';
		add_string_q(m_diglut[(i>>8)&255]);
		m_buffer[m_len++]='.';
		add_string_q(m_diglut[(i>>0)&255]);
	}
	inline void add_hex_ushort(unsigned short v)
	{
		static const char lut[]="0123456789abcdef";
		if (v&0xf000)
		{
			m_buffer[m_len++]=lut[v>>12];
			m_buffer[m_len++]=lut[(v>>8)&0xf];
			m_buffer[m_len++]=lut[(v>>4)&0xf];
			m_buffer[m_len++]=lut[v&0xf];
			return;
		}
		if (v&0xf00)
		{
			m_buffer[m_len++]=lut[(v>>8)&0xf];
			m_buffer[m_len++]=lut[(v>>4)&0xf];
			m_buffer[m_len++]=lut[v&0xf];
			return;
		}
		if (v&0xf0)
		{
			m_buffer[m_len++]=lut[(v>>4)&0xf];
			m_buffer[m_len++]=lut[v&0xf];
			return;
		}
		m_buffer[m_len++]=lut[v&0xf];
	}

};

extern Output g_output;
}
#endif

