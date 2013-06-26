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
#ifndef PACKETQ_H
#define PACKETQ_H

#include "sql.h"

namespace se {

// App class
class PacketQ 
{
    public:
        enum OutputOpts
        {
            json,
            csv,
            csv_format,
            xml 
        };
        PacketQ()
        {
            m_limit          = 0;
            m_output         = json;
        }
        void set_limit(int limit)
        {
            m_limit = limit;
        }
        void set_output(OutputOpts opt)
        {
            m_output = opt;
        }
        OutputOpts get_output() { return m_output; }
        int get_limit()         { return m_limit;  }

    private:
        int         m_limit;
        OutputOpts  m_output;
};

extern PacketQ *g_app;
}
#endif
