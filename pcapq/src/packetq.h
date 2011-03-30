/*! \file */ 
/*
 * Copyright (c) 2011 .SE (The Internet Infrastructure Foundation).
 *                  All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * ##################################################################### 
 *
 */
#ifndef TRACEDNS_H
#define TRACEDNS_H

#include "sql.h"

namespace se {

// App class
class Pcapq 
{
    public:
        Pcapq()
        {
            m_sample_counter = 0;
            m_limit          = 0;
        }
        ~Pcapq()
        {
        }
        bool sample()
        {
            bool res = m_sample_counter++==0;
            if (m_sample_counter>=m_query.get_sample())
                m_sample_counter=0;
            return res;
        }
        void set_limit(int limit)
        {
            m_limit = limit;
        }
        int get_limit() { return m_limit;} 
        Query   m_query;
    private:
        int     m_sample_counter;
        int     m_limit;
};

void read_file(const char *filename);

extern Pcapq *g_app;
}
#endif
