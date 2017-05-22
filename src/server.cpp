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

#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <netinet/in.h>
#include <netdb.h>
#include <getopt.h>
#include <time.h>
#include <fcntl.h>
#include <poll.h>
#include <dirent.h>
#include <map>
#include <list>
#include <string>
#include "packetq.h"
#include "pcap.h"
#include "reader.h"

#define MAXHOSTNAME 256
namespace se {
namespace httpd
{
class Socket;
class Server;

static char redirect[]="HTTP/1.1 307 Temporary Redirect\r\n"
    "Location: /\r\n"
    "Connection: close\r\n"
    "Content-Type: text/html\r\n"
    "\r\n<html><head><title>moved</title></head><body><h1>moved</h1>this page has moved to /</body></html>";

static char header[]="HTTP/1.1 200 OK\r\n"
    "Server: PacketQ builtin\r\n"
    "Connection: close\r\n"
    "Access-Control-Allow-Origin: *\r\n"
    "Content-Type: %s\r\n"
    "\r\n";

Server *g_server=0;

class SocketPool
{
    public:
        SocketPool()
        {
            m_free =0;
            for (int i=0; i<FD_SETSIZE; i++)
                m_sockets[i]=0;
            m_socket_count = 0;
        }
        int add( Socket *s )
        {
            if (m_free<FD_SETSIZE)
                m_sockets[m_free]=s;
            else
                return -1;
            int idx = m_free;
            while ( m_free < FD_SETSIZE && m_sockets[m_free] )
                m_free++;
            m_socket_count++;
            return idx;
        }
        void remove( int s )
        {
            m_sockets[s]=0;
            if (s<m_free)
                m_free=s;
            m_socket_count--;
        }

        int get_sockets() { return m_socket_count; }
        void select();


        fd_set      m_readset;
        fd_set      m_writeset;
        int         m_free;
        int         m_socket_count;
        Socket      *m_sockets[FD_SETSIZE];
};

SocketPool g_pool;

class Stream
{
    public:
        class Buffer
        {
            public:
                Buffer(const unsigned char * buf,int len)
                {
                    m_buf = new unsigned char[len];
                    memcpy(m_buf,buf,len);
                    m_len = len;
                    m_pos = 0;
                }
                Buffer(const Buffer &buf)
                {
                    m_len=buf.m_len;
                    m_buf = new unsigned char[buf.m_len];
                    memcpy(m_buf,buf.m_buf,m_len);
                    m_pos = 0;
                }
                ~Buffer()
                {
                    m_len = 0;
                    delete []m_buf;
                }
                unsigned char *m_buf;
                int m_len;
                int m_pos;
        };
        Stream()
        {
            m_len=0;
        }
        void push_front(unsigned char *data,int len)
        {
            m_stream.push_front(Buffer(data,len));
            m_len+=len;
        }
        void write(unsigned char *data,int len)
        {
            m_stream.push_back(Buffer(data,len));
            m_len+=len;
        }
        int read(unsigned char *data,int maxlen)
        {
            int p=0;
            while(p<maxlen && m_len>0)
            {
                Buffer &buf = m_stream.front();
                int l = maxlen-p;
                if (l > buf.m_len - buf.m_pos)
                    l = buf.m_len - buf.m_pos;
                for (int i=0;i<l;i++)
                    data[p++] = buf.m_buf[buf.m_pos++];
                m_len -= l;
                if ( l==0 )
                {
                    m_stream.pop_front();
                }
            }
            return p;
        }
        int len()
        {
            return m_len;
        }
        int get()
        {
            unsigned char c='@';
            int r = read(&c,1);
            if (r==0)
                return -1;
            return c;
        }

    private:
        int m_len;
        std::list<Stream::Buffer> m_stream;
};

class Socket
{
    public:
        Socket( int s, bool serv ) : m_want_write(false)
        {
            fcntl( s, F_SETFL, fcntl( s, F_GETFL, 0 ) | O_NONBLOCK );   // Add non-blocking flag

            m_bytes_written     = 0;
            m_bytes_read        = 0;
            m_serv              = serv;
            m_socket            = s;
            m_sidx              = g_pool.add( this );
            m_close_when_empty  = false;
            m_file              = 0;
        }
        virtual ~Socket()
        {
            g_pool.remove( m_sidx );
            close( m_socket );
        }
        void process( bool read )
        {
            //m_serv means this is a listening socket
            if ( m_serv )
                return;
            if ( !read )
            {
                on_write();
                unsigned char ptr[4096];
                int len;

                while( len = m_write.read( ptr, sizeof(ptr)))
                {
                    int res = write( m_socket, ptr, len );
                    if (res == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
                    {
                        m_write.push_front( ptr, len);
                        set_want_write();
                        return;
                    }
                    if (res < 0)
                    {
                        delete this;
                        return;
                    }
                    m_bytes_written+=res;
                    if (res < len)
                    {
                        m_write.push_front( &ptr[res], len-res);
                        set_want_write();
                        return;
                    }
                }
                if (m_close_when_empty)
                {
                    shutdown( m_socket, SHUT_WR );
//                    fflush(m_socket);
                    delete this;
                }
            }
            if (read)
            {
                int avail = read_sock();

                if ( avail )
                    on_read();
            }

        }
        virtual void file_write()
        {
        }
        virtual void file_read()
        {
        }
        void set_delete()
        {
            m_close_when_empty = true;
            m_want_write = false;
        }
        virtual void on_write()
        {
        }
        virtual void on_read()
        {
        }
        int read_sock()
        {
            unsigned char buf[2000];
            int len=0;
            if ((len= recv(m_socket,buf,sizeof(buf)-1,0))>0)
            {
                m_bytes_read += len;
                buf[len]=0;
                m_read.write(buf,len);
            }
            if (len<0)
            {
                delete this;
                return 0;
            }
            return len;
        }
        bool failed()
        {
            return m_sidx==-1;
        }
        bool has_data()
        {
            return m_want_write||m_write.len()>0;
        }
        void set_want_write(bool set=true)
        {
            m_want_write = set;
        }

        int m_bytes_written;
        int m_bytes_read;
        int m_socket;
        int m_file;
        int m_sidx;
        bool m_serv;
        bool m_want_write;
        bool m_close_when_empty;
        char m_buffer[4096];

        Stream m_read,m_write;
};

void SocketPool::select()
{
    FD_ZERO(&m_readset);
    FD_ZERO(&m_writeset);
    int max=0;
    for (int i=0;i<FD_SETSIZE;i++)
    {
        if (m_sockets[i])
        {
            if (max<m_sockets[i]->m_socket)
                max=m_sockets[i]->m_socket;
            FD_SET(m_sockets[i]->m_socket,&m_readset);
            if ( m_sockets[i]->has_data() )
                FD_SET(m_sockets[i]->m_socket,&m_writeset);
            if (max<m_sockets[i]->m_file)
                max=m_sockets[i]->m_file;
            FD_SET(m_sockets[i]->m_file,&m_readset);
        }
    }
    timeval timeout;
    timeout.tv_sec = 30;
    timeout.tv_usec = 0;

    int sel= ::select(max+1,&m_readset,&m_writeset,0,&timeout);
    if (sel<0)
    {
        syslog (LOG_ERR|LOG_USER, "sel -1 errno = %d %s max:%d", errno, strerror(errno), max );
        exit(-1);
    }
    if (sel)
    {
        for (int i = 0; i < FD_SETSIZE; i++)
        {
            if ( m_sockets[i] && m_sockets[i]->m_file )
            {
                if ( FD_ISSET(m_sockets[i]->m_file, &m_readset) )
                {
                    m_sockets[i]->file_read();
                }
                if ( m_sockets[i] && FD_ISSET(m_sockets[i]->m_file, &m_writeset) )
                {
                    m_sockets[i]->file_write();
                }
            }
            if( m_sockets[i] && FD_ISSET(m_sockets[i]->m_socket, &m_readset) )
            {
                m_sockets[i]->process(true);
            }
            if( m_sockets[i] && FD_ISSET(m_sockets[i]->m_socket, &m_writeset) )
            {
                m_sockets[i]->process(false);
            }
        }
    }
}


class Server
{
    public:
        Socket m_socket;

        Server(int port, const std::string &pcaproot, const std::string &webroot ) :m_socket( establish(port), true )
                                                                                   ,m_pcaproot (pcaproot), m_webroot( webroot )
        {
            if (m_socket.m_socket<0)
            {
                if (m_socket.m_socket==EADDRINUSE)
                    syslog (LOG_ERR|LOG_USER, "Fail EADDRINUSE (%d)\n",m_socket.m_socket);
                else
                    syslog (LOG_ERR|LOG_USER, "Fail %d port:%d\n",m_socket.m_socket,port);
                exit(-1);
            }
        }

        ~Server()
        {
        }


        int get_connection()
        {
            int s=m_socket.m_socket;
            int t; /* socket of connection */
            if ((t = accept(s,NULL,NULL)) < 0) /* accept connection if there is one */
                return(-1);

            return(t);
        }


        int establish(unsigned short portnum)
        {
            int s,res;
            sockaddr_in sa;
            memset(&sa, 0, sizeof(struct sockaddr_in));

            sa.sin_family = AF_INET;
            sa.sin_addr.s_addr = htonl( INADDR_ANY );

            sa.sin_port= htons(portnum);

            if ((s= socket(AF_INET, SOCK_STREAM, 0)) < 0)
                return(-2);
            int on = 1;

            res = setsockopt( s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on) );

            if ((res=bind(s,(const sockaddr *)&sa,sizeof(struct sockaddr_in))) < 0)
            {
                close(s);
                return(res); /* bind address to socket */
            }
            int x=fcntl(s,F_GETFL,0);              // Get socket flags
            fcntl(s,F_SETFL,x | O_NONBLOCK);   // Add non-blocking flag

            listen(s, 511); /* max # of queued connects */
            return(s);
        }


        std::string m_pcaproot;
        std::string m_webroot;

};

class Url
{
    public:
    Url(const char *url) :m_full(url)
    {
        int i=0;
        for (;i<m_full.length();i++)
        {
            char c = m_full.c_str()[i];
            if (c=='?')
            {
                i++;
                break;
            }
            m_path+=c;
        }
        m_path=decode(m_path);
        if (m_path=="")
            m_path="/";
        decode_params(m_full.substr(i).c_str());
    }
    void decode_params(const char * params)
    {
        if (!params)
            return;
        std::string str = params;
        for (int i=0;i<str.length();)
        {
            std::string param="",value="";
            for (;i<str.length();i++)
            {
                char c = str.c_str()[i];
                if (c=='=' || c=='&')
                {
                    i++;
                    break;
                }
                param+=c;
            }
            for (;i<str.length();i++)
            {
                char c = str.c_str()[i];
                if (c=='&')
                {
                    i++;
                    break;
                }
                value+=c;
            }
            add_param(decode(param), decode(value));
        }
    }
    const char *get_param(const char * param)
    {
        std::map<std::string,std::string>::iterator it = m_params.find(std::string(param));
        if (it == m_params.end())
            return 0;
        return it->second.c_str();
    }
    void add_param(std::string key, std::string val)
    {
        std::map<std::string,std::string>::iterator it = m_params.find(key);
        if (it == m_params.end())
        {
            m_params[key] = val;
            m_counts[key] = 1;
            return;
        }
        char cnt[100];
        int n = m_counts[key];
        m_counts[key] = n+1;

        snprintf(cnt, sizeof(cnt) - 1, "%d", n);
        cnt[99] = 0;
        std::string keyn=key;
        keyn+=cnt;
        m_params[keyn] = val;
    }

    std::string decode(std::string str)
    {
        std::string dst;
        int percent_state=0;
        int code = 0;
        for (int i=0;i<str.length();i++)
        {
            char c = str.c_str()[i];
            if (percent_state)
            {
                int n=0;
                if (c>='0' && c<='9')
                    n=c-'0';
                if (c>='a' && c<='f')
                    n=c-'a'+10;
                if (c>='A' && c<='F')
                    n=c-'A'+10;
                code=(code<<4)|n;
                percent_state--;
                if (!percent_state)
                {
                    dst  += char(code);
                    code =  0;
                }
            }
            else
            {
                if (c=='%')
                {
                    percent_state=2;
                }
                else
                    dst+=c;
            }
        }
        return dst;
    }

    std::string get_full()
    {
        return m_full;
    }
    std::string get_path()
    {
       return m_path;
    }

    std::string m_full;
    std::string m_path;
    std::map<std::string,std::string> m_params;
    std::map<std::string,int> m_counts;
};

class Page
{
    public:
    Page(const char *url, const char *body) : m_url(url)
    {
        m_url.decode_params(body);
    }

    void process()
    {

        if (m_url.get_path().compare("/query")==0)
        {
            if (!m_url.get_param("file"))
            {
                printf(header,"text/plain");
                printf("no file selected\n");
                return ;
            }

            printf(header,"text/plain");
            if (m_url.get_param("sql"))
                query(m_url.get_param("sql"));
            else
                printf("no query defined \n");
        }
        else if (m_url.get_path().substr(0,8).compare("/resolve")==0)
        {
            resolve();
        }
        else if (m_url.get_path().substr(0,5).compare("/list")==0)
        {
            serve_dir();
        }
        else
        {
            serve_static();
        }


        delete g_app;
    }
    static std::string join_path(const std::string &a,const std::string &b)
    {
        if ( b.find("..") != std::string::npos )
            return a;
        if ( a.length()==0 )
            return b;
        if ( b.length()==0 )
            return a;
        if ( a[a.length()-1]!='/' && b[0]!='/')
            return a+std::string("/")+b;
        return a+b;
    }
    const char *get_mimetype(const std::string &file)
    {
        int p = file.find_last_of('.');
        if (p==std::string::npos || p+1>=file.length() )
            return 0;
        std::string suff=file.substr(p+1);
        if (suff.compare("js")   ==0)  return "application/x-javascript";
        if (suff.compare("jpg")  ==0)  return "image/jpeg";
        if (suff.compare("html") ==0)  return "text/html";
        if (suff.compare("htm")  ==0)  return "text/html";
        if (suff.compare("txt")  ==0)  return "text/plain";
        if (suff.compare("png")  ==0)  return "image/png";
        if (suff.compare("gif")  ==0)  return "image/gif";
        if (suff.compare("ico")  ==0)  return "image/x-icon";
        if (suff.compare("json") ==0)  return "application/json";
        if (suff.compare("css")  ==0)  return "text/css";

        return 0;
    }
    bool serve_file(const std::string &file)
    {
        const char *mimetype = get_mimetype(file);

        if (mimetype)
        {
            FILE *fp = fopen(file.c_str(),"rb");
            if (fp)
            {
                printf( header, mimetype );
                char buffer[8192];
                int len;
                while( (len = fread(buffer,1,200,fp)) >0 )
                {
                    fwrite(buffer,1,len,stdout);
                }
                fclose(fp);
                return true;
            }
        }
        return false;
    }
    void serve_static()
    {
        if (g_server->m_webroot=="")
        {
            printf(header,"text/html");
            printf("<h2>This server is not configured to serve static pages</h2>");
            printf("Start using the -w option to set a html directory");
            return;
        }
        std::string file=join_path(g_server->m_webroot,m_url.get_path());

        if (serve_file(file))
            return;
        if (serve_file(join_path(file,"index.html")))
            return;

        if(m_url.get_path().compare("/")!=0)
        {
              printf("%s",redirect);
              return;
        }

        printf(header,"text/html");
        printf("<h2>It works !</h2><br>\n");
        printf("%s","<a href=\"/query?file=sample.pcap&sql=select%20qr,qname,protocol%20from%20dns%20limit%2018;\">Test query</a><br/>\n" );
        printf("%s","<a href=\"/list\">list available files</a><br/>\n" );
    }

    void resolve()
    {
        const char *ip   = m_url.get_param("ip");
        const char *name = m_url.get_param("name");

        if (ip)
        {

            printf(header,"application/json");

            printf("[");

            struct addrinfo *result;
            struct addrinfo *res;
            int error;

            error = getaddrinfo(ip, NULL, NULL, &result);
            if (error == 0)
            {
                for (res = result; res != NULL; res = res->ai_next)
                {
                    char hostname[NI_MAXHOST] = "";

                    error = getnameinfo(res->ai_addr, res->ai_addrlen, hostname, NI_MAXHOST, NULL, 0, 0);
                    if (error != 0)
                    {
                        continue;
                    }
                    if (*hostname != '\0')
                    {
                        printf("\"%s\"", hostname);
                        break;
                    }
                }
                freeaddrinfo(result);
            }
            printf("]\n");
        }
        else if (name)
        {
            char tmp[100];
            printf(header,"application/json");

            printf("[");

            struct addrinfo *result;
            struct addrinfo *res;
            int error;

            error = getaddrinfo(name, NULL, NULL, &result);
            char empty[]="",line[]=",\n";
            char *sep=empty;
            if (error == 0)
            {
                for (res = result; res != NULL; res = res->ai_next)
                {
                    void *ptr = &( (struct sockaddr_in *) res->ai_addr)->sin_addr;
                    if (res->ai_family==AF_INET6)
                            ptr = &( (struct sockaddr_in6 *) res->ai_addr)->sin6_addr;
                    tmp[0]=0;
                    inet_ntop(res->ai_family, ptr, tmp, sizeof( tmp ) );
                    printf("%s\"%s\"", sep, tmp);
                    sep=line;
                }
                freeaddrinfo(result);
            }
            printf("]\n");
        }
        else
            printf("[]\n");
    }

    void serve_dir()
    {
        if (g_server->m_pcaproot=="")
        {
            printf(header,"text/html");
            printf("<h2>This server is not configured to list pcapfiles</h2>");
            printf("Start using the -r option to set a pcap directory");
            return;
        }
        std::string directory=join_path(g_server->m_pcaproot,m_url.get_path().substr(5));

        DIR *dir = opendir(directory.c_str());
        if (!dir)
        {
            printf("%s",redirect);
            return;
        }

        printf(header,"application/json");

        printf("[\n");
        struct dirent *d;
        struct stat   statbuf;

        char comma=' ';

        while ( (d=readdir(dir))!=0 )
        {
            std::string subject=join_path(directory,d->d_name);

            if (stat( subject.c_str(), &statbuf) ==-1)
                continue;
            if (S_ISDIR(statbuf.st_mode))
            {
                if ( (strcmp(d->d_name,".")!=0) && (strcmp(d->d_name,"..")!=0 ) )
                {
                    printf("  %c{\n     \"data\" : \"%s\",\n     \"attr\" : { \"id\": \"%s\" },\n   \"children\" : [], \"state\" : \"closed\"  }\n",
                            comma, d->d_name, join_path(m_url.get_path(),d->d_name).substr(5).c_str() );
                    comma=',';
                }
            }
            else
            {
                bool found = false;
                std::string str = subject;
                transform(str.begin(), str.end(),str.begin(), tolower );
                FILE *fp = fopen(subject.c_str(),"rb");
                if (fp)
                {
                    Pcap_file pfile(fp);
                    if (pfile.get_header())
                    {
		                unsigned char * data=0;
                        int s=0,us,len;
                        data = pfile.get_packet(len, s, us);
                        if (data)
                        {
                            printf("  %c{\n     \"data\" : \"%s\",\n     \"attr\" : { \"id\" : \"%s\", \"size\": %d, \"time\": %d,\"type\": \"pcap\" },\n    \"children\" : []  }\n",
                                    comma,d->d_name,join_path(m_url.get_path(),d->d_name).substr(5).c_str(), int(statbuf.st_size),s );
                            comma = ',';
                            found = true;
                        }
                    }
                    fclose(fp);
                }
                if (!found)
                {
                    std::string str = subject;
                    transform(str.begin(), str.end(),str.begin(), tolower );
                    if ( str.rfind(".json") == str.length()-5 )
                    {
                        printf("  %c{\n     \"data\" : \"%s\",\n     \"attr\" : { \"id\" : \"%s\", \"size\": %d, \"type\": \"json\" },\n    \"children\" : []  }\n",
                                comma,d->d_name,join_path(m_url.get_path(),d->d_name).substr(5).c_str(), int(statbuf.st_size) );
                        comma=  ',';
                        found = true;
                    }
                }
            }
        }

        printf("]\n");

        closedir(dir);
    }

    void query(const char *sql)
    {
        Query query("result", sql);

        query.parse();

        std::vector<std::string> in_files;

        int i=0;
        while(true)
        {
            char param[50]="file";

            std::string par = "file";
            if (i>0) {
                snprintf(param, sizeof(param) - 1, "file%d", i);
                param[49] = 0;
            }
            i++;
            const char *f = m_url.get_param(param);
            if (!f)
                break;
            std::string file = join_path(g_server->m_pcaproot, f);
            in_files.push_back(file);

        }

        Reader reader(in_files, g_app->get_limit());

        query.execute(reader);
        if (query.m_result)
            query.m_result->json(false);
    }
    Url m_url;
};



class Http_socket : public Socket
{
    public:
        enum State
        {
            get_post,header,body,error,wait_child,done
        };
        Http_socket( int socket ) : Socket( socket, false ), m_http_version(0), m_emptyline(0)
        {
            m_state      = get_post;
            m_nextc      = -1;
            m_cr         = false;
            m_line       = "";
            m_url        = "";
            m_child_fd   = 0 ;
            m_child_pid  = 0 ;
            m_child_read = 0 ;
            m_body_cnt   = -1 ;
            m_content_len= 0 ;
        }
        ~Http_socket()
        {
            if (m_child_pid)
            {
                kill(m_child_pid,SIGHUP);
                int status;
                waitpid(m_child_pid, &status, 0 );
            }
            if(m_child_fd)
                close(m_child_fd);
            m_file = 0;
        }
        inline void print(const char *fmt,...)
        {
            char string[4096];
            va_list ap;

            va_start(ap,fmt);
            vsnprintf(string,sizeof(string),fmt,ap);
            va_end(ap);

            m_write.write((unsigned char *)string,strlen(string));
        }

        int peek()
        {
            if (m_nextc>=0)
                return m_nextc;
            m_nextc = m_read.get();
            return m_nextc;
        }
        int getc()
        {
            int c = peek();
            m_nextc = -1;
            return c;
        }

        void on_read()
        {
            while(true)
            {
                int c = peek();
                if (c==-1)
                    return;
                if (m_body_cnt>=0)
                {
                    c = getc();
                    if( !(m_body_cnt==0 && c==10) )
                    {
                        m_line+=char(c);
                        m_content_len--;
                    }
                    m_body_cnt++;
                    if (m_content_len==0)
                        parseline();
                    continue;
                }
                c = getc();
                if (c!=13 && c!=10)
                {
                    m_line+=char(c);
                    m_cr = false;
                }
                else
                {
                    bool cr = m_cr;
                    m_cr = false;
                    if (c==10 && cr)
                    {
                        continue;
                    }
                    if (c==13)
                        m_cr = true;
                    parseline();
                }
            }
        }
        virtual void file_read()
        {
            set_want_write();
        }
        virtual void file_write()
        {
        }
        void on_write()
        {
            set_want_write(false);
            if (m_state==wait_child)
            {
                unsigned char buffer[4096];
                int status;
                bool done  = true;
                if(0==waitpid(m_child_pid, &status, WNOHANG ))
                {
                    done = false;
                }
                if (m_child_fd)
                {
                    size_t res;
                    fcntl( m_child_fd, F_SETFD, fcntl( m_child_fd, F_GETFD, O_NONBLOCK ) | O_NONBLOCK );
                    pollfd pfd;
                    pfd.fd = m_child_fd;
                    pfd.events  = POLLIN;
                    pfd.revents = 0;
                    if ( 1==poll(&pfd,1,0) && ( pfd.revents&POLLIN!=0 ) )
                    {
                        if((res = read( m_child_fd, buffer,(int)sizeof(buffer) )) >0 )
                        {
                            done = false;
                            m_child_read+=res;
                            m_write.write( buffer, res );
                        }
                    }
                }
                if (done)
                {
                    m_child_pid =0 ;
                    if (m_child_fd)
                    {
                        close(m_child_fd);
                        m_child_fd = 0;
                        m_file     = 0;
                    }
                    set_delete();
                }
                else
                {
                }
            }
        }
        void parseline()
        {
            switch(m_state)
            {
                case(get_post):
                    {
                        m_state = error;
                        syslog (LOG_INFO|LOG_USER,"%s\n",m_line.c_str());
                        int p=0;
                        if (m_line.find("GET ")!=-1)
                        {
                            if ( (p=m_line.find(" HTTP/1.1"))!=-1)
                            {
                                m_http_version = 1;
                            }
                            else if ( (p=m_line.find(" HTTP/1.0"))!=-1)
                            {
                                m_http_version = 0;
                            }
                            else
                            {
                                return;
                            }
                            m_url=m_line.substr(4,p-4);
                            m_state=header;
                        }
                        else if (m_line.find("POST ")!=-1)
                        {
                            if ( (p=m_line.find(" HTTP/1.1"))!=-1)
                            {
                                m_http_version = 1;
                            }
                            else if ( (p=m_line.find(" HTTP/1.0"))!=-1)
                            {
                                m_http_version = 0;
                            }
                            else
                            {
                                return;
                            }
                            m_url=m_line.substr(5,p-5);
                            m_state=header;
                        }
                    }
                    break;
                case(header):
                    if (m_line.length()==0)
                    {
                        m_body_cnt=0;
                        m_state=body;
                    }
                    else
                    {
                        int colon = m_line.find(": ");
                        std::string key = m_line.substr(0,colon);
                        std::string val = m_line.substr(colon+2);
                        if (key=="Content-Length")
                        {
                            if (val.length()>0)
                                m_content_len=atoi(val.c_str());
                        }
                    }
                    break;
                case(body):
                        m_body = m_line;
                        header_done();
                    break;
                default:
                    printf("error line: %s !\n",m_line.c_str());
                    break;
            }
            m_line="";
        }
        void header_done()
        {
            fflush(stdout); // required before fork or any unflushed output will go to the client
            int fd[2];
            if(pipe(fd)<0)
                return;
            fcntl( fd[0], F_SETFD, fcntl( fd[0], F_GETFD, O_NONBLOCK ) | O_NONBLOCK );

            m_child_pid=fork();
            if (m_child_pid<0)
            {
                print("Internal error");
                set_delete();
                return;
            }
            if (m_child_pid==0)
            {
                //////////      child code /////////
                dup2(fd[1], fileno(stdout));
                dup2(fd[1], fileno(stderr));
                close(fd[1]);

                Page page(m_url.c_str(),m_body.c_str());
                page.process();
                fflush(stdout);
                exit(0);
                ///////////// child exit() ///////////////
            }
            else
            {
                close(fd[1]);
                m_child_fd = fd[0];
                m_file     = m_child_fd;
                m_state    = wait_child;
            }
            set_want_write();
        }
        State       m_state;
        bool        m_cr;
        int         m_body_cnt;
        int         m_content_len;
        int         m_nextc;
        int         m_child_pid;
        int         m_child_fd;

        int         m_child_read;

        int         m_http_version; // 0 = HTTP/1.0 1 = HTTP/1.1

        int         m_emptyline;
        std::string m_line;
        std::string m_url;
        std::string m_body;
};

}; // end namespace

using namespace httpd;

void start_server(int port,bool fork_me, const std::string &pcaproot, const std::string &webroot, int max_conn )
{
    pid_t   pid, sid;
    bool fg = !fork_me;

    printf("listening on port %d\n",port);

    if (!fg)
    {
        pid = fork();

        if (pid < 0) {
            exit(EXIT_FAILURE);
        } else if (pid > 0) {
            exit(EXIT_SUCCESS);
        }

        sid = setsid();

        if (sid < 0) {
            exit(EXIT_FAILURE);
        }

    }
    openlog("packetq",LOG_PID,LOG_USER);

    httpd::Server server(port,pcaproot,webroot);
    g_server = &server;

    while(true)
    {
        httpd::g_pool.select();
        int cnt = g_pool.get_sockets();
        if ( cnt<max_conn )
        {
            int c=server.get_connection();
            if (c>-1)
            {
                Http_socket *s=new Http_socket(c);
                if ( s && s->failed() )
                {
                    syslog (LOG_ERR|LOG_USER, "failed to create socket");
                    delete s;
                }
            }
        }
        usleep(1000);
    }
    g_server = 0;
    syslog (LOG_INFO|LOG_USER, "exiting");
    exit(EXIT_SUCCESS);

}

}
