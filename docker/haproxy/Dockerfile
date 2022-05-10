FROM base_common:0.1 as haproxy

ENV APP_NAME haproxy

WORKDIR /root/

# Download haproxy
RUN wget https://github.com/haproxy/haproxy/archive/refs/tags/v2.5.0.zip
RUN unzip v2.5.0.zip

# Download and build zlib
WORKDIR /root/haproxy-2.5.0/
RUN wget https://github.com/madler/zlib/archive/refs/tags/v1.2.12.zip
RUN unzip v1.2.12.zip
WORKDIR /root/haproxy-2.5.0/zlib-1.2.12/
RUN ./configure --static
RUN make CFLAGS="-fdump-rtl-expand"
RUN make install

# Download and build liblua
WORKDIR /root/haproxy-2.5.0/
RUN curl -R -O http://www.lua.org/ftp/lua-5.4.4.tar.gz
RUN tar -xzvf lua-5.4.4.tar.gz
WORKDIR /root/haproxy-2.5.0/lua-5.4.4/
RUN make CFLAGS="-fdump-rtl-expand"
RUN make install

# Download and build pcre
WORKDIR /root/haproxy-2.5.0/
RUN wget https://github.com/PCRE2Project/pcre2/releases/download/pcre2-10.39/pcre2-10.39.zip
RUN unzip pcre2-10.39.zip
WORKDIR /root/haproxy-2.5.0/pcre2-10.39/
RUN ./configure
RUN make CFLAGS="-fdump-rtl-expand"
RUN make install

# Download and build openssl
WORKDIR /root/haproxy-2.5.0/
RUN wget https://www.openssl.org/source/openssl-1.1.1o.tar.gz
RUN tar -xzvf openssl-1.1.1o.tar.gz
WORKDIR /root/haproxy-2.5.0/pcre2-10.39/openssl-1.1.1o/
RUN ./Configure linux-x86_64
RUN make CFLAGS="-fdump-rtl-expand" 
RUN make install

# Build the 
WORKDIR /root/haproxy-2.5.0/
RUN make TARGET=linux-glibc USE_OPENSSL=1 USE_PCRE=1 USE_LUA=1 USE_SYSTEMD=0  CFLAGS="-fdump-rtl-expand" LDFLAGS=-static