

RUN wget https://download.lighttpd.net/lighttpd/releases-1.4.x/lighttpd-1.4.64.tar.gz
RUN wget tar -xzvf lighttpd-1.4.64.tar.gz 


# Download and build pcre
WORKDIR /root/lighttpd-1.4.64/
RUN wget https://github.com/PCRE2Project/pcre2/releases/download/pcre2-10.39/pcre2-10.39.zip
RUN unzip pcre2-10.39.zip
WORKDIR pcre2-10.39/
RUN ./configure
RUN make CFLAGS="-fdump-rtl-expand"
RUN make install

# Download and build zlib
WORKDIR /root/lighttpd-1.4.64
RUN wget https://github.com/madler/zlib/archive/refs/tags/v1.2.12.zip
RUN unzip v1.2.12.zip
WORKDIR zlib-1.2.12/
RUN ./configure
RUN make CFLAGS="-fdump-rtl-expand"
RUN make install

# Download and build openssl
WORKDIR /root/lighttpd-1.4.64
RUN wget https://www.openssl.org/source/openssl-1.1.1o.tar.gz
RUN tar -xzvf openssl-1.1.1o.tar.gz
WORKDIR openssl-1.1.1o/ 
RUN ./Configure linux-x86_64
RUN make CFLAGS="-fdump-rtl-expand" 
RUN make install

WORKDIR /root/lighttpd-1.4.64/
RUN ./configure
RUN make CFLAGS="-fdump-rtl-expand"
RUN make clean

RUN mkdir -p expand_lighttpd
RUN find . -name \*.expand -exec cp {} expand_lighttpd/ --backup=numbered \;
RUN rm expand_lighttpd/test_* expand_lighttpd/example*

RUN apt install scons -y
RUN mkdir install_bin

RUN scons build_static=1 build_dynamic=0 prefix=install_bin/ CFLAGS="--static"