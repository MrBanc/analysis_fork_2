RUN wget https://nginx.org/download/nginx-1.20.2.tar.gz
RUN tar -xzvf nginx-1.20.2.tar.gz

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


RUN apt install apt install autoconf python-dev
RUN wget https://github.com/GNOME/libxml2/archive/refs/tags/v2.9.12.zip
RUN unzip v2.9.12.zip
WORKDIR 
RUN autoreconf -f -i
RUN ./configure
RUN make CFLAGS="-fdump-rtl-expand"
RUN make install


RUN wget https://github.com/GNOME/libxslt/archive/refs/tags/v1.1.34.zip
RUN unzip v1.1.34.zip
WORKDIR 
RUN autoreconf -f -i
RUN ./configure
RUN make CFLAGS="-fdump-rtl-expand"
RUN make install


RUN wget https://github.com/libgd/libgd/releases/download/gd-2.3.3/libgd-2.3.3.tar.gz
RUN tar -xzvf libgd-2.3.3.tar.gz
WORKDIR 
RUN ./configure
RUN make CFLAGS="-fdump-rtl-expand"
RUN make install


RUN wget https://github.com/maxmind/geoip-api-c/archive/refs/tags/v1.6.12.zip
RUN unzip v1.6.12.zip
WORKDIR 
RUN autoreconf -f -i
RUN ./configure
RUN make CFLAGS="-fdump-rtl-expand"
RUN make install

RUN ./configure --with-zlib="/home/gain/apps_to_test/nginx-1.20.2/zlib-1.2.12/" --with-pcre="/home/gain/apps_to_test/nginx-1.20.2/pcre2-10.39/" --with-openssl="/home/gain/apps_to_test/nginx-1.20.2/openssl-1.1.1o/" --with-http_ssl_module --with-http_realip_module --with-http_addition_module --with-http_xslt_module --with-http_image_filter_module --with-http_geoip_module --with-http_sub_module --with-http_dav_module --with-http_flv_module --with-http_mp4_module --with-http_gzip_static_module --with-http_gunzip_module --with-http_random_index_module --with-http_secure_link_module --with-http_stub_status_module --with-cc-opt="-fdump-tree-gimple" --with-http_auth_request_module --with-http_v2_module --with-cc-opt="-static -static-libgcc"