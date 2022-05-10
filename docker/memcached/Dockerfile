FROM base_common:latest as memcached

ENV APP_NAME memcached

WORKDIR /root/

# Download memcached
RUN wget http://www.memcached.org/files/memcached-1.6.12.tar.gz
RUN tar -xzf memcached-1.6.12.tar.gz
WORKDIR /root/memcached-1.6.12/

# Download and build libevent
RUN wget https://github.com/libevent/libevent/releases/download/release-2.1.10-stable/libevent-2.1.10-stable.tar.gz
RUN tar -xzf libevent-2.1.10-stable.tar.gz
WORKDIR /root/memcached-1.6.12/libevent-2.1.10-stable/
RUN ./configure CFLAGS="-fdump-rtl-expand"
RUN make CFLAGS="-fdump-rtl-expand"
RUN rm -rf test/ sample/
RUN make install

# Build memcached
WORKDIR /root/memcached-1.6.12/
RUN ./configure CFLAGS="-fdump-rtl-expand -static -lpthread" --with-libevent="$PWD/libevent-2.1.10-stable/"
RUN make 
RUN mkdir -p expand_memcached

RUN find . -name \*.expand -exec cp {} expand_memcached/ \;