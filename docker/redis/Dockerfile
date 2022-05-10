FROM base_common:latest as redis-server

ENV APP_NAME redis-server

ADD src $HOME/root/
WORKDIR /root/

RUN make CFLAGS="-static -fdump-rtl-expand" EXEEXT="-static"
RUN mkdir -p expand_redis
RUN find . -name \*.expand -exec cp {} expand_redis \;