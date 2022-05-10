FROM base_common:latest as weborf

ENV APP_NAME weborf

ADD src $HOME/root/
WORKDIR /root/

RUN wget https://github.com/ltworf/weborf/archive/refs/tags/0.17.zip
RUN unzip 0.17.zip

WORKDIR /root/weborf-0.17
RUN apt install autoconf
RUN autoreconf -f -i

RUN ./configure CFLAGS="-fdump-rtl-expand -static"

RUN make CFLAGS="-static -fdump-rtl-expand" EXEEXT="-static"
RUN mkdir -p expand_weborf
RUN find . -name \*.expand -exec cp {} expand_weborf \;