FROM base_common:latest as sqlite

ENV APP_NAME sqlite

WORKDIR /root/

# Download sqlite
RUN wget https://github.com/sqlite/sqlite/archive/refs/tags/version-3.38.0.zip
RUN unzip version-3.38.0.zip
WORKDIR /root/sqlite-version-3.38.0/

# Download and build zlib
RUN wget https://github.com/madler/zlib/archive/refs/tags/v1.2.12.zip
RUN unzip v1.2.12.zip
WORKDIR /root/sqlite-version-3.38.0/zlib-1.2.12/
RUN ./configure
RUN make CFLAGS="-fdump-rtl-expand"
RUN make install

# Build SQlite
WORKDIR /root/sqlite-version-3.38.0/
RUN ./configure --disable-load-extension CFLAGS="-fdump-rtl-expand -static" 
RUN make CFLAGS="-static -fdump-rtl-expand" EXEEXT="-static"

RUN mkdir -p expand_sqlite
RUN find . -name \*.expand -exec cp {} expand_sqlite \;
RUN rm expand_sqlite/example.c.229r.expand

# Build amalgation as static

RUN wget https://www.sqlite.org/2022/sqlite-amalgamation-3380500.zip
RUN unzip sqlite-amalgamation-3380500.zip
WORKDIR /root/sqlite-amalgamation-3380500/
RUN gcc shell.c sqlite3.c -lpthread -DSQLITE_OMIT_LOAD_EXTENSION  -lm -o sqlite3 --static
