FROM ubuntu:21.04 as base_common

# Disable Prompt During Packages Installation
WORKDIR "/root"
ARG DEBIAN_FRONTEND=noninteractive

RUN apt update
# Generally needed for compilation of applications
RUN apt install -y git build-essential wget gcc gawk libssl-dev \
                   seccomp python3 python3-pip unzip pkg-config file wget

# Generally needed for debugging
RUN apt install -y vim gdb

# Necessary for build-dep
RUN cp /etc/apt/sources.list /tmp/sources.list
RUN sed -i 's/deb /deb-src /' /tmp/sources.list
RUN cat /tmp/sources.list >> /etc/apt/sources.list
RUN apt update