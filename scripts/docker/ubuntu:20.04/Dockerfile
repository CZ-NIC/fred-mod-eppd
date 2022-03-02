FROM ubuntu:20.04
ENV DEBIAN_FRONTEND noninteractive

RUN apt-get -y update \
        && apt-get -y install --no-install-recommends gnupg2

RUN printf 'deb http://archive.nic.cz/ubuntu focal main\n' > /etc/apt/sources.list.d/cz.nic.list \
        && printf 'deb http://archive.nic.cz/scratch focal main\n' >> /etc/apt/sources.list.d/cz.nic.list \
        && apt-key adv --keyserver keyserver.ubuntu.com --recv-keys E6DD3CAC7844804C

RUN apt-get -y update \
        && apt-get -y install --no-install-recommends \
            ssh-client                      \
            cmake                           \
            pkg-config                      \
            build-essential                 \
            ninja-build                     \
            bash-completion                 \
            git                             \
            liborbit2-dev                   \
            libaprutil1-dev                 \
            libapr1-dev                     \
            doxygen                         \
            apache2-dev                     \
            libxml2-dev                     \
            libssl-dev                      \
        && apt-get -y clean                 \
        && rm -rf /var/lib/apt/lists/*
