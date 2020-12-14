FROM centos/devtoolset-7-toolchain-centos7
USER root

RUN yum -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm \
    && yum -y clean all       \
    && yum -y install         \
        git                   \
        cmake3                \
        make                  \
        gcc                   \
        apr-devel             \
        httpd-devel           \
        libxml2-devel         \
        openssl-devel         \
        ORBit2-devel          \
        doxygen               \
        perl                  \
        graphviz              \
    && rm -rf /var/cache/yum

RUN ln -s /usr/bin/cmake3 /usr/local/bin/cmake       \
    && ln -s /usr/bin/ccmake3 /usr/local/bin/ccmake  \
    && ln -s /usr/bin/ctest3 /usr/local/bin/ctest    \
    && ln -s /usr/bin/cpack3 /usr/local/bin/cpack

USER 1001
