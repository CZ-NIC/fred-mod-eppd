FROM fedora:32

RUN dnf -y install            \
        git                   \
        cmake                 \
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
    && dnf clean all          \
    && rm -rf /var/cache/yum
