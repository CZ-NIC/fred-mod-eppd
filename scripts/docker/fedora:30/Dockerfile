FROM fedora:30
RUN dnf -y clean all                  \
        && dnf -y update              \
        && dnf -y install             \
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
                graphviz
