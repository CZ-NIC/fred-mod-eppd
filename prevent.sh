#!/bin/sh
DIR=~/cov/mod_eppd/
PRODUCT=mod_eppd
cov-build --dir ${DIR} --config /opt/prevent-linux64-3.6.1/config/coverity_config.xml make && \
cov-analyze --all --dir ${DIR} --config /opt/prevent-linux64-3.6.1/config/coverity_config.xml && \
cov-commit-defects --datadir ~/cov/gui/ --product ${PRODUCT} --user ondrej --dir ${DIR}
