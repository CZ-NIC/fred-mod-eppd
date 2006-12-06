#!/bin/sh

# Script for Certificate Revocation List (CRL) regular updating
# 
# The script is ment to be run regularly from cron (recomended once per day).
# The script downloads CRLs from CRL_URLS urls. Because these CRLs are
# DER-encoded, they must be transformed to PEM-format. Finally all downloaded
# and transformed CRLs are concatenated to one file, which can be used in
# apache mod_ssl's SSLCARevocationFile configuration directive. The script
# requires openssl and wget command line tools.
#
# All actions are logged to LOGFILE. Configuration may be tweaked by variables
# bellow.
#
#                                     Jan Kryl <jan.kryl@nic.cz>, 1.12.2006


# Concatenate as many URLs as many CRLs you want to download
CRL_URLS="http://www.postsignum.cz/crl/psrootqca.crl"
CRL_URLS="$CRL_URLS http://www.postsignum.cz/crl/psqualifiedca.crl"

# Certificate against which are validated CRLs
CA_FILE=/etc/apache2/ssl/CA.crt

# CRL file which apache reads at its startup
TARGETFILE=/etc/apache2/ssl/post.crl

# Directory used for temporary files (must exist)
TMPDIR=/tmp
# Names of various temporary files used by script. Rarely subject to change.
TMPFILE=.temporary-crl-$$.crl
TMPDER=.temporary-der-$$.crl
TMPPEM=.temporary-pem-$$.crl

# Where all messages from CRL update will go
LOGFILE=/var/log/crl-update.log

# Command which restarts apache
APACHE_RESTART="apache2ctl restart"

########################################################################
### Do not change code bellow this line ################################
########################################################################

function logprefix()
{
	echo -n "`date +\"%b %d %H:%M:%S\"` [$$] " >>$LOGFILE
}

function info()
{
	logprefix
	echo "INFO: $1" >>$LOGFILE
}

function warn()
{
	logprefix
	echo "WARNING: $1" >>$LOGFILE
}

function error()
{
	logprefix
	echo "ERROR: $1" >>$LOGFILE
	logprefix
	info "Due to previously encountered errors exiting"
	logprefix
	info "The CRL file has not been updated!"
	exit 1
}

info "Process of CRL's update started"

# test that temporary file does not exist
if [ -f $TMPDIR/$TMPFILE ]
then
	warn "The temporary file already exists. Unclean shutdown?"
	warn "The temporary file will be deleted."
	if ! rm $TMPDIR/$TMPFILE
	then
		error "Could not delete temporary file"
	fi
fi

for CRL_URL in $CRL_URLS
do
	info "Downloading and processing CRL from $CRL_URL"
	# download fresh certificate revocation list in binary (DER) format
	OUTPUT=`wget --no-verbose --timeout=300 --waitretry=10 --output-document=$TMPDIR/$TMPDER $CRL_URL 2>&1`
	if [ $? -ne 0 ]
	then
		rm -f $TMPDIR/$TMPDER
		info "Output of wget: $OUTPUT"
		error "Error when downloading CRL file"
	fi
	info "CRL Downloaded successfully"

	# convert CRL from DER format to PEM format
	OUTPUT=`openssl crl -inform DER -outform PEM -in $TMPDIR/$TMPDER -out $TMPDIR/$TMPPEM -CAfile $CA_FILE 2>&1`
	if [ $? -ne 0 ]
	then
		rm -f $TMPDIR/$TMPDER
		rm -f $TMPDIR/$TMPPEM
		info "Output of openssl: $OUTPUT"
		error "Error when converting and verifing CRL file"
	fi

	# and append result to tmp file
	if ! cat $TMPDIR/$TMPPEM >> $TMPDIR/$TMPFILE && rm $TMPDIR/$TMPDER && rm $TMPDIR/$TMPPEM
	then
		rm -f $TMPDIR/$TMPDER
		rm -f $TMPDIR/$TMPPEM
		error "Error when creating new crl or deleting temp files"
	fi
done

info "Download and processing of all CRLs done"
# do the final overwritting of CRL file
if ! mv $TMPDIR/$TMPFILE $TARGETFILE
then
	rm -f $TMPDIR/$TMPFILE
	error "Could not overwrite official CRL file. Check permissions."
fi

info "New CRL file is in place"

info "Restarting apache server ..."
if ! $APACHE_RESTART
then
	error "Error when restarting apache. Apache may not be running!"
fi
info "Work done :-)"
