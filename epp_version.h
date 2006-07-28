/**
 * @file epp_version.h
 * This file serves as an easy place where to find and modify ccReg's
 * version reported in greeting frame.
 */

#ifndef MODEPPD_VERSION
/**
 * The version displayed in epp <greeting> frame. The version format
 * (digits '.' digits) is hardcoded in epp schema, we cannot change
 * it wilfully. Note that this is the version of whole ccReg project
 * including central repository (therefore the name modeppd_version
 * is somewhat confusing, I know).
 */
#define MODEPPD_VERSION	"1.0"
#endif

#ifndef SVN_REV
/**
 * SVN_REV is revision number from svn repository. It should be defined
 * as argument to cc on command line. This is just a default value in
 * case it is not so.
 */
#define SVN_REV	"unknown"
#endif
