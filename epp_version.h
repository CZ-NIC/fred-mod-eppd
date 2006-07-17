#ifndef MODEPPD_VERSION
/**
 * The version displayed in epp <greeting> frame. The version format
 * (digits '.' digits) is hardcoded in epp schema, we cannot change
 * it wilfully.
 */
#define MODEPPD_VERSION	"1.0"
#endif

#ifndef SVN_REV

/**
 * SVN_REV should be defined as argument to cc on command line. This is
 * just a default value in case it is not so.
 */
#define SVN_REV	"unknown"
#endif
