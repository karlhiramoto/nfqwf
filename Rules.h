#ifndef RULES_H
#define RULES_H 1

#ifdef HAVE_CONFIG_H
#include "nfq-proxy-config.h"
#endif

#include <stdbool.h>
#include <linux/in.h>
#include "Filter.h"


/**
* @defgroup Rules Rule definitions
* @{
*/


/**
*  Different actions a rule can take
*/
enum Rule_action {
	Rule_invalid = 0,  /** not checked yet,  0 so calloc() or memset(0) will init */
	Rule_reject,
	Rule_accept,
	Rule_virus,
	Rule_malware,
	Rule_phishing,
	/** Trust:  will trust the connection, so subsequent requests and packets will not be checked */
	Rule_alwaysTrust,

	Rule_continue,  /** Rule matches but continue rule list */
};

#define MAX_OBJ_NAME 12
#if 0
#ifdef URLF_ENABLE
struct {
	char name[MAX_OBJ_NAME+1];
	char value[MAX_CATEGORY_VALUE+1];
	int id;
} category_obj;
#endif


struct {
	char name[MAX_OBJ_NAME+1];
	in_addr_t address;
	in_addr_t mask;
} ipv4_obj;

struct {
	char name[MAX_OBJ_NAME+1];
	short start;            /**< Start time in minutes from 00:00 */
	short stop;             /**< Stop time in minutes from 00:00 */
	uint8_t days;
} when_obj;
#endif


#define MAX_FITERS_PER_RULE 16
#define MAX_FITERS_TYPES 4
/** Rule definition. */
struct Rule {
	int id;        /** Rule ID */
	bool disabled; /** Is rule disabled */
	bool log;      /** Log this rule if it matches */
	bool notify;   /** Email Notify */
	enum Rule_action action;  /** Action this rule should take */

	/// Note possible new way to do fitlers. 
	/** Filter object may be of any objects
	like IP, Network, host, domain, category, etc
	A logical AND is operated on each filter type */

	/** 2D array.  within each group logical OR. Betwen groups logical AND.
	  See  @link FilterList */
	struct FilterList **filter_groups[MAX_FITERS_TYPES];

	/// Do it oldSkool
//  	struct Filter *src[MAX_FITERS_PER_RULE];
// 	struct Filter *dst[MAX_FITERS_PER_RULE];
// 	struct Filter *when[MAX_FITERS_PER_RULE];
// 	struct Filter *category[MAX_FITERS_PER_RULE];


};


/** @}
end of file
*/

#endif

