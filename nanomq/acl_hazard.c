#ifdef ACL_SUPP
#include "include/acl_hazard.h"
#include "nng/supplemental/nanolib/log.h"

#include <pthread.h>
#include <stdlib.h>

// Maximum number of ACL readers that may hold a hazard pointer concurrently.
// This bounds the number of nng worker / callback threads that can be inside
// auth_acl at the same time. It is intentionally generous; if it is ever
// exhausted the reader falls back to a memory-safe deny (see acquire) and logs.
#define ACL_HAZARD_MAX 1024

// The published pointer to the live, immutable ACL snapshot. Written only by
// the single reload writer; read by every ACL reader. Accessed exclusively via
// __atomic builtins so the publication is visible without a lock.
static conf_acl *acl_current = NULL;

// Set once nmq_acl_hazard_init has published the first snapshot. Readers that
// observe this as 0 fall back to the memory-safe config-embedded ACL.
static int hazard_ready = 0;

// Per-reader hazard slots. A reader publishes the snapshot it is traversing
// into its own slot; the writer scans all claimed slots before reclaiming a
// retired snapshot. A reader only ever writes its OWN slot, so reader cores do
// not share a written cache line (unlike an rwlock reader counter).
static conf_acl *hazard_slots[ACL_HAZARD_MAX];

// High-water mark of claimed slots; the writer only needs to scan this many.
// Monotonically increased via __atomic; never decreased (threads keep their
// slot for their lifetime).
static int hazard_high = 0;

// This thread's claimed slot index, or -1 if it has not claimed one yet.
static __thread int t_hazard_index = -1;

// Retire list of replaced snapshots awaiting reclamation, plus its lock. Both
// are writer-side only (off the read hot path): the single reload writer pushes
// retired snapshots and drains those no longer protected by any hazard pointer.
typedef struct retire_node {
	conf_acl *          acl;
	struct retire_node *next;
} retire_node;

static retire_node *   retire_head = NULL;
static pthread_mutex_t retire_lock = PTHREAD_MUTEX_INITIALIZER;

// hazard_claim_slot lazily assigns this thread a hazard slot the first time it
// reads the ACL, remembering the index in thread-local storage. Returns the
// slot index, or -1 when the fixed-size registry is exhausted.
static int
hazard_claim_slot(void)
{
	if (t_hazard_index >= 0) {
		return t_hazard_index;
	}
	int idx = __atomic_fetch_add(&hazard_high, 1, __ATOMIC_SEQ_CST);
	if (idx >= ACL_HAZARD_MAX) {
		// Undo the over-increment so the high-water mark stays bounded by
		// ACL_HAZARD_MAX for the writer's scan.
		__atomic_fetch_sub(&hazard_high, 1, __ATOMIC_SEQ_CST);
		return -1;
	}
	t_hazard_index = idx;
	return idx;
}

// hazard_is_protected reports whether any reader currently publishes p in its
// hazard slot. Called only by the writer while draining the retire list.
static bool
hazard_is_protected(conf_acl *p)
{
	int high = __atomic_load_n(&hazard_high, __ATOMIC_SEQ_CST);
	if (high > ACL_HAZARD_MAX) {
		high = ACL_HAZARD_MAX;
	}
	for (int i = 0; i < high; i++) {
		if (__atomic_load_n(&hazard_slots[i], __ATOMIC_SEQ_CST) == p) {
			return true;
		}
	}
	return false;
}

// acl_retire pushes old onto the retire list and reclaims every retired
// snapshot no longer protected by a hazard pointer. Single-writer, so no CAS is
// needed; the lock only guards the retire list against a hypothetical second
// caller and keeps the drain self-consistent.
static void
acl_retire(conf_acl *old)
{
	retire_node *node = malloc(sizeof(*node));
	if (node == NULL) {
		// Cannot track it for deferred reclamation; leak rather than risk
		// freeing a snapshot a reader may still be traversing.
		log_error("ACL hazard: retire node alloc failed; leaking old ACL");
		return;
	}
	node->acl = old;

	pthread_mutex_lock(&retire_lock);
	node->next  = retire_head;
	retire_head = node;

	retire_node **pp = &retire_head;
	while (*pp != NULL) {
		retire_node *cur = *pp;
		if (!hazard_is_protected(cur->acl)) {
			*pp = cur->next;
			conf_acl_destroy(cur->acl);
			free(cur->acl);
			free(cur);
		} else {
			pp = &cur->next;
		}
	}
	pthread_mutex_unlock(&retire_lock);
}

void
nmq_acl_hazard_init(conf *config)
{
	if (__atomic_load_n(&hazard_ready, __ATOMIC_SEQ_CST)) {
		return;
	}

	conf_acl *snap = malloc(sizeof(*snap));
	if (snap == NULL) {
		log_error("ACL hazard: initial snapshot alloc failed; ACL "
		          "reload disabled");
		return;
	}
	// Move the parsed rules into the immutable heap snapshot and detach them
	// from config->acl so conf_fini() cannot double-free them. Keep
	// config->acl.enable because callers read it to decide whether to invoke
	// auth_acl at all.
	snap->enable     = config->acl.enable;
	snap->rule_count = config->acl.rule_count;
	snap->rules      = config->acl.rules;

	config->acl.rule_count = 0;
	config->acl.rules      = NULL;

	__atomic_store_n(&acl_current, snap, __ATOMIC_SEQ_CST);
	__atomic_store_n(&hazard_ready, 1, __ATOMIC_SEQ_CST);
}

conf_acl *
nmq_acl_hazard_acquire(void)
{
	if (!__atomic_load_n(&hazard_ready, __ATOMIC_SEQ_CST)) {
		return NULL;
	}

	int idx = hazard_claim_slot();
	if (idx < 0) {
		log_error("ACL hazard: slot registry exhausted (max %d); "
		          "denying to stay memory-safe",
		    ACL_HAZARD_MAX);
		return NULL;
	}

	// Standard hazard-pointer publish-and-recheck: publish the pointer we
	// intend to traverse, then confirm it is still the live pointer. The
	// SEQ_CST hazard store followed by the SEQ_CST reload provides the
	// StoreLoad ordering that stops the writer's publish+scan from racing the
	// reader's publish. If the writer swapped in between, retry.
	conf_acl *p;
	do {
		p = __atomic_load_n(&acl_current, __ATOMIC_SEQ_CST);
		__atomic_store_n(&hazard_slots[idx], p, __ATOMIC_SEQ_CST);
	} while (p != __atomic_load_n(&acl_current, __ATOMIC_SEQ_CST));

	if (p == NULL) {
		// Nothing published (should not happen post-init); clear and fall
		// back so the caller does not dereference NULL.
		__atomic_store_n(&hazard_slots[idx], NULL, __ATOMIC_SEQ_CST);
	}
	return p;
}

bool
nmq_acl_hazard_ready(void)
{
	return __atomic_load_n(&hazard_ready, __ATOMIC_SEQ_CST) != 0;
}

void
nmq_acl_hazard_release(void)
{
	int idx = t_hazard_index;
	if (idx >= 0) {
		__atomic_store_n(&hazard_slots[idx], NULL, __ATOMIC_SEQ_CST);
	}
}

void
reload_acl_config(conf *config, conf *new_conf)
{
	// If startup init never published a snapshot, readers are on the
	// config-embedded fallback ACL and would never see this reload; no-op so
	// the enable gate and the rules readers traverse stay consistent.
	if (!__atomic_load_n(&hazard_ready, __ATOMIC_SEQ_CST)) {
		log_error("ACL hazard: registry not initialized; skipping ACL "
		          "reload");
		return;
	}

	conf_acl *snap = malloc(sizeof(*snap));
	if (snap == NULL) {
		log_error("ACL hazard: reload snapshot alloc failed; keeping "
		          "current ACL");
		return;
	}
	snap->enable     = new_conf->acl.enable;
	snap->rule_count = new_conf->acl.rule_count;
	snap->rules      = new_conf->acl.rules;

	// Detach the moved rules so conf_fini(new_conf) does not double-free them.
	new_conf->acl.rule_count = 0;
	new_conf->acl.rules      = NULL;

	// The no-match policy and deny action are companions of the rules (same
	// auth config block) but are evaluated live from config by auth_acl and
	// the pub/sub handlers, so reload them together with the rules.
	config->acl_nomatch     = new_conf->acl_nomatch;
	config->acl_deny_action = new_conf->acl_deny_action;

	// Single-writer publish: load-then-store, no CAS required.
	conf_acl *old = __atomic_load_n(&acl_current, __ATOMIC_SEQ_CST);
	__atomic_store_n(&acl_current, snap, __ATOMIC_SEQ_CST);

	// Update the caller-visible enable gate only after the snapshot is live,
	// so a reader that passes a newly-enabled gate always finds the new rules.
	config->acl.enable = snap->enable;

	if (old != NULL) {
		acl_retire(old);
	}
}

#endif /* ACL_SUPP */
