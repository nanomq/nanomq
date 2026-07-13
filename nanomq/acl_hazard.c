#ifdef ACL_SUPP
#include "include/acl_hazard.h"
#include "nng/nng.h"
#include "nng/supplemental/nanolib/log.h"

#include <stdlib.h>

// Atomic + TLS portability shim. nng's public API offers nng_atomic_ptr, but
// hazard pointers also need an ARRAY of per-thread slots and a thread-local
// slot index, which have no public nng primitive; so the raw operations are
// wrapped here once, per compiler. GCC/Clang use __atomic builtins; MSVC uses
// Interlocked intrinsics (full-barrier, so every SEQ_CST requirement below is
// met, if over-satisfied) and __declspec(thread).
#if defined(__GNUC__) || defined(__clang__)

#define ACL_HAZ_TLS __thread

static inline conf_acl *
haz_ptr_load(conf_acl **p)
{
	return __atomic_load_n(p, __ATOMIC_SEQ_CST);
}

static inline void
haz_ptr_store(conf_acl **p, conf_acl *v)
{
	__atomic_store_n(p, v, __ATOMIC_SEQ_CST);
}

static inline int
haz_int_load(int *p)
{
	return __atomic_load_n(p, __ATOMIC_SEQ_CST);
}

static inline void
haz_int_store(int *p, int v)
{
	__atomic_store_n(p, v, __ATOMIC_SEQ_CST);
}

static inline int
haz_int_fetch_add(int *p, int v)
{
	return __atomic_fetch_add(p, v, __ATOMIC_SEQ_CST);
}

// Release-ordered store for clearing a hazard slot: the writer's scan only
// needs to never miss a protected pointer; a stale non-NULL read merely
// delays reclamation to the next retire drain, so no full fence is needed.
static inline void
haz_ptr_store_rel(conf_acl **p, conf_acl *v)
{
	__atomic_store_n(p, v, __ATOMIC_RELEASE);
}

#elif defined(_MSC_VER)

#include <intrin.h>

#define ACL_HAZ_TLS __declspec(thread)

static __forceinline conf_acl *
haz_ptr_load(conf_acl **p)
{
	// CAS(NULL, NULL) is a full-barrier load: it only writes when *p is
	// already NULL, and then writes the same NULL back.
	return (conf_acl *) _InterlockedCompareExchangePointer(
	    (void *volatile *) p, NULL, NULL);
}

static __forceinline void
haz_ptr_store(conf_acl **p, conf_acl *v)
{
	(void) _InterlockedExchangePointer((void *volatile *) p, v);
}

static __forceinline int
haz_int_load(int *p)
{
	return (int) _InterlockedCompareExchange((volatile long *) p, 0, 0);
}

static __forceinline void
haz_int_store(int *p, int v)
{
	(void) _InterlockedExchange((volatile long *) p, (long) v);
}

static __forceinline int
haz_int_fetch_add(int *p, int v)
{
	return (int) _InterlockedExchangeAdd((volatile long *) p, (long) v);
}

// MSVC has no cheaper release-only store intrinsic; reuse the full-barrier
// exchange (correct, merely stronger than required).
static __forceinline void
haz_ptr_store_rel(conf_acl **p, conf_acl *v)
{
	(void) _InterlockedExchangePointer((void *volatile *) p, v);
}

#else
#error "acl_hazard.c needs GCC/Clang __atomic builtins or MSVC intrinsics"
#endif

// Maximum number of ACL readers that may hold a hazard pointer concurrently.
// This bounds the number of nng worker / callback threads that can be inside
// auth_acl at the same time. It is intentionally generous; if it is ever
// exhausted the affected thread's ACL checks are denied (fail-safe, see
// auth_acl) and the exhaustion is logged once per thread.
#define ACL_HAZARD_MAX 1024

// The published pointer to the live, immutable ACL snapshot. Written only by
// the single reload writer; read by every ACL reader. Accessed exclusively via
// the atomic shim above so the publication is visible without a lock.
static conf_acl *acl_current = NULL;

// Set once nmq_acl_hazard_init has published the first snapshot. Readers that
// observe this as 0 fall back to the memory-safe config-embedded ACL.
static int hazard_ready = 0;

// Per-reader hazard slots. A reader publishes the snapshot it is traversing
// into its own slot; the writer scans all claimed slots before reclaiming a
// retired snapshot. A reader only ever writes its OWN slot, and each slot is
// padded out to a cache line so concurrently-active readers (who claim
// adjacent indices) never write-share a line (unlike an rwlock reader
// counter).
typedef struct {
	conf_acl *ptr;
	char      pad[64 - sizeof(conf_acl *)];
} hazard_slot;

static hazard_slot hazard_slots[ACL_HAZARD_MAX];

// High-water mark of claimed slots; the writer only needs to scan this many.
// Monotonically increased atomically; never decreased (threads keep their
// slot for their lifetime).
static int hazard_high = 0;

// This thread's claimed slot index; HAZARD_INDEX_UNSET before the first claim
// attempt, HAZARD_INDEX_NONE once the registry was found exhausted (the
// failure is remembered and logged once per thread, keeping the repeated
// atomic RMW and the log call off the per-message hot path).
#define HAZARD_INDEX_UNSET -1
#define HAZARD_INDEX_NONE -2
static ACL_HAZ_TLS int t_hazard_index = HAZARD_INDEX_UNSET;

// Retire list of replaced snapshots awaiting reclamation, plus its lock. Both
// are writer-side only (off the read hot path): the single reload writer pushes
// retired snapshots and drains those no longer protected by any hazard pointer.
typedef struct retire_node {
	conf_acl *          acl;
	struct retire_node *next;
} retire_node;

static retire_node *retire_head = NULL;
static nng_mtx *    retire_mtx  = NULL; // allocated by nmq_acl_hazard_init

// hazard_claim_slot lazily assigns this thread a hazard slot the first time it
// reads the ACL, remembering the index in thread-local storage. Returns the
// slot index, or -1 when the fixed-size registry is exhausted.
static int
hazard_claim_slot(void)
{
	if (t_hazard_index >= 0) {
		return t_hazard_index;
	}
	if (t_hazard_index == HAZARD_INDEX_NONE) {
		return -1;
	}
	int idx = haz_int_fetch_add(&hazard_high, 1);
	if (idx >= ACL_HAZARD_MAX) {
		// Undo the over-increment so the high-water mark stays bounded by
		// ACL_HAZARD_MAX for the writer's scan, and remember the failure so
		// this thread neither repeats the RMW nor logs again.
		haz_int_fetch_add(&hazard_high, -1);
		t_hazard_index = HAZARD_INDEX_NONE;
		log_error("ACL hazard: slot registry exhausted (max %d); ACL "
		          "checks on this thread will be denied",
		    ACL_HAZARD_MAX);
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
	int high = haz_int_load(&hazard_high);
	if (high > ACL_HAZARD_MAX) {
		high = ACL_HAZARD_MAX;
	}
	for (int i = 0; i < high; i++) {
		if (haz_ptr_load(&hazard_slots[i].ptr) == p) {
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

	nng_mtx_lock(retire_mtx);
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
	nng_mtx_unlock(retire_mtx);
}

// acl_snapshot_take moves src's rules into a freshly-allocated immutable heap
// snapshot and detaches them from src (rule_count/rules cleared) so the source
// conf's conf_fini cannot double-free them. src->enable is copied but left set
// on src. Returns NULL when the allocation fails, leaving src untouched.
static conf_acl *
acl_snapshot_take(conf_acl *src)
{
	conf_acl *snap = malloc(sizeof(*snap));
	if (snap == NULL) {
		return NULL;
	}
	snap->enable     = src->enable;
	snap->rule_count = src->rule_count;
	snap->rules      = src->rules;

	src->rule_count = 0;
	src->rules      = NULL;
	return snap;
}

void
nmq_acl_hazard_init(conf *config)
{
	if (haz_int_load(&hazard_ready)) {
		return;
	}

	if (retire_mtx == NULL && nng_mtx_alloc(&retire_mtx) != 0) {
		log_error("ACL hazard: retire mutex alloc failed; ACL "
		          "reload disabled");
		return;
	}

	// Move the parsed rules into the immutable heap snapshot; config->acl
	// keeps only the enable gate, which callers read to decide whether to
	// invoke auth_acl at all.
	conf_acl *snap = acl_snapshot_take(&config->acl);
	if (snap == NULL) {
		log_error("ACL hazard: initial snapshot alloc failed; ACL "
		          "reload disabled");
		return;
	}

	haz_ptr_store(&acl_current, snap);
	haz_int_store(&hazard_ready, 1);
}

conf_acl *
nmq_acl_hazard_acquire(void)
{
	if (!haz_int_load(&hazard_ready)) {
		return NULL;
	}

	int idx = hazard_claim_slot();
	if (idx < 0) {
		// Exhaustion was already logged once by hazard_claim_slot; the
		// caller denies (see auth_acl).
		return NULL;
	}

	// Standard hazard-pointer publish-and-recheck: publish the pointer we
	// intend to traverse, then confirm it is still the live pointer. The
	// SEQ_CST hazard store followed by the SEQ_CST reload provides the
	// StoreLoad ordering that stops the writer's publish+scan from racing the
	// reader's publish. If the writer swapped in between, retry.
	conf_acl *p;
	do {
		p = haz_ptr_load(&acl_current);
		haz_ptr_store(&hazard_slots[idx].ptr, p);
	} while (p != haz_ptr_load(&acl_current));

	if (p == NULL) {
		// Nothing published (should not happen post-init); clear and fall
		// back so the caller does not dereference NULL.
		haz_ptr_store_rel(&hazard_slots[idx].ptr, NULL);
	}
	return p;
}

bool
nmq_acl_hazard_ready(void)
{
	return haz_int_load(&hazard_ready) != 0;
}

void
nmq_acl_hazard_release(void)
{
	int idx = t_hazard_index;
	if (idx >= 0) {
		haz_ptr_store_rel(&hazard_slots[idx].ptr, NULL);
	}
}

void
reload_acl_config(conf *config, conf *new_conf)
{
	// If startup init never published a snapshot, readers are on the
	// config-embedded fallback ACL and would never see this reload; no-op so
	// the enable gate and the rules readers traverse stay consistent.
	if (!haz_int_load(&hazard_ready)) {
		log_error("ACL hazard: registry not initialized; skipping ACL "
		          "reload");
		return;
	}

	conf_acl *snap = acl_snapshot_take(&new_conf->acl);
	if (snap == NULL) {
		log_error("ACL hazard: reload snapshot alloc failed; keeping "
		          "current ACL");
		return;
	}

	// The no-match policy and deny action are companions of the rules (same
	// auth config block) but are evaluated live from config by auth_acl and
	// the pub/sub handlers, so reload them together with the rules.
	config->acl_nomatch     = new_conf->acl_nomatch;
	config->acl_deny_action = new_conf->acl_deny_action;

	// Single-writer publish: load-then-store, no CAS required.
	conf_acl *old = haz_ptr_load(&acl_current);
	haz_ptr_store(&acl_current, snap);

	// Update the caller-visible enable gate only after the snapshot is live,
	// so a reader that passes a newly-enabled gate always finds the new rules.
	config->acl.enable = snap->enable;

	if (old != NULL) {
		acl_retire(old);
	}
}

#endif /* ACL_SUPP */
