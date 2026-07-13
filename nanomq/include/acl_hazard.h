#ifndef NANOMQ_ACL_HAZARD_H
#define NANOMQ_ACL_HAZARD_H

#ifdef ACL_SUPP

#include "nng/supplemental/nanolib/acl_conf.h"
#include "nng/supplemental/nanolib/conf.h"

// Lock-free, hazard-pointer-based publication of the live ACL.
//
// The ACL (the set of parse rules used by auth_acl) is read on the hot path by
// every publish and subscribe, and rewritten wholesale by `nanomq reload`.
// Instead of guarding the read path with an rwlock (whose rdlock performs a
// read-modify-write on a shared reader counter and therefore bounces that
// cache line between every reader core), the live ACL is published through a
// single atomically-swapped pointer to an immutable conf_acl. Readers load the
// pointer once and traverse that immutable snapshot; the only shared write a
// reader performs is to its OWN hazard slot, so reader cores never contend on a
// shared cache line.
//
// Reclamation of a replaced ACL is deferred until no reader still holds a
// hazard pointer to it (hazard-pointer safe memory reclamation). Reload is
// single-writer (the cmd server processes one reload at a time), so the writer
// may load-then-store the published pointer without a CAS.

// nmq_acl_hazard_init installs the ACL parsed into config->acl as the first
// immutable snapshot and initializes the hazard registry. It must be called
// exactly once at broker startup, before any worker context can call auth_acl.
// It takes ownership of config->acl.rules (moving them into the heap snapshot)
// and detaches them from config->acl so conf_fini() cannot double-free them;
// config->acl.enable is left intact because callers still read it to gate the
// auth_acl call.
extern void nmq_acl_hazard_init(conf *config);

// nmq_acl_hazard_acquire returns the current immutable ACL snapshot with this
// thread's hazard pointer set to it, protecting it from reclamation until
// nmq_acl_hazard_release is called. Returns NULL when the registry is not yet
// initialized or when no hazard slot is available; the caller must then choose
// a memory-safe path (never traverse the live pointer unprotected): before
// init the rules still live in config->acl, after init only the snapshot
// holds them, so consult nmq_acl_hazard_ready to pick fallback vs deny.
extern conf_acl *nmq_acl_hazard_acquire(void);

// nmq_acl_hazard_ready reports whether the registry has published a snapshot
// (i.e. the rules have been moved out of config->acl). Lets auth_acl tell a
// pre-init acquire failure (config->acl still authoritative) from a
// post-init one (config->acl is empty; fail safe by denying).
extern bool nmq_acl_hazard_ready(void);

// nmq_acl_hazard_release clears this thread's hazard pointer. It MUST be called
// on every auth_acl exit path once acquire has been called.
extern void nmq_acl_hazard_release(void);

// reload_acl_config publishes new_conf's ACL as the new immutable snapshot and
// retires the previous one, reclaiming it once no reader still protects it.
// The rules are moved out of new_conf->acl (rule_count/rules cleared) so the
// caller's conf_fini(new_conf) does not double-free them. The companion policy
// fields acl_nomatch and acl_deny_action are copied into config (auth_acl and
// the pub/sub handlers evaluate them live), and config->acl.enable is updated
// after the snapshot is published so a reader passing a newly-enabled gate
// always finds the new rules.
extern void reload_acl_config(conf *config, conf *new_conf);

#endif /* ACL_SUPP */
#endif /* NANOMQ_ACL_HAZARD_H */
