;; No-op detection plugin for `osiris-bench ingest --plugins` (Phase 12b).
;; Implements ABI v1 and returns 0 ("no output") for every event, so the
;; bench measures the host cost of calling a plugin, not any guest logic.
(module
  (memory (export "memory") 4)
  (func (export "osiris_abi_version") (result i32)
    i32.const 1)
  ;; One fixed 1 KiB offset; the module never reads the input back.
  (func (export "osiris_alloc") (param $len i32) (result i32)
    i32.const 1024)
  (func (export "osiris_on_event") (param $ptr i32) (param $len i32) (result i64)
    i64.const 0))
