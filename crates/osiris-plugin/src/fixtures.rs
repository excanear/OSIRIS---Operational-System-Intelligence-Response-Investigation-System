//! Shared WAT plugin fixtures for tests (compiled to binary wasm on demand).
//!
//! Memory layout shared by all fixtures: 8 pages (512 KiB); constant output at
//! `OUT_PTR`; needle at `NEEDLE_PTR`; bump allocator starting at `HEAP_START`.

const OUT_PTR: u32 = 16;
const NEEDLE_PTR: u32 = 3000;
const HEAP_START: u32 = 4096;

const NC_ALERT: &str = r#"{"id":"nc_seen","severity":"HIGH","reasons":["process is nc"]}"#;
const NC_NEEDLE: &str = r#""name":"nc""#;

/// Escapes arbitrary bytes into a WAT string literal body.
fn wat_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("\\{b:02x}")).collect()
}

fn data(offset: u32, bytes: &[u8]) -> String {
    format!("(data (i32.const {offset}) \"{}\")", wat_bytes(bytes))
}

struct Parts<'a> {
    abi: i32,
    alloc: bool,
    import: bool,
    /// Extra module-level items (globals, helper funcs, data).
    extra: String,
    /// Body of `osiris_on_event` (must leave an i64 on the stack).
    on_event: &'a str,
}

fn build(p: Parts<'_>) -> Vec<u8> {
    let import = if p.import {
        "(import \"env\" \"host_fn\" (func $host_fn))"
    } else {
        ""
    };
    let alloc = if p.alloc {
        String::from(
            "(func (export \"osiris_alloc\") (param $len i32) (result i32) (local $p i32)
               (local.set $p (global.get $heap))
               (global.set $heap (i32.add (global.get $heap) (local.get $len)))
               (local.get $p))",
        )
    } else {
        String::new()
    };
    let src = format!(
        "(module
           {import}
           (memory (export \"memory\") 8)
           (global $heap (mut i32) (i32.const {HEAP_START}))
           (func (export \"osiris_abi_version\") (result i32) (i32.const {abi}))
           {alloc}
           {extra}
           (func (export \"osiris_on_event\") (param $ptr i32) (param $len i32) (result i64)
             (local $i i32) (local $j i32) (local $tmp i32) (local $d i32) (local $p i32)
             {body}))",
        abi = p.abi,
        extra = p.extra,
        body = p.on_event,
    );
    wat::parse_str(&src).expect("fixture WAT must be valid")
}

fn ret_const(ptr: u32, len: usize) -> String {
    format!("(i64.or (i64.shl (i64.const {ptr}) (i64.const 32)) (i64.const {len}))")
}

fn base(on_event: &str) -> Parts<'_> {
    Parts {
        abi: 1,
        alloc: true,
        import: false,
        extra: String::new(),
        on_event,
    }
}

/// A plugin that always returns the constant JSON `json`.
pub fn fixed_output(json: &str) -> Vec<u8> {
    assert!(
        OUT_PTR as usize + json.len() < NEEDLE_PTR as usize,
        "fixture output too long"
    );
    let body = ret_const(OUT_PTR, json.len());
    let mut p = base(&body);
    p.extra = data(OUT_PTR, json.as_bytes());
    build(p)
}

/// Returns the wasm bytes of the named fixture.
pub fn wasm(name: &str) -> Vec<u8> {
    match name {
        "detect_nc" => {
            let out = format!(r#"{{"alerts":[{NC_ALERT}]}}"#);
            let n = NC_NEEDLE.len();
            let body = format!(
                "(if (i32.lt_u (local.get $len) (i32.const {n})) (then (return (i64.const 0))))
                 (block $done
                   (loop $outer
                     (br_if $done (i32.gt_u (local.get $i) (i32.sub (local.get $len) (i32.const {n}))))
                     (local.set $j (i32.const 0))
                     (block $mismatch
                       (loop $cmp
                         (if (i32.eq (local.get $j) (i32.const {n}))
                           (then (return {hit})))
                         (br_if $mismatch (i32.ne
                           (i32.load8_u (i32.add (local.get $ptr) (i32.add (local.get $i) (local.get $j))))
                           (i32.load8_u (i32.add (i32.const {NEEDLE_PTR}) (local.get $j)))))
                         (local.set $j (i32.add (local.get $j) (i32.const 1)))
                         (br $cmp)))
                     (local.set $i (i32.add (local.get $i) (i32.const 1)))
                     (br $outer)))
                 (i64.const 0)",
                hit = ret_const(OUT_PTR, out.len()),
            );
            let mut p = base(&body);
            p.extra = format!(
                "{}\n{}",
                data(OUT_PTR, out.as_bytes()),
                data(NEEDLE_PTR, NC_NEEDLE.as_bytes())
            );
            build(p)
        }
        "tagger" => fixed_output(r#"{"tags":["seen"]}"#),
        "infinite_loop" => build(base("(loop $l (br $l)) (i64.const 0)")),
        "recursion_bomb" => {
            let mut p = base("(call $r) (i64.const 0)");
            p.extra = "(func $r (call $r))".into();
            build(p)
        }
        "memory_bomb" => build(base(
            "(loop $l
               (if (i32.eq (memory.grow (i32.const 16)) (i32.const -1)) (then unreachable))
               (br $l))
             (i64.const 0)",
        )),
        "oob_output" => build(base(
            "(i64.or (i64.shl (i64.const 0x100000) (i64.const 32)) (i64.const 16))",
        )),
        "overflow_output" => build(base(
            "(i64.or (i64.shl (i64.const 0xFFFFFFF0) (i64.const 32)) (i64.const 0x20))",
        )),
        "with_import" => {
            let mut p = base("(i64.const 0)");
            p.import = true;
            build(p)
        }
        "abi_v2" => {
            let mut p = base("(i64.const 0)");
            p.abi = 2;
            build(p)
        }
        "missing_alloc" => {
            let mut p = base("(i64.const 0)");
            p.alloc = false;
            build(p)
        }
        "counter" => {
            let prefix = br#"{"tags":["n"#;
            let suffix = br#""]}"#;
            let plen = prefix.len() as u32;
            let digits_at = OUT_PTR + plen;
            let body = format!(
                "(global.set $n (i32.add (global.get $n) (i32.const 1)))
                 (local.set $tmp (global.get $n))
                 (local.set $d (i32.const 0))
                 (loop $count
                   (local.set $d (i32.add (local.get $d) (i32.const 1)))
                   (local.set $tmp (i32.div_u (local.get $tmp) (i32.const 10)))
                   (br_if $count (i32.ne (local.get $tmp) (i32.const 0))))
                 (local.set $tmp (global.get $n))
                 (local.set $p (i32.add (i32.const {digits_at}) (local.get $d)))
                 (loop $write
                   (local.set $p (i32.sub (local.get $p) (i32.const 1)))
                   (i32.store8 (local.get $p)
                     (i32.add (i32.const 48) (i32.rem_u (local.get $tmp) (i32.const 10))))
                   (local.set $tmp (i32.div_u (local.get $tmp) (i32.const 10)))
                   (br_if $write (i32.ne (local.get $tmp) (i32.const 0))))
                 (local.set $p (i32.add (i32.const {digits_at}) (local.get $d)))
                 (i32.store8 (local.get $p) (i32.const {s0}))
                 (i32.store8 (i32.add (local.get $p) (i32.const 1)) (i32.const {s1}))
                 (i32.store8 (i32.add (local.get $p) (i32.const 2)) (i32.const {s2}))
                 (i64.or
                   (i64.shl (i64.const {OUT_PTR}) (i64.const 32))
                   (i64.extend_i32_u (i32.add (i32.const {plen3}) (local.get $d))))",
                s0 = suffix[0],
                s1 = suffix[1],
                s2 = suffix[2],
                plen3 = plen + 3,
            );
            let mut p = base(&body);
            p.extra = format!(
                "(global $n (mut i32) (i32.const 0))\n{}",
                data(OUT_PTR, prefix)
            );
            build(p)
        }
        other => panic!("unknown fixture `{other}`"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::load::{new_engine, HostState};
    use wasmtime::{Linker, Module, Store, StoreLimitsBuilder};

    fn run(engine: &wasmtime::Engine, module: &Module, input: &str) -> Vec<u8> {
        let linker: Linker<HostState> = Linker::new(engine);
        let mut store = Store::new(engine, HostState::new(StoreLimitsBuilder::new().build()));
        store.limiter(|s| &mut s.limits);
        store.set_fuel(1_000_000).unwrap();
        let inst = linker.instantiate(&mut store, module).unwrap();
        call(&mut store, &inst, input)
    }

    fn call(store: &mut Store<HostState>, inst: &wasmtime::Instance, input: &str) -> Vec<u8> {
        let alloc = inst
            .get_typed_func::<i32, i32>(&mut *store, "osiris_alloc")
            .unwrap();
        let on_event = inst
            .get_typed_func::<(i32, i32), i64>(&mut *store, "osiris_on_event")
            .unwrap();
        let mem = inst.get_memory(&mut *store, "memory").unwrap();
        let ptr = alloc.call(&mut *store, input.len() as i32).unwrap();
        mem.write(&mut *store, ptr as usize, input.as_bytes())
            .unwrap();
        let r = on_event
            .call(&mut *store, (ptr, input.len() as i32))
            .unwrap() as u64;
        if r == 0 {
            return Vec::new();
        }
        let (p, l) = ((r >> 32) as usize, (r & 0xFFFF_FFFF) as usize);
        mem.data(&*store)[p..p + l].to_vec()
    }

    #[test]
    fn every_fixture_is_valid_wasm_and_detect_nc_matches() {
        for n in [
            "detect_nc",
            "tagger",
            "infinite_loop",
            "memory_bomb",
            "recursion_bomb",
            "oob_output",
            "overflow_output",
            "with_import",
            "abi_v2",
            "missing_alloc",
            "counter",
        ] {
            assert!(!wasm(n).is_empty(), "{n}");
        }
        let engine = new_engine();
        let m = Module::new(&engine, wasm("detect_nc")).unwrap();
        let hit = run(&engine, &m, r#"{"process":{"name":"nc","pid":1}}"#);
        assert_eq!(
            String::from_utf8(hit).unwrap(),
            format!(r#"{{"alerts":[{NC_ALERT}]}}"#)
        );
        assert!(run(&engine, &m, r#"{"process":{"name":"bash"}}"#).is_empty());
        assert!(run(&engine, &m, "short").is_empty());
    }

    #[test]
    fn counter_increments_within_an_instance() {
        let engine = new_engine();
        let m = Module::new(&engine, wasm("counter")).unwrap();
        let linker: Linker<HostState> = Linker::new(&engine);
        let mut store = Store::new(&engine, HostState::new(StoreLimitsBuilder::new().build()));
        store.limiter(|s| &mut s.limits);
        store.set_fuel(10_000_000).unwrap();
        let inst = linker.instantiate(&mut store, &m).unwrap();
        for k in 1..=12 {
            let out = call(&mut store, &inst, "{}");
            assert_eq!(
                String::from_utf8(out).unwrap(),
                format!(r#"{{"tags":["n{k}"]}}"#)
            );
        }
        let t = Module::new(&engine, wasm("tagger")).unwrap();
        assert_eq!(run(&engine, &t, "{}"), br#"{"tags":["seen"]}"#);
    }
}
