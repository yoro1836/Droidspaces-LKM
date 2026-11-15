#!/usr/bin/env python3
"""Turn upstream kernel/sched/ext.c into the android14-6.1 port.

task_struct and struct rq have no scx member on this kernel. The per-task
entity is laid over p->dl, which only a deadline task uses, and the per-rq
part lives in a per-CPU array. Every access is rewritten to an accessor;
nothing else in the file is touched here. What 6.1 lacks otherwise is
supplied by src/scx61/compat.h around the generated file.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UP = ROOT / 'src/scx61/upstream'
OUT = ROOT / 'src/scx61'
FILES = {'ext.c': 'ext-gen.c', 'ext.h': 'ext-gen.h'}

# An rq is spelled as a variable that ends in rq or as one of these calls.
RQ = r'(?:\w*rq|cpu_rq\([^()]*\)|this_rq\(\)|task_rq\([^()]*\))'
EXPR = r'\w+(?:\([^()]*\))?(?:->\w+)*'


def accessor(expr):
    return 'scx_rq(%s)' % expr if re.fullmatch(RQ, expr) else 'scx_ent(%s)' % expr


def convert(text):
    # container_of(x, struct task_struct, scx.member) and the rq form
    text = re.sub(r'container_of\(([^,]+),\s*struct task_struct,\s*scx\.(\w+)\)',
                  r'scx_task_of(container_of(\1, struct sched_ext_entity, \2))', text)
    text = re.sub(r'container_of\(([^,]+),\s*struct rq,\s*scx\.(\w+)\)',
                  r'scx_rq_owner(container_of(\1, struct scx_rq, \2))', text)
    text = re.sub(r'offsetof(end)?\(struct task_struct,\s*scx\.(\w+)\)',
                  r'(SCX_ENT_OFFSET + offsetof\1(struct sched_ext_entity, \2))', text)
    text = re.sub(r'container_of\(([^,]+),\s*struct task_struct,\s*scx\)', r'scx_task_of(\1)', text)
    text = re.sub(r'list_first_entry_or_null\(([^;]+?),\s*struct task_struct,\s*scx\.([\w.]+)\)',
                  r'scx_first_task_or_null(\1, \2)', text, flags=re.S)
    # The class shares the idle slot, so "is this task ours" cannot be a
    # comparison of class pointers.
    text = re.sub(r'(%s)->sched_class == &ext_sched_class' % EXPR, r'task_is_scx(\1)', text)
    text = re.sub(r'(%s)->sched_class != &ext_sched_class' % EXPR, r'!task_is_scx(\1)', text)
    # Below ext sits only the real idle task.
    text = re.sub(r'sched_class_above\(&ext_sched_class, (%s)->sched_class\)' % EXPR, r'scx_above_task(\1)', text)
    text = text.replace('sched_class_above(&ext_sched_class, next_class)', 'scx_above_task(next)')
    # list walks keyed on a member of p->scx
    text = re.sub(r'list_for_each_entry_safe\((\w+),\s*(\w+),\s*([^;{]+?),\s*scx\.([\w.]+)\)',
                  r'scx_for_each_task_safe(\1, \2, \3, \4)', text, flags=re.S)
    text = re.sub(r'list_for_each_entry_safe_reverse\((\w+),\s*(\w+),\s*([^;{]+?),\s*scx\.(\w+)\)',
                  r'scx_for_each_task_safe_reverse(\1, \2, \3, \4)', text, flags=re.S)
    text = re.sub(r'list_for_each_entry\((\w+),\s*([^;{]+?),\s*scx\.(\w+)\)',
                  r'scx_for_each_task(\1, \2, \3)', text, flags=re.S)
    # &x->scx, then x->scx.member
    text = re.sub(r'&(%s)->scx\b(?!\.)' % EXPR, lambda m: accessor(m.group(1)), text)
    text = re.sub(r'(%s)->scx\.' % EXPR, lambda m: accessor(m.group(1)) + '->', text)
    return text


# Changes to ext.c beyond the accessors: (what, pattern, replacement, count).
# Each is something 6.12's core or BPF has in a shape 6.1 does not.
PATCHES = [
    ('the dump tracepoint needs a trace header in the kernel tree',
     r'#define CREATE_TRACE_POINTS\n#include <trace/events/sched_ext.h>\n', '', 1),
    ('6.1 has no delayed dequeue',
     r'\t+if \(old_class != new_class && p->se\.sched_delayed\)\n\t+dequeue_task\([^;]*DEQUEUE_DELAYED\);\n', '', 2),
    ('the class table has 6.12 members; src/scx61 calls it from the idle slot',
     r'DEFINE_SCHED_CLASS\(ext\) = \{', 'static const struct scx61_class ext_class = {', 1),
    ('struct_ops callbacks have 6.12 prototypes; src/scx61 registers them',
     r'static struct bpf_struct_ops bpf_sched_ext_ops = \{',
     'static struct scx61_struct_ops bpf_sched_ext_ops = {', 1),
    ('bpf_struct_ops_find() takes only the type id',
     r'bpf_struct_ops_find\(btf, btf_id\)', 'bpf_struct_ops_find(btf_id)', 1),
    ('btf_struct_access() is handed the type, and reads too',
     r'static int bpf_scx_btf_struct_access\([^)]*\)\n\{\n'
     r'\tconst struct btf_type \*t;\n\n\tt = btf_type_by_id\(reg->btf, reg->btf_id\);\n',
     'static int bpf_scx_btf_struct_access(struct bpf_verifier_log *log,\n'
     '\t\t\t\t     const struct btf *btf,\n'
     '\t\t\t\t     const struct btf_type *t, int off, int size,\n'
     '\t\t\t\t     enum bpf_access_type atype, u32 *next_btf_id,\n'
     '\t\t\t\t     enum bpf_type_flag *flag)\n{\n'
     '\tif (atype == BPF_READ)\n'
     '\t\treturn btf_struct_access(log, btf, t, off, size, atype, next_btf_id, flag);\n', 1),
    ('the vmlinux BTF is not passed to bpf_struct_ops_find()',
     r'\tstruct btf \*btf = bpf_get_btf_vmlinux\(\);\n(\tconst struct bpf_struct_ops_desc)', r'\1', 1),
    ('struct_ops types cannot be registered on 6.1; src/scx61/bpf.c takes a slot',
     r'register_bpf_struct_ops\(&bpf_sched_ext_ops, sched_ext_ops\)',
     'scx61_register_struct_ops(&bpf_sched_ext_ops)', 1),
    ('a module has one initcall, which calls scx_init()', r'\n__initcall\(scx_init\);\n', '\n', 1),
    ('init() cannot be a sleepable program before v6.3, so creating a queue must not sleep',
     r'dsq = kmalloc_node\(sizeof\(\*dsq\), GFP_KERNEL, node\);',
     'dsq = kmalloc_node(sizeof(*dsq), GFP_ATOMIC, node);', 1),
    ('sleepable is in prog->aux', r'prog->sleepable', 'prog->aux->sleepable', 1),
    ('uevent callbacks take a non-const kobject',
     r'static int scx_uevent\(const struct kobject \*kobj,', 'static int scx_uevent(struct kobject *kobj,', 1),
    ('sysrq handlers take an int', r'\(u8 key\)', '(int key)', 2),
    ('kfuncs are found through the merged vmlinux BTF, so the sets have no owner',
     r'\t\.owner\t+= THIS_MODULE,\n(\t\.set\t+= &scx_kfunc_ids_)', r'\1', 6),
]


def convert_c(text):
    for what, pattern, repl, count in PATCHES:
        text, n = re.subn(pattern, repl, text)
        if n != count:
            sys.exit('gen-scx61: "%s" matched %d times, expected %d' % (what, n, count))
    return text


if __name__ == '__main__':
    for src, dst in FILES.items():
        out = convert(UP.joinpath(src).read_text())
        if src.endswith('.c'):
            out = convert_c(out)
        left = [i + 1 for i, line in enumerate(out.splitlines())
                if re.search(r'->scx\b|\bscx\.\w+\)', line) and not line.lstrip().startswith('*')]
        OUT.joinpath(dst).write_text(
            '/* Generated from upstream/%s by scripts/gen-scx61.py. Do not edit. */\n' % src + out)
        print('%s: %d lines, %d left for hand conversion: %s' % (dst, out.count('\n'), len(left), left[:20]))
