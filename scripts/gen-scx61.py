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
EXPR = r'(?:\w+\([^()]*\)|\w+)'


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
    # list walks keyed on a member of p->scx
    text = re.sub(r'list_for_each_entry_safe_reverse\((\w+),\s*(\w+),\s*([^;{]+?),\s*scx\.(\w+)\)',
                  r'scx_for_each_task_safe_reverse(\1, \2, \3, \4)', text, flags=re.S)
    text = re.sub(r'list_for_each_entry\((\w+),\s*([^;{]+?),\s*scx\.(\w+)\)',
                  r'scx_for_each_task(\1, \2, \3)', text, flags=re.S)
    # &x->scx, then x->scx.member
    text = re.sub(r'&(%s)->scx\b(?!\.)' % EXPR, lambda m: accessor(m.group(1)), text)
    text = re.sub(r'(%s)->scx\.' % EXPR, lambda m: accessor(m.group(1)) + '->', text)
    return text


def convert_c(text):
    # The dump tracepoint would need a trace header of its own in the kernel
    # tree. compat.h has it as an empty inline.
    text = text.replace('#define CREATE_TRACE_POINTS\n#include <trace/events/sched_ext.h>\n', '')
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
