#!/usr/bin/env python3
"""Generate src/netfilter61/upstream from a vendor android14-6.1 kernel tree.

Applies the same mechanical adaptations the android16-6.12 module
(src/netfilter) carries, so nftables can live in one module on a kernel
built without CONFIG_NF_TABLES:

- net->nft.{base_seq,gencursor} -> ds_nft_state(net)->..., per-net state kept
  in net_generic storage because the native struct net has no nft member;
- module_init()/module_exit() of each former module -> ds_nf_init_<unit>() /
  ds_nf_exit_<unit>(), called in order by src/netfilter61/main.c;
- nf_nat_inet_{,un}register_fn -> the module's ds_ versions (nat-inet.c);
- include/net/netfilter/nf_tables.h copied to compat/ with the
  IS_ENABLED(CONFIG_NF_TABLES) block enabled.

Records the hashes of the unmodified inputs in upstream/SOURCES.json.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'src/netfilter61'
CORE = ['nf_tables_core', 'nf_tables_api', 'nft_chain_filter', 'nf_tables_trace',
        'nft_immediate', 'nft_cmp', 'nft_range', 'nft_bitwise', 'nft_byteorder',
        'nft_payload', 'nft_lookup', 'nft_dynset', 'nft_meta', 'nft_rt', 'nft_exthdr',
        'nft_last', 'nft_counter', 'nft_chain_route', 'nf_tables_offload',
        'nft_set_hash', 'nft_set_bitmap', 'nft_set_rbtree', 'nft_set_pipapo']
EXTRA = ['nft_objref', 'nft_ct', 'nft_nat', 'nft_chain_nat', 'nft_masq', 'nft_fib',
         'nft_fib_inet', 'nft_compat', 'nft_limit', 'nft_reject', 'nft_reject_inet',
         'nft_log', 'nft_redir']
V4 = ['nft_fib_ipv4', 'nft_reject_ipv4']
V6 = ['nft_fib_ipv6', 'nft_reject_ipv6']
HEADERS = ['nft_set_pipapo.h', 'nft_set_pipapo_avx2.h']
NFT_STATE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*(?:->[A-Za-z_][A-Za-z0-9_]*)*)->nft\.(base_seq|gencursor)')
INIT = re.compile(r'^module_init\((\w+)\);\n', re.M)
EXIT = re.compile(r'^module_exit\((\w+)\);\n', re.M)


def adapt(name, text):
    text = NFT_STATE.sub(r'ds_nft_state(\1)->\2', text)
    init, exit_ = INIT.search(text), EXIT.search(text)
    unit = None
    if init and exit_:
        unit = name
        text = INIT.sub('', text)
        text = EXIT.sub(f'int __init ds_nf_init_{name}(void) {{ return {init.group(1)}(); }}\n'
                        f'void ds_nf_exit_{name}(void) {{ {exit_.group(1)}(); }}\n', text)
        text = re.sub(r'\b__exit\b\s*', '', text)
    elif init or exit_:
        raise SystemExit(f'{name}: unpaired module_init/module_exit')
    else:
        text = re.sub(r'^(void|static void) __exit ', r'\1 ', text, flags=re.M)
    if name == 'nft_chain_nat':
        text, n = re.subn(r'\bnf_nat_inet_(register|unregister)_fn\b', r'ds_nf_nat_inet_\1_fn', text)
        if n != 2:
            raise SystemExit('nft_chain_nat: expected two INET NAT calls')
        text = text.replace('static int nft_nat_inet_reg(',
                            'extern int ds_nf_nat_inet_register_fn(struct net *, const struct nf_hook_ops *);\n'
                            'extern void ds_nf_nat_inet_unregister_fn(struct net *, const struct nf_hook_ops *);\n'
                            'static int nft_nat_inet_reg(', 1)
    return text, unit


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path, help='vendor kernel tree')
    args = parser.parse_args()
    src = args.source.resolve()
    up = OUT / 'upstream'
    up.mkdir(parents=True, exist_ok=True)
    hashes, units, objects = {}, [], []
    files = [(f'net/netfilter/{n}.c', n) for n in CORE + EXTRA]
    files += [(f'net/ipv4/netfilter/{n}.c', n) for n in V4]
    files += [(f'net/ipv6/netfilter/{n}.c', n) for n in V6]
    for rel, name in files:
        data = (src / rel).read_bytes()
        hashes[rel] = hashlib.sha256(data).hexdigest()
        text, unit = adapt(name, data.decode())
        (up / f'{name}.c').write_text(text)
        objects.append(name)
        if unit:
            units.append(unit)
    for h in HEADERS:
        data = (src / 'net/netfilter' / h).read_bytes()
        hashes[f'net/netfilter/{h}'] = hashlib.sha256(data).hexdigest()
        (up / h).write_bytes(data)
    rel = 'include/net/netfilter/nf_tables.h'
    data = (src / rel).read_bytes()
    hashes[rel] = hashlib.sha256(data).hexdigest()
    text = NFT_STATE.sub(r'ds_nft_state(\1)->\2', data.decode())
    text, n = re.subn(r'^#if IS_ENABLED\(CONFIG_NF_TABLES\)$',
                      '#if 1 /* Private nftables implementation; preserve native struct net. */',
                      text, flags=re.M)
    if n != 1:
        raise SystemExit('nf_tables.h: expected one CONFIG_NF_TABLES block')
    text = text.replace('#include <net/flow_offload.h>\n', '#include <net/flow_offload.h>\n#include "ds-state.h"\n', 1)
    if '"ds-state.h"' not in text:
        raise SystemExit('nf_tables.h: include anchor not found')
    compat = OUT / 'compat/net/netfilter'
    compat.mkdir(parents=True, exist_ok=True)
    (compat / 'nf_tables.h').write_text(text)
    # nf_tables_api registers the core first; the rest follow in list order.
    units.sort(key=lambda u: (u != 'nf_tables_api', files.index(next(f for f in files if f[1] == u))))
    (OUT / 'units.h').write_text('/* Generated by scripts/gen-netfilter61.py. Registration order; core first. */\n' +
                                 ''.join(f'DS_NF_UNIT({u})\n' for u in units))
    (OUT / 'objects.mk').write_text('# Generated by scripts/gen-netfilter61.py.\ndroidspaces_netfilter-y += \\\n' +
                                    ' \\\n'.join(f'\tsrc/netfilter61/upstream/{o}.o' for o in objects) + '\n')
    (up / 'SOURCES.json').write_text(json.dumps({'files': hashes}, indent=1) + '\n')
    print(f'{len(objects)} objects, {len(units)} units: {" ".join(units)}')
