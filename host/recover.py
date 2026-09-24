#!/usr/bin/python3
"""Copyright (c) docker-maintenance-center contributors. MIT licensed.
Root-only uncertainty review. Never replays, rolls back, restores data, or reports success.
Repair the deployment out of band first if its current Compose/runtime contract is invalid.
"""
import argparse
import json
import os
import re
import sys

from host_config import load_config
from project_registry import Registry, RegistryError, ID, atomic, digest, require


def snapshot(registry, project, operation_ref):
    data = registry.load()
    require(ID.fullmatch(project) and project in data['projects'], 'project_not_allowed')
    operation = registry.record('operations', project)
    require(operation is not None and operation['status'] == 'unknown'
            and operation.get('operation_ref') == operation_ref, 'operation_not_unknown')
    definition = data['projects'][project]
    material, _ = registry.inspect(definition['compose_path'], definition['services'], data, definition['compose_project'])
    health = registry.readonly(definition, 'health')
    return {'project':project, 'revision':data['revision'], 'definition':definition,
            'operation':operation, 'material':material, 'health':health}


def resolve(registry, project, operation_ref, expected, evidence):
    require(isinstance(evidence, str) and 20 <= len(evidence) <= 4000
            and not any(ord(char) < 32 for char in evidence), 'evidence_required')
    observed = snapshot(registry, project, operation_ref)
    require(digest(observed) == expected, 'review_stale')
    require(observed['health']['overall'] == 'healthy', 'recovery_health_required')
    previous = observed['operation']
    # The prior uncertainty remains immutable in the review audit. This only
    # releases the mutation interlock; it does not retroactively certify an update.
    outcome = dict(previous, status='failed', code='manually_reviewed', recovery='not_required',
                   resolution={'review_digest':expected, 'evidence':evidence,
                               'reviewed_at':registry.clock(), 'operator_uid':os.getuid(),
                               'data_restored':False, 'operation_replayed':False})
    audit = registry.state / 'audit' / (operation_ref + '-review-' + expected + '.json')
    if audit.exists():
        registry.trusted(audit)
        saved = json.loads(audit.read_text())
        require(saved['before'] == previous and saved['observed'] == observed
                and saved['after']['resolution']['evidence'] == evidence, 'review_conflict')
        outcome = saved['after']
    else:
        atomic(audit, {'before':previous, 'after':outcome, 'observed':observed})
    atomic(registry.state / 'operations' / (project + '.json'), outcome)
    return outcome


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('review', 'resolve'))
    parser.add_argument('--project', required=True)
    parser.add_argument('--operation-ref', required=True)
    parser.add_argument('--expected-review', help='Exact SHA256 review_digest from review output')
    parser.add_argument('--evidence', help='Operator investigation and external repair evidence, 20–4000 characters; no secrets')
    parser.add_argument('--acknowledge-no-data-recovery', action='store_true')
    args = parser.parse_args()
    try:
        require(os.getuid() == 0 and os.geteuid() == 0, 'root_required')
        require(re.fullmatch(r'[a-f0-9]{16}', args.operation_ref), 'operation_ref_invalid')
        registry = Registry.configured(load_config())
        registry.ensure_state()
        with registry.locked():
            if args.action == 'review':
                observed = snapshot(registry, args.project, args.operation_ref)
                # Do not print captured Compose environment/secrets to terminal.
                result = {'review_digest':digest(observed), 'operation':observed['operation'],
                          'health':observed['health'], 'revision':observed['revision'],
                          'images':{s:v['image'] for s,v in observed['material']['services'].items()}}
            else:
                require(args.acknowledge_no_data_recovery and args.expected_review
                        and re.fullmatch(r'[a-f0-9]{64}', args.expected_review), 'acknowledgement_required')
                result = resolve(registry, args.project, args.operation_ref, args.expected_review, args.evidence)
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception as error:
        print(json.dumps({'error':getattr(error, 'code', 'review_failed')}), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
