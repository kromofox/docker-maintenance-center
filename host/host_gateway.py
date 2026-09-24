#!/usr/bin/python3
"""Copyright (c) docker-maintenance-center contributors. MIT licensed."""
import json
import os
import sys
from project_registry import PROTOCOL, Registry, RegistryError, parse
from host_config import load_config, check_caller


def main():
    request_id = None
    try:
        config = load_config()
        if len(sys.argv) != 1:
            raise RegistryError('caller_forbidden')
        check_caller(config, root=True)
        request = parse(sys.stdin.buffer.read(65537))
        request_id = request['request_id']
        result = {'protocol':PROTOCOL,'request_id':request_id,'ok':True,'data':Registry.configured(config).handle(request)}
    except Exception as error:
        result = {'protocol':PROTOCOL,'request_id':request_id,'ok':False,
                  'error':{'code':getattr(error,'code','request_failed')}}
    encoded = json.dumps(result,separators=(',',':')).encode()
    if len(encoded) > 1024*1024:
        encoded = json.dumps({'protocol':PROTOCOL,'request_id':request_id,'ok':False,
                              'error':{'code':'response_limit'}}).encode()
    sys.stdout.buffer.write(encoded+b'\n')
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    sys.exit(main())
