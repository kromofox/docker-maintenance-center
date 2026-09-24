#!/usr/bin/python3
"""Copyright (c) docker-maintenance-center contributors. MIT licensed."""
import json
import os
import subprocess
import sys
from project_registry import PROTOCOL, RegistryError, parse
from host_config import INSTALL, load_config, check_caller


def route(protocol, raw):
    if protocol != PROTOCOL:
        raise RegistryError('protocol_invalid')
    return [str(INSTALL / 'host_gateway.py')], parse(raw)


def main():
    request_id = None
    try:
        if len(sys.argv) != 1:
            raise RegistryError('caller_forbidden')
        check_caller(load_config())
        command, request = route(os.environ.get('SSH_ORIGINAL_COMMAND',''),sys.stdin.buffer.read(65537))
        request_id = request['request_id']
        # The root worker owns durable state and locks. Transport timeouts must
        # not terminate it and create an apparently retryable business action.
        return subprocess.run(['/usr/bin/sudo','-n']+command,input=json.dumps(request).encode(),
                              env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'}).returncode
    except Exception as error:
        print(json.dumps({'protocol':PROTOCOL,'request_id':request_id,'ok':False,
                          'error':{'code':getattr(error,'code','dispatch_failed')}}))
        return 2


if __name__ == '__main__':
    sys.exit(main())
