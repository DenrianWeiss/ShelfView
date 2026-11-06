"""Run the opt-in Apple media task test against the local Redfish reference."""
import argparse
import importlib.util
import os
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--c-build', type=Path, required=True)
    parser.add_argument('--swift-scratch', type=Path, default=Path('build-apple'))
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    c_build = args.c_build.resolve()
    scratch = args.swift_scratch.resolve()
    spec = importlib.util.spec_from_file_location('reference', root / 'tests/redfish_integration.py')
    reference = importlib.util.module_from_spec(spec)
    saved_argv = sys.argv
    try:
        sys.argv = ['reference', str(c_build / 'bcontrol-redfish-client')]
        spec.loader.exec_module(reference)
    finally:
        sys.argv = saved_argv
    original_get = reference.Handler.do_GET

    def get(handler):
        if handler.path == reference.TASK and getattr(handler.server, 'resume_outcome', '') == 'gone':
            handler.server.requests.append(handler.path)
            handler.reply(410, {})
            return
        if handler.path == reference.MANAGERS and getattr(handler.server, 'journal_fixture', False):
            handler.server.requests.append(handler.path)
            handler.reply(200, {'@odata.type': '#ManagerCollection.ManagerCollection',
                                'Members': [{'@odata.id': '/redfish/v1/Managers/mgr1'}]})
            return
        if handler.path == reference.MONITOR:
            handler.server.task_checks = getattr(handler.server, 'task_checks', 0) + 1
            if handler.server.task_checks >= 2:
                handler.server.task_state = 'Completed'
        if handler.path == '/redfish/v1/work-queue' and getattr(handler.server, 'capture_discovery_failure', False):
            handler.server.requests.append(handler.path)
            handler.reply(404, {})
            return
        original_get(handler)

    original_task = reference.Handler.task

    def task(handler):
        body = original_task(handler)
        if getattr(handler.server, 'capture_identity', False):
            body.update(StartTime='2026-10-24T05:00:00Z', Payload={
                'HttpOperation': 'POST', 'TargetUri': reference.VM_INSERT,
                'JsonBody': 'secret-image'})
        if handler.path == reference.TASK and getattr(handler.server, 'resume_outcome', ''):
            body['TaskState'] = 'Completed'
            if getattr(handler.server, 'journal_fixture', False):
                handler.server.vm_inserted = handler.server.resume_outcome != 'failed'
                handler.server.vm_image = 'http://fixture.invalid/live.iso' if handler.server.vm_inserted else ''
            if handler.server.resume_outcome == 'failed':
                body['TaskState'] = 'Exception'
                body['TaskStatus'] = 'Critical'
            if handler.server.resume_outcome == 'changed':
                body['StartTime'] = '2026-10-24T05:00:01Z'
            elif handler.server.resume_outcome == 'missing':
                body.pop('Payload', None)
        return body

    reference.Handler.task = task
    original_reply = reference.Handler.reply

    def reply(handler, status, body, *args):
        if status == 202 and handler.path == reference.VM_INSERT and isinstance(body, dict) and getattr(handler.server, 'capture_identity', False):
            body = dict(body)
            body.update(Id='7', StartTime='2026-10-24T05:00:00Z', Payload={
                'HttpOperation': 'POST', 'TargetUri': reference.VM_INSERT,
                'JsonBody': 'secret-image'})
        return original_reply(handler, status, body, *args)

    reference.Handler.reply = reply
    reference.Handler.do_GET = get
    reference.Redfish.setUpClass()
    try:
        with reference.Redfish().fixture('vm-accepted') as server:
            environment = {key: value for key, value in os.environ.items() if not key.startswith('BC_TEST_')}
            environment.update(BC_TEST_REDFISH_URL='https://localhost:' + str(server.server_port),
                               BC_TEST_REDFISH_CA=str(reference.Redfish.root / 'cert'),
                               BC_TEST_REDFISH_MEDIA_ASYNC='1')
            command = ['swift', 'test', '--package-path', str(root / 'frontends/apple'),
                       '--scratch-path', str(scratch), '-Xcc', '-I', '-Xcc', str(root / 'include'),
                       '-Xcc', '-I', '-Xcc', str(root / 'adapters/megarac'),
                       '-Xlinker', '-L', '-Xlinker', str(c_build),
                       '-Xlinker', '-rpath', '-Xlinker', str(c_build),
                       '--filter', 'testLiveVirtualMediaAsyncTaskLifecycle']
            subprocess.run(command, env=environment, cwd=root, check=True, timeout=120)
            if (len(server.posts), server.task_checks, server.requests.count(reference.TASK)) != (1, 3, 1):
                raise RuntimeError('Expected one media POST, three monitor GETs and one declared Task fallback')
            print('Apple media task: single POST, pending/completed monitor, declared Task fallback passed')
        for outcome in ('captured', 'missing', 'discovery-failed'):
            with reference.Redfish().fixture('vm-accepted') as server:
                server.capture_identity = outcome != 'missing'
                server.capture_discovery_failure = outcome == 'discovery-failed'
                environment = {key: value for key, value in os.environ.items() if not key.startswith('BC_TEST_')}
                environment.update(BC_TEST_REDFISH_URL='https://localhost:' + str(server.server_port),
                                   BC_TEST_REDFISH_CA=str(reference.Redfish.root / 'cert'),
                                   BC_TEST_REDFISH_TASK_REFERENCE=outcome)
                subprocess.run(command[:-1] + ['testLiveVirtualMediaTaskReferenceCapture'],
                               env=environment, cwd=root, check=True, timeout=120)
                if len(server.posts) != 1 or server.requests.count(reference.TASK) != 0:
                    raise RuntimeError('Reference capture must not replay POST or fetch an undeclared Task')
                print('Apple media reference: ' + outcome + ', accepted result preserved, no Task GET')
        for outcome in ('matched', 'changed', 'missing', 'gone', 'binding'):
            with reference.Redfish().fixture('vm-accepted') as server:
                server.capture_identity = True
                server.resume_outcome = outcome
                environment = {key: value for key, value in os.environ.items() if not key.startswith('BC_TEST_')}
                environment.update(BC_TEST_REDFISH_URL='https://localhost:' + str(server.server_port),
                                   BC_TEST_REDFISH_CA=str(reference.Redfish.root / 'cert'),
                                   BC_TEST_REDFISH_TASK_RESUME=outcome)
                subprocess.run(command[:-1] + ['testLiveVirtualMediaTaskReferenceResume'],
                               env=environment, cwd=root, check=True, timeout=120)
                if len(server.posts) != 1 or server.requests.count(reference.TASK) != (0 if outcome == 'binding' else 1):
                    raise RuntimeError('Resume must only GET its validated saved Task and never replay POST')
                print('Apple media resume: ' + outcome + ', one original POST, bounded identity-checked GET')
        for journal_outcome in ('matched', 'failed', 'changed', 'gone'):
            with reference.Redfish().fixture('vm-accepted') as server:
                server.capture_identity = True
                server.resume_outcome = journal_outcome
                server.journal_fixture = True
                environment = {key: value for key, value in os.environ.items() if not key.startswith('BC_TEST_')}
                environment.update(BC_TEST_REDFISH_URL='https://localhost:' + str(server.server_port),
                                   BC_TEST_REDFISH_CA=str(reference.Redfish.root / 'cert'), BC_TEST_REDFISH_JOURNAL='1',
                                       BC_TEST_REDFISH_JOURNAL_FAILURE='1' if journal_outcome == 'failed' else '0',
                                       BC_TEST_REDFISH_JOURNAL_UNRESOLVED='1' if journal_outcome in ('changed', 'gone') else '0')
                subprocess.run(command[:-1] + ['testLiveMediaJournalRecreationResumesWithoutReplayingWrite'],
                               env=environment, cwd=root, check=True, timeout=120)
                if len(server.posts) != 1 or server.requests.count(reference.TASK) != 1:
                    raise RuntimeError('Journal recreation must only resume one saved Task without replaying mount/eject')
                print('Apple journal: ' + journal_outcome + ', recreated workspace resumes without replay and preserves cleanup policy')
        for mode, outcome in [('vm-drop', 'uncertain'), ('vm-reject', 'rejected')]:
            with reference.Redfish().fixture(mode) as server:
                environment = {key: value for key, value in os.environ.items() if not key.startswith('BC_TEST_')}
                environment.update(BC_TEST_REDFISH_URL='https://localhost:' + str(server.server_port),
                                   BC_TEST_REDFISH_CA=str(reference.Redfish.root / 'cert'),
                                   BC_TEST_REDFISH_MEDIA_OUTCOME=outcome)
                subprocess.run(command[:-1] + ['testLiveVirtualMediaWriteOutcome'],
                               env=environment, cwd=root, check=True, timeout=120)
                if len(server.posts) != 1:
                    raise RuntimeError('Media write failure must not replay the original POST')
                print('Apple media outcome: ' + outcome + ', single POST passed')
    finally:
        reference.Redfish.tearDownClass()


if __name__ == '__main__':
    main()
