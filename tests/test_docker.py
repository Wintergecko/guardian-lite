import contextlib
import importlib.machinery
import importlib.util
import io
import pathlib
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
PATH = ROOT / 'sbin' / 'guardian-docker'
loader = importlib.machinery.SourceFileLoader('guardian_docker', str(PATH))
spec = importlib.util.spec_from_loader(loader.name, loader)
docker = importlib.util.module_from_spec(spec)
loader.exec_module(docker)


class DockerHelperTests(unittest.TestCase):
    def test_missing_docker_is_reported_without_running_commands(self):
        with mock.patch.object(docker, 'docker_binary', return_value=None):
            status = docker.docker_status()
        self.assertFalse(status['available'])
        self.assertEqual(status['containers'], [])
        self.assertIn('nicht installiert', status['error'])

    def test_invalid_container_inventory_is_reported_not_shown_as_empty(self):
        with mock.patch.object(docker, 'command', return_value=b'not-json\n'):
            with self.assertRaisesRegex(ValueError, 'ungueltig'):
                docker.inspect_containers()

    def test_invalid_compose_inventory_is_reported_not_shown_as_empty(self):
        with mock.patch.object(docker, 'compose_cli_available', return_value=True), \
                mock.patch.object(docker, 'command', return_value=b'not-json'):
            with self.assertRaisesRegex(ValueError, 'Projektliste ist ungueltig'):
                docker.compose_projects()

    def test_container_creation_uses_only_validated_docker_options(self):
        values = {
            'name': 'web-test', 'image': 'nginx:stable', 'memory_mib': 512,
            'cpus': '1.5', 'restart': 'unless-stopped', 'bind': '127.0.0.1',
            'host_port': '8080', 'container_port': '80', 'protocol': 'tcp',
            'volume': 'web-data', 'mount_path': '/var/lib/nginx',
        }
        with mock.patch.object(docker, 'command', return_value=b'a' * 64) as execute:
            result = docker.create_container(values)
        command = execute.call_args.args[0]
        self.assertEqual(result['container'], 'a' * 64)
        self.assertIn('--memory', command)
        self.assertIn('--cpus', command)
        self.assertIn('127.0.0.1:8080:80/tcp', command)
        self.assertIn('type=volume,source=web-data,target=/var/lib/nginx', command)
        self.assertNotIn('--privileged', command)
        self.assertNotIn('/var/run/docker.sock', ' '.join(command))

    def test_container_creation_rejects_host_mounts_and_public_bind_variants(self):
        values = {'name': 'unsafe', 'image': 'nginx:stable', 'memory_mib': 512,
                  'cpus': '1', 'restart': 'no', 'bind': '192.0.2.1',
                  'host_port': '8080', 'container_port': '80', 'protocol': 'tcp'}
        with mock.patch.object(docker, 'command') as execute:
            with self.assertRaisesRegex(ValueError, 'gebunden'):
                docker.create_container(values)
        execute.assert_not_called()
        values['bind'] = '127.0.0.1'
        values['image'] = '--privileged'
        with mock.patch.object(docker, 'command') as execute:
            with self.assertRaisesRegex(ValueError, 'Image'):
                docker.create_container(values)
        execute.assert_not_called()

    def test_container_updates_are_argument_arrays_and_bounded(self):
        container = {'id': 'b' * 64}
        with mock.patch.object(docker, 'command') as execute:
            docker.update_container(container, {'memory_mib': 1024, 'cpus': '2', 'restart': 'always'})
        self.assertEqual(execute.call_args.args[0],
                         ['update', '--memory', '1024m', '--cpus', '2', '--restart', 'always', 'b' * 64])
        with mock.patch.object(docker, 'command') as execute:
            with self.assertRaisesRegex(ValueError, 'Arbeitsspeicher'):
                docker.update_container(container, {'memory_mib': 0})
        execute.assert_not_called()

    def test_container_deletion_refuses_running_containers_and_preserves_volumes(self):
        with mock.patch.object(docker, 'resolve_container',
                               return_value={'id': 'c' * 64, 'running': True}), \
                mock.patch.object(docker, 'command') as execute:
            with self.assertRaisesRegex(ValueError, 'zuerst stoppen'):
                docker.container_action('container-remove', 'c' * 64)
        execute.assert_not_called()
        with mock.patch.object(docker, 'resolve_container',
                               return_value={'id': 'c' * 64, 'running': False}), \
                mock.patch.object(docker, 'command') as execute:
            result = docker.container_action('container-remove', 'c' * 64)
        self.assertTrue(result['volumes_preserved'])
        self.assertNotIn('-v', execute.call_args.args[0])

    def test_unknown_actions_are_rejected(self):
        output = io.StringIO()
        with mock.patch.object(docker, 'audit'), contextlib.redirect_stdout(output):
            code = docker.main(['exec', 'container', 'sh'])
        self.assertNotEqual(code, 0)
        self.assertIn('Ungueltige Docker-Aktion', output.getvalue())

    def test_compose_down_never_removes_volumes(self):
        project = {'name': 'sample', 'files': ['/srv/compose.yaml'], 'managed': False}
        with mock.patch.object(docker, 'resolve_project', return_value=project), \
                mock.patch.object(docker, 'command') as execute:
            result = docker.perform_compose('compose-down', 'sample')
        self.assertTrue(result['volumes_preserved'])
        self.assertEqual(execute.call_args.args[0][-2:], ['down', '--remove-orphans'])
        self.assertNotIn('--volumes', execute.call_args.args[0])

    def test_deleted_sentinel_projects_remain_recoverable_from_their_backup(self):
        backup_id = 'd' * 32
        registry = {'old-stack': {'deleted': True, 'backup': backup_id}}
        with mock.patch.object(docker, 'compose_cli_available', return_value=True), \
                mock.patch.object(docker, 'command', return_value=b'[]'), \
                mock.patch.object(docker, 'registry_read', return_value=registry):
            projects, available = docker.compose_projects()
        self.assertTrue(available)
        self.assertEqual(projects, [{
            'name': 'old-stack', 'status': 'deleted; backup available', 'files': [],
            'managed': True, 'deleted': True, 'backup_id': backup_id,
        }])

    def test_existing_compose_file_requires_root_owned_safe_path(self):
        with mock.patch.object(docker, 'resolve_project', return_value={
            'name': 'sample', 'files': ['/srv/compose.yaml'], 'managed': False,
        }), mock.patch.object(docker, 'resolve_project_file', return_value=pathlib.Path('/srv/compose.yaml')), \
                mock.patch.object(docker, 'safe_compose_parent',
                                  side_effect=ValueError('Compose-Datei kann nur in root-verwalteten Verzeichnissen bearbeitet werden.')):
            with self.assertRaisesRegex(ValueError, 'root-verwalteten'):
                docker.validate_yaml({'name': 'sample', 'files': ['/srv/compose.yaml']}, 0, b'services: {}')


if __name__ == '__main__':
    unittest.main()
