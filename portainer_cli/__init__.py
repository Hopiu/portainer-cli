#!/usr/bin/env python
import os
import re
import logging
import json
import plac
import validators
from requests import Request, Session


try:
    FileNotFoundError
except NameError:
    FileNotFoundError = IOError

__version__ = '0.3.0'

logger = logging.getLogger('portainer-cli')

env_arg_regex = r'--env\.(.+)=(.+)'


def env_arg_to_dict(s):
    split = re.split(env_arg_regex, s)
    return (split[1], split[2],)


class PortainerCLI(object):
    COMMAND_CONFIGURE = 'configure'
    COMMAND_LOGIN = 'login'
    COMMAND_REQUEST = 'request'
    COMMAND_CREATE_STACK = 'create_stack'
    COMMAND_UPDATE_STACK = 'update_stack'
    COMMAND_CREATE_OR_UPDATE_STACK = 'create_or_update_stack'
    COMMAND_GET_STACK_ID = 'get_stack_id'
    COMMAND_UPDATE_REGISTRY = 'update_registry'
    COMMANDS = [
        COMMAND_CONFIGURE,
        COMMAND_LOGIN,
        COMMAND_REQUEST,
        COMMAND_CREATE_STACK,
        COMMAND_UPDATE_STACK,
        COMMAND_CREATE_OR_UPDATE_STACK,
        COMMAND_GET_STACK_ID,
        COMMAND_UPDATE_REGISTRY
    ]

    METHOD_GET = 'GET'
    METHOD_POST = 'POST'
    METHOD_PUT = 'PUT'

    local = False
    _base_url = 'http://localhost:9000/'
    _jwt = None
    _proxies = {}
    _swarm_id = None

    @property
    def base_url(self):
        return self._base_url

    @base_url.setter
    def base_url(self, value):
        if not validators.url(value):
            raise Exception('Insert a valid base URL')
        self._base_url = value if value.endswith('/') else '{}/'.format(value)
        self.persist()

    @property
    def jwt(self):
        return self._jwt

    @jwt.setter
    def jwt(self, value):
        self._jwt = value
        self.persist()

    @property
    def proxies(self):
        return self._proxies

    @proxies.setter
    def proxies(self, value):
        try:
            self._proxies['http'] = os.environ['HTTP_PROXY']
        except KeyError:
            self._proxies['http'] = ''
        try:
            self._proxies['https'] = os.environ['HTTPS_PROXY']
        except KeyError:
            self._proxies['https'] = ''
        if self._proxies['http'] == '' and self._proxies['https'] == '':
            self._proxies = {}

    @property
    def swarm_id(self):
        return self._swarm_id

    @swarm_id.setter
    def swarm_id(self, value):
        self._swarm_id = value
        self.persist()

    @property
    def data_path(self):
        if self.local:
            logger.debug('using local configuration file')
            return '.portainer-cli.json'
        logger.debug('using user configuration file')
        return os.path.join(
            os.path.expanduser('~'),
            '.portainer-cli.json',
        )

    def persist(self):
        data = {
            'base_url': self.base_url,
            'jwt': self.jwt,
        }
        logger.info('persisting configuration: {}'.format(data))
        data_file = open(self.data_path, 'w+')
        data_file.write(json.dumps(data))
        logger.info('configuration persisted in: {}'.format(self.data_path))

    def load(self):
        try:
            data_file = open(self.data_path)
        except FileNotFoundError:
            return
        data = json.loads(data_file.read())
        logger.info('configuration loaded: {}'.format(data))
        self._base_url = data.get('base_url')
        self._jwt = data.get('jwt')

    def configure(self, base_url):
        self.base_url = base_url

    def login(self, username, password):
        response = self.request(
            'auth',
            self.METHOD_POST,
            {
                'username': username,
                'password': password,
            }
        )
        r = response.json()
        jwt = r.get('jwt')
        logger.info('logged with jwt: {}'.format(jwt))
        self.jwt = jwt

    # Retrieve the stack if. -1 if the stack does not exist
    @plac.annotations(
        endpoint_id=('Endpoint id', 'option', 'e'),
        stack_name=('Stack name', 'option', 'n')
    )
    def get_stack_id(self, endpoint_id, stack_name):
        stack_url = 'stacks'
        result = self.request(
            stack_url,
            self.METHOD_GET
        ).json()
        if not result:
            logger.debug('Stack with name={} does not exist').format(
                stack_name)
            return -1
        else:
            for stack in result:
                if stack['Name'] == stack_name:
                    logger.debug(
                        'Stack with name={} -> id={}').format(stack_name, stack['Id'])
                    return stack['Id']
            logger.debug('Stack with name={} does not exist').format(
                stack_name)
            return -1

    def extract_env(self, env_file='', *args):
        if env_file:
            env = {}
            for env_line in open(env_file).readlines():
                env_line = env_line.strip()
                if not env_line or env_line.startswith('#') or '=' not in env_line:
                    continue
                k, v = env_line.split('=', 1)
                k, v = k.strip(), v.strip()
                env[k] = v
        else:
            env_args = filter(
                lambda x: re.match(env_arg_regex, x),
                args,
            )
        env = dict(map(
            lambda x: env_arg_to_dict(x),
            env_args,
        ))
        return env

    def create_or_update_stack(self, *args):
        stack_id = plac.call(self.get_stack_id, *args)
        if stack_id == -1:
            plac.call(self.create_stack, *args)
        else:
            plac.call(self.update_stack, '-s', stack_id, *args)

    @plac.annotations(
        stack_name=('Stack name', 'option', 'n'),
        endpoint_id=('Endpoint id', 'option', 'e'),
        env_file=('Environment Variable file', 'option', 'f'),
        owner_type=('Owner type', 'option', 'ot', ['user', 'team', 'public']),
        owner=('Owner (user name or team name)')
    )
    def create_stack(self, endpoint_id, stack_file, stack_name, env_file='', owner_type='public', owner='', *args):
        logger.info('Creating stack name={}').format(stack_name)
        stack_url = 'stacks?type=1&method=string&endpointId={}'.format(
            endpoint_id
        )
        swarm_url = 'endpoints/{}/docker/swarm'.format(endpoint_id)
        swarm_id = self.request(swarm_url, self.METHOD_GET).json().get('ID')
        self.swarm_id = swarm_id
        stack_file_content = open(stack_file).read()

        env = self.extract_env(env_file, *args)
        final_env = list(
            map(
                lambda x: {'name': x[0], 'value': x[1]},
                env.items()
            ),
        )
        data = {
            'StackFileContent': stack_file_content,
            'SwarmID': self.swarm_id,
            'Name': stack_name,
            'Env': final_env if len(final_env) > 0 else []
        }
        logger.debug('create stack data: {}'.format(data))
        self.request(
            stack_url,
            self.METHOD_POST,
            data,
        )

    @plac.annotations(
        stack_id=('Stack id', 'option', 's'),
        endpoint_id=('Endpoint id', 'option', 'e'),
        stack_file=('Stack file', 'option', 'f'),
        env_file=('Environment Variable file', 'option'),
        prune=('Prune services', 'flag', 'p'),
        clear_env=('Clear all env vars', 'flag', 'c'),
    )
    def update_stack(self, stack_id, endpoint_id, stack_file='', env_file='',
                     prune=False, clear_env=False, *args):
        logger.info('Updating stack id={}').format(stack_id)
        stack_url = 'stacks/{}?endpointId={}'.format(
            stack_id,
            endpoint_id,
        )
        current = self.request(stack_url).json()
        stack_file_content = ''
        if stack_file:
            stack_file_content = open(stack_file).read()
        else:
            stack_file_content = self.request(
                'stacks/{}/file?endpointId={}'.format(
                    stack_id,
                    endpoint_id,
                )
            ).json().get('StackFileContent')

        env = self.extract_env(env_file, *args)

        if not clear_env:
            current_env = dict(
                map(
                    lambda x: (x.get('name'), x.get('value'),),
                    current.get('Env'),
                ),
            )
            current_env.update(env)
            env = current_env
        final_env = list(
            map(
                lambda x: {'name': x[0], 'value': x[1]},
                env.items()
            ),
        )
        data = {
            'Id': stack_id,
            'StackFileContent': stack_file_content,
            'Prune': prune,
            'Env': final_env if len(final_env) > 0 else current.get('Env'),
        }
        logger.debug('update stack data: {}'.format(data))
        self.request(
            stack_url,
            self.METHOD_PUT,
            data,
        )

    @plac.annotations(
        name=('Name', 'option'),
        url=('URL', 'option'),
        authentication=('Use authentication', 'flag', 'a'),
        username=('Username', 'option'),
        password=('Password', 'option'),
    )
    def update_registry(self, id, name='', url='', authentication=False,
                        username='', password=''):
        assert not authentication or (authentication and username and password)
        registry_url = 'registries/{}'.format(id)
        current = self.request(registry_url).json()
        data = {
            'Name': name or current.get('Name'),
            'URL': url or current.get('URL'),
            'Authentication': authentication,
            'Username': username or current.get('Username'),
            'Password': password,
        }
        self.request(
            registry_url,
            self.METHOD_PUT,
            data,
        )

    @plac.annotations(
        printc=('Print response content', 'flag', 'p'),
    )
    def request(self, path, method=METHOD_GET, data='', printc=False):
        url = '{}api/{}'.format(
            self.base_url,
            path,
        )
        session = Session()
        request = Request(method, url)
        prepped = request.prepare()
        if data:
            prepped.headers['Content-Type'] = 'application/json'
            try:
                json.loads(data)
                prepped.body = data
            except Exception:
                prepped.body = json.dumps(data)
            prepped.headers['Content-Length'] = len(prepped.body)
        if self.jwt:
            prepped.headers['Authorization'] = 'Bearer {}'.format(self.jwt)
        response = session.send(prepped, proxies=self.proxies, verify=False)
        logger.debug('request response: {}'.format(response.content))
        response.raise_for_status()
        if printc:
            print(response.content.decode())
        return response

    @plac.annotations(
        command=(
            'Command',
            'positional',
            None,
            str,
            COMMANDS,
        ),
        debug=('Enable debug mode', 'flag', 'd'),
        local=('Use local/dir configuration', 'flag', 'l'),
    )
    def main(self, command, debug=False, local=local, *args):
        if debug:
            logging.basicConfig(level=logging.DEBUG)
        self.local = local
        self.load()
        self.proxies = {}
        if command == self.COMMAND_CONFIGURE:
            plac.call(self.configure, args)
        elif command == self.COMMAND_LOGIN:
            plac.call(self.login, args)
        elif command == self.COMMAND_CREATE_STACK:
            plac.call(self.create_stack, args)
        elif command == self.COMMAND_UPDATE_STACK:
            plac.call(self.update_stack, args)
        elif command == self.COMMAND_CREATE_OR_UPDATE_STACK:
            plac.call(self.create_or_update_stack, args)
        elif command == self.COMMAND_GET_STACK_ID:
            plac.call(self.get_stack_id, args)
        elif command == self.COMMAND_UPDATE_REGISTRY:
            plac.call(self.update_registry, args)
        elif command == self.COMMAND_REQUEST:
            plac.call(self.request, args)
