import argparse
import asyncio
import json
import logging
import socket
import sys


BUF_SIZE = 32 * 1024
FORMATTER = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
LOGGING_LEVEL = logging.INFO

logger = logging.getLogger(__name__)


class ConfigError(Exception):
    pass


class Config(object):

    cfgs_exlucded = ['config', 'log_file']

    def __init__(self, dic,  *args, **kwargs):
        self.__dict__ = dic
        self.check_all_confs()

    def check_non_confs(self):
        for cfg, val in self.__dict__.items():
            if not val and cfg not in self.cfgs_exlucded:
                raise ConfigError('{!r} was not configured'.format(cfg))

    def validate_ip(self, ip):
        try:
            lst = ip.split('.')
            if len(lst) == 4 and all(-1 < int(i) < 256 for i in lst):
                return True
        except ValueError:
            pass

    def validate_port(self, port):
        try:
            return 0 < port < 66536
        except TypeError:
            pass

    def check_server_ip(self):
        valid = self.validate_ip(self.server_ip)
        if not valid:
            raise ConfigError('Invalid server_ip {!r}'.format(self.server_ip))

    def check_server_port(self):
        valid = self.validate_port(self.server_port)
        if not valid:
            raise ConfigError(
                'Invalid server_port {!r}'.format(self.server_port)
            )


class ClientConfig(Config):

    def check_all_confs(self):
        self.check_non_confs()
        self.check_server_ip()
        self.check_server_port()
        self.check_client_ip()
        self.check_client_port()

    def check_client_ip(self):
        if not self.bind_ip.lower() == 'localhost':
            valid = self.validate_ip(self.bind_ip)
            if not valid:
                raise ConfigError('Invalid bind_ip {!r}'.format(self.bind_ip))

    def check_client_port(self):
        valid = self.validate_port(self.listen_port)
        if not valid:
            raise ConfigError(
                'Invalid listen_port {!r}'.format(self.listen_port)
            )


class ServerConfig(Config):

    def check_all_confs(self):
        self.check_non_confs()
        self.check_server_ip()
        self.check_server_port()


def parse_commands(name):
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', help='config file')
    parser.add_argument('-s', '--server_ip', help='server ip')
    parser.add_argument('-p', '--server_port', type=int, default=10000,
                        help='server port')
    if name == 'client':
        parser.add_argument('-b', '--bind_ip', default='127.0.0.1',
                            help='bind ip')
        parser.add_argument('-l', '--listen_port', type=int, default=7070,
                            help='listen port')
    parser.add_argument('-t', '--crt_file', default='ssl.crt', help='crt file')
    parser.add_argument('-k', '--key_file', default='ssl.key', help='key file')
    parser.add_argument('-v', '--log_level', default='info', help='log level')
    parser.add_argument('-f', '--log_file', help='log file')
    args = parser.parse_args()
    kwargs = dict(args._get_kwargs())

    if not args.config:  # no config file passed
        return kwargs

    # settings configured take precedence over arguments
    with open(args.config) as f:
        cfg = json.load(f)

    for key in kwargs:
        if key not in cfg:
            cfg[key] = kwargs[key]

    return cfg


def get_logging_config(format=FORMATTER, stream=sys.stderr, log_level=None,
                       log_file=None):

    try:
        level = getattr(logging, log_level.upper())
    except AttributeError:
        raise ConfigError('Unknow logging level {!r}'.format(log_level)) \
            from None

    cfg = dict(level=level, format=format, stream=stream, filename=log_file)
    key = 'filename' if not log_file else 'stream'
    cfg.pop(key)
    return cfg


@asyncio.coroutine
def write_and_drain(writer, data):
    writer.write(data)
    yield from writer.drain()


@asyncio.coroutine
def read_and_write(reader, writer, is_remote_writer):
    while True:
        try:
            data = yield from reader.read(BUF_SIZE)
        except Exception as e:
            logger.debug(e)
            if not is_remote_writer:
                return True
            data = None

        if not data:
            return

        try:
            yield from write_and_drain(writer, data)
        except Exception as e:
            logger.debug(e)
            if is_remote_writer:
                return True
            return


@asyncio.coroutine
def handle_tcp(reader, writer, r_reader, r_writer):
    l2r = asyncio.ensure_future(read_and_write(reader, r_writer, True))
    r2l = asyncio.ensure_future(read_and_write(r_reader, writer, False))
    futs = [l2r, r2l]

    for fut in asyncio.as_completed(futs):
        result = yield from fut
        if result:
            for f in futs:
                if not f.done():
                    f.set_result(None)
            return True


def clean_tasks(event_loop):
    tasks = asyncio.Task.all_tasks(loop=event_loop)
    try:
        for t in tasks:
            t.cancel()
    except:
        pass


def set_tcp_nodelay(transport):
    sock = transport.get_extra_info('socket')
    sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
