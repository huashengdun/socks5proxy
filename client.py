import asyncio
import functools
import logging
import socket
import ssl
import struct

from common import (ClientConfig, get_logging_config, handle_tcp,
                    parse_commands, write_and_drain, clean_tasks)

ADDRTYPE_IPV4 = 1
ADDRTYPE_HOST = 3

logger = logging.getLogger('client')

ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
ssl_context.check_hostname = False


def parse_header(data):
    addrtype = ord(data[0:1])
    dest_addr = None
    dest_port = None
    header_length = 0
    if addrtype == ADDRTYPE_IPV4:
        if len(data) >= 7:
            dest_addr = socket.inet_ntoa(data[1:5])
            dest_port = struct.unpack('>H', data[5:7])[0]
            header_length = 7
        else:
            logger.warn('header is too short')
    elif addrtype == ADDRTYPE_HOST:
        if len(data) > 2:
            addrlen = ord(data[1:2])
            if len(data) >= 2 + addrlen:
                dest_addr = data[2:2 + addrlen]
                dest_port = struct.unpack('>H', data[2 + addrlen:4 +
                                                     addrlen])[0]
                header_length = 4 + addrlen
            else:
                logger.warn('header is too short')
        else:
            logger.warn('header is too short')
    else:
        logger.warn('unsupported addrtype %s' % addrtype)

    if dest_addr is None:
        return None
    elif type(dest_addr) == str:
        dest_addr = dest_addr.encode()

    return addrtype, dest_addr, dest_port, header_length


@asyncio.coroutine
def request(event_loop, reader, writer):
    address = writer.get_extra_info('peername')
    logger.info('connected from {}:{}'.format(*address))
    data = yield from reader.read(256)
    yield from write_and_drain(writer, b"\x05\x00")
    data = yield from reader.read(256)
    mode = ord(data[1:2])
    if mode != 1:
        return
    result = parse_header(data[3:])
    reply = b"\x05\x00\x00\x01"
    r_reader, r_writer = yield from asyncio.open_connection(
        host=conf.server_ip, port=conf.server_port, ssl=ssl_context
    )
    local = r_writer.get_extra_info('sockname')
    reply += socket.inet_aton(local[0]) + struct.pack(">H", local[1])
    yield from write_and_drain(writer, reply)
    # socks5 connection opened

    logger.info(result[1])
    logger.info(result[2])
    dest = result[1] + b':' + str(result[2]).encode()
    logger.info('connecting to {}'.format(dest.decode()))
    yield from write_and_drain(r_writer, dest)

    yield from handle_tcp(event_loop, reader, writer, r_reader, r_writer)
    writer.close()
    r_writer.close()


def run():
    event_loop = asyncio.get_event_loop()
    factory = asyncio.start_server(
        functools.partial(request, event_loop),
        host=conf.bind_ip, port=conf.listen_port
    )
    logger.info('server address {}:{}'.format(
        conf.server_ip, conf.server_port)
    )
    logger.info('listening on {}:{}'.format(
        conf.bind_ip, conf.listen_port)
    )
    server = event_loop.run_until_complete(factory)

    try:
        event_loop.run_forever()
    except KeyboardInterrupt:
        clean_tasks(event_loop)
    finally:
        logger.debug('closing client')
        server.close()
        event_loop.run_until_complete(server.wait_closed())
        logger.debug('closing event loop')
        event_loop.close()


if __name__ == '__main__':
    cmds = parse_commands()
    conf = ClientConfig(cmds)
    ssl_context.load_verify_locations(conf.crt_file)
    log_cfg = get_logging_config(
        log_level=conf.log_level, log_file=conf.log_file
    )
    logging.basicConfig(**log_cfg)
    logger.debug(cmds)
    run()
