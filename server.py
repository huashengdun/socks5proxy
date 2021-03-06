import asyncio
import logging
import ssl
from common import (
    handle_tcp, parse_commands, ServerConfig, get_logging_config, clean_tasks,
    write_and_drain, set_tcp_nodelay, BUF_SIZE
)


logger = logging.getLogger('server')

CONNECT_TIMEOUT = 3


@asyncio.coroutine
def connect_to_dest(dest):
    fut = asyncio.open_connection(*dest)
    try:
        d_reader, d_writer = yield from asyncio.wait_for(
            fut, timeout=CONNECT_TIMEOUT
        )
    except Exception as e:
        logger.debug(e)
        return

    return d_reader, d_writer


@asyncio.coroutine
def serve(reader, writer):
    set_tcp_nodelay(writer)
    cli_addr = writer.get_extra_info('peername')
    logger.info('Connected from {}:{}'.format(*cli_addr))
    data = yield from reader.read(BUF_SIZE)
    host, data = data.split(b'\n', 1)
    hostname, port = host.decode('utf-8').split(':')
    dest = (hostname, int(port))
    logger.info('Connecting to {}:{}'.format(*dest))
    transport = yield from connect_to_dest(dest)

    while transport:
        d_reader, d_writer = transport
        set_tcp_nodelay(d_writer)
        if data:
            yield from write_and_drain(d_writer, data)
            data = None
        result = yield from handle_tcp(reader, writer, d_reader, d_writer)
        d_writer.close()
        if not result:
            writer.close()
            return
        transport = yield from connect_to_dest(dest)


def main():
    cmds = parse_commands(logger.name)
    conf = ServerConfig(cmds)
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.check_hostname = False
    ssl_context.load_cert_chain(conf.crt_file, conf.key_file)
    log_cfg = get_logging_config(
        log_level=conf.log_level, log_file=conf.log_file
    )
    logging.basicConfig(**log_cfg)
    logger.debug(cmds)

    event_loop = asyncio.get_event_loop()
    factory = asyncio.start_server(
        serve, host=conf.server_ip, port=conf.server_port, ssl=ssl_context
    )
    logger.info(
        'Serving on {}:{}'.format(conf.server_ip, conf.server_port)
    )
    server = event_loop.run_until_complete(factory)

    try:
        event_loop.run_forever()
    except KeyboardInterrupt:
        clean_tasks(event_loop)
    finally:
        logger.debug('Closing server')
        server.close()
        event_loop.run_until_complete(server.wait_closed())
        logger.debug('Closing event loop')
        event_loop.close()


if __name__ == '__main__':
    main()
