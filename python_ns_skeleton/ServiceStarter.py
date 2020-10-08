from tornado import websocket, web, ioloop
from threading import Thread
from python_ns_skeleton import nsSkeletonMessaging
from python_ns_skeleton.nsSkeletonMessaging import logger
from python_ns_skeleton.nsSkeletonMessaging import configClass
import uuid
import argparse, msgpack
import json, base64


class WebSockethandler(websocket.WebSocketHandler):
    clients = {}

    def open(self):
        self.id = str(uuid.uuid4())
        logger.info('[WebSocket]: New client is connected: {}'.format(self.request.remote_ip))
        WebSockethandler.clients[self.id] = self

    def on_message(self, message):
        logger.info('[WebSocket]: New message from {} received'.format(self.request.remote_ip))
        logger.debug('[WebSocket]: New message is {}'.format(message))
        if ServiceStarter.ws_callbacks:
            parsed_msg = json.loads(message)
            if parsed_msg['methodName'] in ServiceStarter.ws_callbacks:
                ServiceStarter.ws_callbacks[parsed_msg['methodName']](self, parsed_msg['data'])
        else:
            ServiceStarter.__override_on_message__(self, message)

    def on_close(self):
        WebSockethandler.clients.pop(self.id)
        logger.info('[WebSocket]: Client is disconnected: {}'.format(self.request.remote_ip))


class HttpHandler(web.RequestHandler):
    def set_default_headers(self):
        self.set_header("Access-Control-Allow-Origin", "*")

    def get(self, url_path):
        logger.info('[HTTP]: Get request from {} was received'.format(self.request.remote_ip))
        try:
            msgList = msgpack.unpackb(base64.b64decode(url_path))
            methodName = msgList[0].decode('latin1')  # методНейм приводим к виду через котороый можно обратиться в словарь
            args = msgpack.unpackb(msgList[1], encoding='latin1')  # args from received message
            flag = msgList[2]
        except Exception as ex:
            logger.error('Cannot unpack received message')
            logger.debug('Raised exception - {}:{}'.format(type(ex), ex.__str__()))
            raise Exception('UnpackError')
        if flag is True:
            replyMsg, replyLen = nsSkeletonMessaging.nsSkeletonListener.runCallbackFunc(methodName, args, flag)
            try:
                logger.info('Send response message to client')
                self.write(base64.b64encode(replyMsg))
            except Exception as ex:
                logger.error('Cannot send response message')
                logger.debug('Raised exception - {}:{}'.format(type(ex), ex.__str__()))
                raise Exception('SendError')


class ServiceStarter():

    ws_callbacks = {}

    def __init__(self, serviceName):
        self.cmd_params = self.unparsed = None
        logger.info('Create "ServiceStarter" instance for serviceName {}'.format(serviceName))
        try:
            logger.info('Read local config file {}'.format(serviceName))
            self.local_config = configClass.getLocalConfig(serviceName)
        except:
            logger.error('Cannot read local config file')
            raise Exception
        try:
            logger.info('Read global config for {}'.format(serviceName))
            self.global_config = configClass.getGlobalConfig(serviceName)
        except:
            logger.error('Cannot read global config file')
            raise Exception
        try:
            logger.info('Try parse input cmd args')
            self.parseArgs()
        except Exception as ex:
            logger.error('Cannot parse input cmd args')
            logger.debug('Raised exception - {}:{}'.format(type(ex), ex.__str__()))
            raise Exception
        try:
            logger.info('Try create "Listener" for {}'.format(serviceName))
            self.nsServer = nsSkeletonMessaging.nsSkeletonListener(
                configClass.getListenerAddress(serviceName),
                self.cmd_params.get('port')[0] or configClass.getListenerPort(serviceName))
        except Exception as ex:
            logger.error('Cannot create "Listener" instance')
            logger.debug('Raised exception - {}:{}'.format(type(ex), ex.__str__()))
            raise Exception
        try:
            logger.info('Try create WS Handler')
            self.wsHandler = WebSockethandler
        except Exception as ex:
            logger.error('Cannot create WS Handler')
            logger.debug('Raised exception - {}:{}'.format(type(ex), ex.__str__()))
            raise Exception
        try:
            logger.info('Try create HTTP Handler')
            self.httpHandler = HttpHandler
        except Exception as ex:
            logger.error('Cannot create HTTP Handler')
            logger.debug('Raised exception - {}:{}'.format(type(ex), ex.__str__()))
            raise Exception

    def parseArgs(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('-n','--name', dest='name')
        parser.add_argument('-p','--port', dest='port', type=int)
        if self.local_config.get('param-keys'):
            for arg in self.local_config['param-keys']:
                if(not arg.get('key')):
                    logger.error('No key was found for this arg: {}'.format(arg))
                    continue
                if(not arg.get('long-key')):
                    logger.error('No long-key was found for arg with key {}'.format(arg.get('key')))
                    continue
                parser.add_argument('-'+arg.get('key'), '--'+arg.get('long-key'), action='store_true' if not arg.get('isRequired') else None)
        params, self.unparsed = parser.parse_known_args()
        self.cmd_params = vars(params)
        for key in self.cmd_params:
            val_type = type(self.cmd_params[key])
            self.cmd_params[key] = str(self.cmd_params[key]).split(' ')
            if val_type != str:
                self.cmd_params[key][0] = eval(self.cmd_params[key][0])

    def __ws_loop(self, loop, host, port):
        try:
            logger.info('[WebSocket]: Try start listen WebSocket on {}:{}'.format(host, port))
            app = web.Application([(r'/ws', WebSockethandler), ])
            app.listen(port,  host)
            loop.start()
        except Exception as ex:
            logger.error('[WebSocket]: Cannot start WebSocket')
            logger.debug('[WebSocket]: Raised exception - {}:{}'.format(type(ex), ex.__str__()))
            raise Exception

    def startWSServer(self, host, port):
        ws_loop = ioloop.IOLoop.instance()
        self.nsServer.registerShutdownCallback(ws_loop.stop)
        t = Thread(target=self.__ws_loop, args=(ws_loop, host, port))
        t.start()

    def __http_loop(self, loop, host, port):
        try:
            logger.info('[HTTP]: Try start listen HTTP on {}:{}'.format(host, port))
            app = web.Application([(r'/(.*)', HttpHandler), ])
            app.listen(port, host)
            loop.start()
        except Exception as ex:
            logger.error('[HTTP]: Cannot start HTTP Handler')
            logger.debug('[HTTP]: Raised exception - {}:{}'.format(type(ex), ex.__str__()))
            raise Exception

    def startHttpServer(self, host, port):
        http_loop = ioloop.IOLoop.instance()
        self.nsServer.registerShutdownCallback(http_loop.stop)
        t = Thread(target=self.__http_loop, args=(http_loop, host, port))
        t.start()

    def registerWebSocketCallback(self, methodName, func):
        ServiceStarter.ws_callbacks[methodName] = func

    @staticmethod
    def __override_on_message__(self, message):
        return

    def setWebSocketOnMsg(self, func):
        ServiceStarter.__override_on_message__ = func
