import msgpack
import logging
import socket
import ipaddress
import traceback
from threading import Thread
from python_ns_skeleton import Configuration    # модуль работы с конфиг. файлом

configClass = Configuration.Configuration()

# создание логгера и настройка формата вывода логов
logger = logging.Logger(__name__, Configuration.DEFAULT_LOGGING_LEVEL)  # logger с именем запускаемого скрипта
formatter = logging.Formatter(Configuration.DEFAULT_LOGGING_FORMAT)
handler = logging.StreamHandler(Configuration.DEFAULT_LOGGING_OUTPUT)
handler.setFormatter(formatter)
logger.addHandler(handler)

class nsSkeletonListener(Thread):
    callback_dict = {}
    def __init__(self, serverBindAddress, serverBindPort):
        self.__shutdown_callbacks = []
        self.waiting_flag = True
        try:
            logger.debug('Init thread for nsSkeletonServer class')
            super().__init__(name='nsSkeletonServer')
            self.run = self.__run
        except:
            logger.error('Cannot init thread for nsSkeletonServer class')
            raise Exception('ThreadInitError')
        # приватные поля класса
        try:
            self.__bindAddress = socket.gethostbyname(serverBindAddress)
        except:
            if serverBindAddress != '':
                logger.error('Incorrect nsSkeletonServer address or unknown dns')
                raise Exception('ServerAddressError')
            else:
                self.__bindAddress = serverBindAddress
        self.__serverPort = serverBindPort
        try:
            if (type(ipaddress.ip_address(self.__bindAddress))==ipaddress.IPv4Address):
                logger.info('Creating server with IPv4 address')
                addressFamily = socket.AF_INET
            else:
                logger.info('Creating server with IPv6 address')
                addressFamily = socket.AF_INET6
        except:
            if self.__bindAddress != '':
                logger.error('Incorrect nsSkeletonServer address, its not ip-address')
                raise Exception('ServerAddressError')
            else:
                addressFamily = socket.AF_INET # при получении serverBindAddress = '', слушаются все интерфейсы на IPv4
        try:
            self.__createServer(addressFamily)
        except:
            logger.error('Cannot create server')
            raise Exception('CreateServerError')
        try:
            logger.debug('Try start created thread')
            self.start() # запуск потока сервера
        except Exception as ex:
            logger.error('Cannot start created thread')
            logger.debug('Raised exception - {}:{}'.format(type(ex), ex.__str__()))

    def __createServer(self, addressFamily): # бинд сокета сервера на адрес __bindAddress и семейство addressFamily (приватный)
        try:
            self.__serverSocket = socket.socket(addressFamily, socket.SOCK_STREAM)
            self.__serverSocket.bind((self.__bindAddress, self.__serverPort))
        except Exception as ex:
            logger.error('Cannot create server and bind "server address:port" {}:{}.'
                          .format(self.__bindAddress, self.__serverPort))
            logger.debug('Raised exception - {}:{}'.format(type(ex), ex.__str__()))
            raise Exception
        logger.info('Server created. "server address:port" {}:{}.'.format(self.__bindAddress, self.__serverPort))

    def __run(self):
        logger.info('Start listening server socket')
        try:
            logger.debug('Prepare to listening')
            self.__serverSocket.listen(Configuration.DEFAULT_QUEUE_SIZE)  # кол-во клиентов в очереди (которые подключились, но для них не был вызван accept())
            logger.debug('Listening start')
        except Exception as ex:
            logger.info('Cannot start listening server socket')
            logger.debug('Raised exception - {}:{}'.format(type(ex), ex.__str__()))
            raise Exception('ListenError')
        while self.waiting_flag:
            try:
                logger.debug('Waiting for client connection')
                clientSocket, clientAddrPort = self.__serverSocket.accept()
                if (not self.waiting_flag):
                    return
                logger.info('New client is connected.')
                if clientSocket.family == socket.AF_INET6:
                    logger.debug('Connected client use IPv6 address')
                    clientAddrPort = (clientAddrPort[0], clientAddrPort[1]) # при подключении клиента с IPv6, clientAddrPort = (host, port, flowinfo, scopeid), мы берем только host и port
                logger.info('"client address, port" {}'.format(clientAddrPort))
            except Exception as ex:
                logger.error('Client tried to connect to server, but connection refused')
                logger.debug('Raised exception - {}:{}'.format(type(ex), ex.__str__()))
                continue
            try:
                logger.debug('Try create a thread for new client')
                newThread = self.__ClientThread(clientAddrPort, clientSocket, self.shutdown)
                logger.debug('New thread created successfully')
            except Exception as ex:
                logger.error('Cannot create thread for new client')
                logger.debug('Raised exception - {}:{}'.format(type(ex), ex.__str__()))
                continue
            try:
                logger.debug('Try start created thread')
                newThread.start() # запуск потока подключенного клиента
            except Exception as ex:
                logger.error('Cannot start created thread')
                logger.debug('Raised exception - {}:{}'.format(type(ex), ex.__str__()))
                continue

    def getServerAddress(self):
        """ Возвращает IP адрес сервера в формате строки """
        return self.__bindAddress

    def getServerPort(self):
        """ Возвращает TCP порт сервера в формате числа """
        return self.__serverPort

    def shutdown(self):
        logger.debug('Try shutdown server')
        self.waiting_flag = False
        # нужно для того, чтобы у сервера отработал accept(), а затем мы корректно вышли из цикла
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((self.__bindAddress, self.__serverPort))
        for callback in self.__shutdown_callbacks:
            callback()

    def registerCallback(self, callbackFunc, methodName):
        nsSkeletonListener.callback_dict[methodName] = callbackFunc

    def registerShutdownCallback(self, callback):
        self.__shutdown_callbacks.append(callback)


    class __ClientThread(Thread):  # класс для каждого подключенного клиента (приватный)

        def __init__(self, clientAddrPort, clientSocket, shutdown_callback):
            self.clientAddress, self.clientPort = clientAddrPort
            self.main_server_shutdown = shutdown_callback
            logger.debug('FROM [{}:{}]. Init thread for ClientThread class'.format(self.clientAddress,self.clientPort))
            Thread.__init__(self, daemon=True)
            self.clientSocket = clientSocket
            try:
                logger.debug('FROM [{}:{}].Set timeout value from config'.format(self.clientAddress,self.clientPort))
                self.clientSocket.settimeout(Configuration.DEFAULT_CLIENT_TIMEOUT) # таймаут ожидания данных для подключенного клиента
            except:
                logger.error('FROM [{}:{}].Incorrect "client timeout" value in config'.format(self.clientAddress,self.clientPort))
                raise Exception

        def run(self):
            logger.debug('FROM [{}:{}].Start client message waiting cycle.'.format(self.clientAddress,self.clientPort))
            msg_len = self.clientSocket.recv(4)
            if not msg_len:
                logger.error('FROM [{0}:{1}].Cannot receive message length. Break client cycle'.format(self.clientAddress, self.clientPort))
                raise Exception
            try:
                logger.debug('FROM [{}:{}].Convert received msg length to int'.format(self.clientAddress, self.clientPort))
                msg_len_int = int.from_bytes(msg_len, byteorder='big')
                logger.debug('FROM [{}:{}].Msg length is {}'.format(self.clientAddress, self.clientPort, msg_len_int))
            except:
                logger.error('FROM [{}:{}].Cannot convert received message length to int'.format(self.clientAddress, self.clientPort))
                raise Exception
            try:
                data = self.clientSocket.recv(msg_len_int) # получение из сокета куска сообщения
                logger.info('FROM [{}:{}].Received data is {}'.format(self.clientAddress, self.clientPort, data[:Configuration.LOGGER_MESSAGE_SIZE]))
            except Exception as ex:
                logger.error('FROM [{0}:{1}].Cannot receive data from client {0}:{1} '.format(self.clientAddress, self.clientPort))
                logger.debug('Raised exception - {}:{}'.format(type(ex), ex.__str__()))
                raise Exception('ReceiveError')
            logger.info('Success get message. Run checking function')
            self.checkMessageAndCallback(data)

        def checkMessageAndCallback(self, bytesReceivedData): # проверка полученного сообщения, если корректный - вызов callbackFunc
            try:
                logger.debug('Try unpack received msg')
                msgList = msgpack.unpackb(bytesReceivedData)
                methodName = msgList[0].decode('latin1')  # методНейм приводим к виду через котороый можно обратиться в словарь
                args = msgpack.unpackb(msgList[1], encoding='latin1')  # args from received message
                flag = msgList[2]
            except Exception as ex:
                logger.error('Cannot unpack received message')
                logger.debug('Raised exception - {}:{}'.format(type(ex), ex.__str__()))
                raise Exception('UnpackError')
            logger.debug('Received message: {}'.format(str(msgList)[:Configuration.LOGGER_MESSAGE_SIZE]))
            logger.debug('Parsed message: {}, {}, {}'.format(methodName, str(args)[:Configuration.LOGGER_MESSAGE_SIZE], flag))
            if methodName == 'shutdown':
                self.main_server_shutdown()
                return
            if flag is True:
                replyMsg, replyLen = nsSkeletonListener.runCallbackFunc(methodName, args, flag)
                try:
                    logger.debug('Send message: {}'.format(replyLen + replyMsg[:Configuration.LOGGER_MESSAGE_SIZE]))
                    logger.info('Send response message to client')
                    self.clientSocket.sendall(replyLen + replyMsg)
                except Exception as ex:
                    logger.error('Cannot send response message')
                    logger.debug('Raised exception - {}:{}'.format(type(ex), ex.__str__()))
                    raise Exception('SendError')
            else:
                nsSkeletonListener.runCallbackFunc(methodName, args, flag)

    @staticmethod
    def runCallbackFunc(methodName, args, flag):
        if flag is True:
            logger.info('Client wait response')
            if methodName in nsSkeletonListener.callback_dict:
                responseFlag = True
                try:
                    logger.info('Call method: {} with args: {}'.format(methodName, str(args)[:Configuration.LOGGER_MESSAGE_SIZE]))
                    replyText = msgpack.packb(nsSkeletonListener.callback_dict[methodName](args), encoding = 'latin1')
                except Exception as ex:
                    logger.error('Called method raise exception - {}:{}'.format(type(ex), ex.__str__()))
                    replyText = msgpack.packb([-32000, traceback.format_exc(), []], encoding = 'latin1')
                    responseFlag = False
            else:
                logger.warning('Cannot find method {} in callbackDict'.format(methodName))
                raise Exception('SearchError')
            try:
                logger.info('Try pack response message')
                replyMsg = msgpack.packb([responseFlag, replyText], use_bin_type = True)
                replyLen = len(replyMsg).to_bytes(4, byteorder='big', signed=True)
                return replyMsg, replyLen
            except Exception as ex:
                logger.error('Cannot pack response message')
                logger.debug('Raised exception - {}:{}'.format(type(ex), ex.__str__()))
                raise Exception
        else:
            logger.info('Client doesnt wait for response')
            if methodName in nsSkeletonListener.callback_dict:
                try:
                    logger.info('Call method: {} with args: {}'.format(methodName, str(args)[:Configuration.LOGGER_MESSAGE_SIZE]))
                    nsSkeletonListener.callback_dict[methodName](args)
                except Exception as ex:
                    logger.error('Called method raise exception - {}:{}'.format(type(ex), ex.__str__()))
                    raise Exception


class nsSkeletonSender:

    def send(self, serviceName, methodName, args, flag, isComplexServiceName = False):
        serviceJson = None
        if isComplexServiceName:
            [serviceName, servicePort] = serviceName.split(':')
        for value in configClass.configData:
            if value['service-name'] == serviceName:
                serviceJson = value
                break
        if not serviceJson:
            logger.error('Cannot find service: {} in config'.format(serviceName))
            raise Exception('SearchError')
        try:
            serviceHost = serviceJson['host']
            if not isComplexServiceName:
                servicePort = serviceJson['port']
        except:
            logger.error('Cannot parse config. No "host"/"port" keys')
            raise Exception('SearchError')
        try:
            logger.debug('Call methodName {} with args {} on service {}'.format(methodName, str(args)[:Configuration.LOGGER_MESSAGE_SIZE], serviceName))
            logger.info('Try pack sending data')
            argsb = msgpack.packb(args, use_bin_type=True)
            sendList = msgpack.packb([methodName, argsb, flag], use_bin_type=True)
            msgLen = (len(sendList).to_bytes(4, byteorder='big', signed=True))
        except Exception as ex:
            logger.error('Cannot pack sending data')
            logger.debug('Raised exception - {}:{}'.format(type(ex), ex.__str__()))
            raise Exception('PackError')
        message = msgLen + sendList

        response = self.__createSocketAndSend(serviceHost, int(servicePort), message, flag)

        if flag == True:
            return self.unpackMessage(response)

    def __createSocketAndSend(self, serviceHost, servicePort, message, flag):
        if not serviceHost or type(serviceHost) is not str:
            logger.error('Illegal type of field "serviceHost" (should be string) or its empty')
            raise Exception('TypeError')
        if not servicePort or type(servicePort) is not int:
            logger.error('Illegal type of field "servicePort" (should be int) or its empty')
            raise Exception('TypeError')
        try:
            bindAddress = socket.gethostbyname(serviceHost)
        except:
            if serviceHost != '':
                logger.error('Incorrect nsSkeletonServer address or unknown dns')
                raise Exception('ServerAddressError')
            else:
                bindAddress = serviceHost
        try:
            if (type(ipaddress.ip_address(bindAddress))==ipaddress.IPv4Address):
                logger.info('Creating server with IPv4 address')
                addressFamily = socket.AF_INET
            else:
                logger.info('Creating server with IPv6 address')
                addressFamily = socket.AF_INET6
        except:
            if bindAddress != '':
                logger.error('Incorrect nsSkeletonServer address, its not ip-address')
                raise Exception('ServerAddressError')
            else:
                addressFamily = socket.AF_INET # при получении serverBindAddress = '', слушаются все интерфейсы на IPv4
        try:
            logger.debug('Creating client socket with address family:.'.format(str(addressFamily)))
            __clientSocket = socket.socket(addressFamily, socket.SOCK_STREAM)
            __clientSocket.settimeout(Configuration.DEFAULT_CONNECT_TIMEOUT)
        except Exception as ex:
            logger.error('Cannot create client socket')
            logger.debug('Raised exception - {}:{}'.format(type(ex), ex.__str__()))
            raise Exception
        try:
            logger.info('[TO {}:{}]. Try send message: {}'.format(serviceHost, servicePort, message[:Configuration.LOGGER_MESSAGE_SIZE]))
            __clientSocket.connect((serviceHost, servicePort))
            __clientSocket.sendall(message)
        except:
            logger.error('[TO {}:{}].Cannot send message'.format(serviceHost, servicePort))
            raise Exception

        if flag == True:
            msg_len = __clientSocket.recv(4)
            if not msg_len:
                logger.error('Cannot receive message length. Break waiting cycle')
                raise Exception
            try:
                logger.debug('Convert received msg length to int')
                msg_len_int = int.from_bytes(msg_len, byteorder='big')
                logger.debug('Msg length is {}'.format(msg_len_int))
            except:
                logger.error('Cannot convert received message length to int')
                raise Exception
            try:
                data = __clientSocket.recv(msg_len_int)  # получение из сокета сообщения
                logger.info('Received data is {}'.format(data[:Configuration.LOGGER_MESSAGE_SIZE]))
            except Exception as ex:
                logger.error('Cannot receive data')
                logger.debug('Raised exception - {}:{}'.format(type(ex), ex.__str__()))
                raise Exception('ReceiveError')
            logger.info('Success get message')
            return data

    def unpackMessage(self, message):
        try:
            logger.info('Try unpack received message')
            self.unpackedMsg = msgpack.unpackb(message)
            response_flag = self.unpackedMsg[0]
            result = msgpack.unpackb(self.unpackedMsg[1], encoding='latin1')
            logger.debug('Unpacked message: {}'.format(result))
        except:
            logger.error('Cannot unpack received message')
            raise Exception
        if response_flag == False:
            raise Exception(result[1])
        return result
