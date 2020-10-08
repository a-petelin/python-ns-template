import json
import logging
import sys, os

GLOBAL_CONFIG_FILE_PATH = '/etc/nanoservices/global.conf.json'
DEFAULT_CLIENT_TIMEOUT = 4000  # секунд
DEFAULT_QUEUE_SIZE = 25
DEFAULT_LOGGING_LEVEL = 'ERROR'
DEFAULT_LOGGING_FORMAT = '%(filename)-30s %(funcName)-20s [LINE:%(lineno)-3d] # %(levelname)-8s  [%(asctime)s] %(message)s'
DEFAULT_LOGGING_OUTPUT = sys.stderr
DEFAULT_CONNECT_TIMEOUT = 100 # секунд
LOGGER_MESSAGE_SIZE = 50 # кол-во символов полученного от клиента сообщения выводимых логгером (None - неограничено)

logger = logging.Logger(__name__, DEFAULT_LOGGING_LEVEL) # logger с именем запускаемого скрипта
defaultHandler = logging.StreamHandler(DEFAULT_LOGGING_OUTPUT) # по умолчанию stderr
defaultFormatter = logging.Formatter(DEFAULT_LOGGING_FORMAT)
defaultHandler.setFormatter(defaultFormatter)
logger.addHandler(defaultHandler)

class Configuration:

    def __init__(self, configFilePath = GLOBAL_CONFIG_FILE_PATH):
        try:
            with open(configFilePath) as config:
                self.configData = json.load(config)['known-services']
        except ValueError:
            logger.error('Cannot parse json config file. Incorrect json file')
        except (OSError, IOError):
            logger.error('Cannot open json config file. Incorrect path to file')
        except:
            logger.error('Cannot open or parsing json file.')

    def __getDataFromJson(self, serviceName, jsonKey, fieldType): # приватный
        logger.info('Try get {} value from configuration file for service {}'.format(jsonKey, serviceName))
        serviceJson = None
        try:
            for value in self.configData:
                if value['service-name'] == serviceName:
                    serviceJson = value
                    break
            if (serviceJson):
                if jsonKey == 'all':
                    return serviceJson
                requestedField = serviceJson[jsonKey]
                if type(requestedField) is not fieldType:
                    logger.error('Illegal type of field "{}" (should be {})'.format( jsonKey, fieldType))
                    raise Exception
            else:
                logger.error('Cant find service {} in global config'.format(serviceName))
                raise Exception

        except:
            logger.error('Cannot parse json config file. Field "{}" for service "{}" doesnt exist'.format(jsonKey,serviceName))
            raise Exception
        logger.info('Return value is {}'.format(requestedField))
        return requestedField

    def getListenerAddress(self, serviceName):
        return self.__getDataFromJson(serviceName, 'host', str)

    def getListenerPort(self, serviceName):
        return self.__getDataFromJson(serviceName, 'port', int)

    def getLocalConfig(self, serviceName):
        try:
            with open('{}/local/{}.conf.json'.format(os.path.dirname(GLOBAL_CONFIG_FILE_PATH),serviceName)) as config:
                configData = json.load(config)
        except ValueError:
            logger.error('Cannot parse json config file. Incorrect json file')
            raise Exception
        except (OSError, IOError):
            logger.error('Cannot open json config file. Incorrect path to file')
            raise Exception
        except:
            logger.error('Cannot open or parsing json file.')
            raise  Exception
        return configData

    def getGlobalConfig(self, serviceName):
        return self.__getDataFromJson(serviceName, 'all', dict)
