Отправить сообщение:
___
nsSkeletonMessaging.nsSkeletonSender().send(serviceName, methodName, args, flag, opt:host, opt:port)

* serviceName - имя сервиса, которому адресовано сообщение ("worker_service", если нужно отправить на конкретный host port)
* methodName - имя метода, вызываемого на сервисе
* args - аргументы для вызываемого метода
* flag - флаг ожидания ответа от сервиса
* host - хост, на котором сидит вызываемый сервис (опционально)
* port - порт, на котором сидит вызываемый сервис (опционально)

Создание экземпляра слушателя для сервиса 
___
ServiceStarter.ServiceStarter(serviceName, opt:host, opt:port)

* serviceName - имя сервиса, для которога запускаем слушателя ("worker_service" или ничего не передаем, если запускаем на конкретном host port)
* host - хост, на котором запускаем слушателя (опционально)
* port - порт, на котором запускаем слушателя (опционально)
   

Чтобы создать .whl пакет: python3 setup.py bdist_wheel
