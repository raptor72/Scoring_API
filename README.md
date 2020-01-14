# Scoring_API

Приложение - http-сервер, обрабатыващий POST запросы и возвращающий оценку или список интересов пользователей. Сервер имеет два метода работы **online_score** и **clients_interests**.

Серверу можно указать на каком порту работать через переменную `--port`. Если параметр не указан, то будет использован порт 8080.  
Файл в который будут писаться логи приложения задается через опцию `--log`. Если он не указан, то все сообщения будут выводится в stdout. 
#### Пример запуска:

    $ python api.py --port 8090 --log "path/file"

#### Пример тестирования:

    $ python test.py


#### Метод online_score.
Аргументы:
* phone - строка или число, длиной 11, начинается с 7, опционально, может быть пустым
* email - строка, в которой есть @, опционально, может быть пустым
* first_name - строка, опционально, может быть пустым
* last_name - строка, опционально, может быть пустым
* birthday - дата в формате DD.MM.YYYY, с которой прошло не больше 70 лет, опционально, может быть пустым
* gender - число 0, 1 или 2, опционально, может быть пустым


Валидация аругементов:

аргументы валидны, если валидны все поля по отдельности и если присутсвует хоть одна пара phone-email, first name-last name, gender-birthday с непустыми значениями.


Контекст:

В словарь контекста должна прописываться запись "has" - список полей, которые были не пустые для данного запроса


Ответ:

В ответ выдается число, полученное вызовом функции get_score (см. scoring.py). Но если пользователь админ (см. check_auth), то нужно всегда отавать 42.

#### Примеры вызовов валидного запроса online_score:

    curl -X POST -H "Content-Type: application/json" -d '{"account": "horns&hoofs", "login": "h&f", "method": "online_score", "token": "55cc9ce545bcd144300fe9efc28e65d415b923ebb6be1e19d2750a2c03e80dd209a27954dca045e5bb12418e7d89b6d718a9e35af34e14e1d5bcd5a08f21fc95", "arguments": {"phone": "79177002040", "email": "ipetrov@gmail.com", "first_name": "Ivan", "last_name": "Petrov", "birthday": "01.01.1990", "gender": 1}}' http://127.0.0.1:8080/method/

    curl -X POST -H "Content-Type: application/json" -d '{"account": "horns&hoofs", "login": "h&f", "method": "online_score", "token": "55cc9ce545bcd144300fe9efc28e65d415b923ebb6be1e19d2750a2c03e80dd209a27954dca045e5bb12418e7d89b6d718a9e35af34e14e1d5bcd5a08f21fc95", "arguments": {"phone": "79177002040", "email": "ipetrov@gmail.com", "first_name": "Ivan", "birthday": "01.01.1990"}}' http://127.0.0.1:8080/method/

Примеры соответствующих ответов:

    {"code": 200, "response": {"score": 5.0}}
    
    {"code": 200, "response": {"score": 3.0}}
    
#### Метод clients_interests.
Аргументы:
* client_ids - массив числе, обязательно, не пустое
* date - дата в формате DD.MM.YYYY, опционально, может быть пустым

#### Пример вызова валидного запроса clients_interests:

    curl -X POST -H "Content-Type: application/json" -d '{"account": "horns&hoofs", "login": "h&f", "method": "clients_interests", "token": "55cc9ce545bcd144300fe9efc28e65d415b923ebb6be1e19d2750a2c03e80dd209a27954dca045e5bb12418e7d89b6d718a9e35af34e14e1d5bcd5a08f21fc95", "arguments": {"client_ids": [1,2,3,4], "date": "10.01.2020"}}' http://127.0.0.1:8080/method/
    
Пример ответа:

    {"code": 200, "response": {"1": ["tv", "geek"], "2": ["tv", "books"], "3": ["hi-tech", "cinema"], "4": ["music", "geek"]}}
