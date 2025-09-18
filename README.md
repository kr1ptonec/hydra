# Руководство по использованию Hydra

## Содержание

- [Переменные окружения](#environments)
- [Методы](#Методы)
    - [init](#init)
    - [unseal](#unseal)
    - [inject](#inject)
    - [okd-sync](#okd-sync)
    - [backup](#backup)
    - [help](#help)

---

## Environments

| Переменная             | Обязательна | По умолчанию | Требуется для                | Описание                                                   |
|------------------------|-------------|--------------|-----------------------------|-----------------------------------------------------------|
| VAULT_ADDR             | Да          |              | init/unseal/inject/backup/okd-sync | URL основного Vault                                        |
| VAULT_SECRET_PATH      | Да          |              | inject                      | Путь к секретам в Vault.                                  |
| VAULT_WRITE_PATH       | Да          |              | init/okd-sync               | Путь для записи ключей и токенов в Vault.                 |
| VAULT_RECURSIVE        | Нет         | false        | inject                      | Включение рекурсивной обработки секретов.                 |
| SEC_VAULT_ADDR         | Да          |              | init/unseal/backup          | URL вторичного Vault                                       |
| SEC_VAULT_UNSEAL_KEY*  | Да          |              | unseal                      | Цифра ключа для разблокировки Vault (от 1 до 32).         |
| SEC_VAULT_TOKEN        | Нет         |              | init/unseal/backup          | Токен для вторичного Vault.                               |
| VAULT_INIT_SHARES      | Нет         | 5            | init                        | Количество генерируемых ключей для разблокировки Vault.   |
| VAULT_INIT_THRESHOLD   | Нет         | 3            | init                        | Количество ключей, необходимых для успешной разблокировки.|
| OC_USERNAME            | Да          |              | okd-sync                    | Имя пользователя для OpenShift.                           |
| OC_PASSWORD            | Да          |              | okd-sync                    | Пароль пользователя для OpenShift.                        |
| OC_NAMESPACES          | Да          |              | okd-sync                    | Список namespace для обработки (через запятую).           |
| OC_CLUSTER             | Да          |              | okd-sync                    | Имя кластера OpenShift.                                   |
| VAULT_BACKUP_PATH      | Да          |              | backup                      | Путь для резервного копирования секретов.                 |
| VAULT_EXCLUDE_REGEX    | Нет         |              | inject/backup/okd-sync      | Regex для исключения секретов.                            |
| VAULT_INSECURE         | Нет         | false        | init/unseal/inject/backup/okd-sync | Включение принудительного доверия сертификату сервера.    |
| VAULT_AUTH_ROLE        | Нет         |              | init/unseal                 | Роль для аутентификации в Vault.                          |
| VAULT_ID_TOKEN         | Нет         |              | init/unseal                 | ID токен для аутентификации.                              |
| VAULT_K8S_AUTH         | Нет         |              | init/unseal                 | Флаг активации Kubernetes аутентификации.                 |
| VAULT_K8S_TOKEN        | Нет         |              | init/unseal                 | Токен Kubernetes для аутентификации.                      |
| VAULT_CA_PATH          | Нет         |              | init/unseal/inject/backup/okd-sync | Путь к сертификатам CA.                                   |
| CI_PROJECT_DIR         | Нет         |              | init/unseal/inject          | Путь рабочего каталога для GitLab CI/CD.                  |
| GITLAB_API_TOKEN       | Нет         |              | init/backup                 | Токен API GitLab для доступа к проекту.                   |
| GITLAB_GROUP_ID        | Нет         |              | init/unseal                 | Идентификатор группы GitLab.                              |
| GITLAB_PROJECT_ID      | Нет         |              | init/unseal                 | Идентификатор проекта GitLab.                             |
| GITLAB_API_URL         | Нет         |              | init/unseal                 | URL API GitLab.                                            |

---

# Методы

### init

- **Назначение**: Инициализация нового экземпляра Vault.
- **Переменные**: `VAULT_ADDR`, `VAULT_INIT_SHARES`, `VAULT_INIT_THRESHOLD`, `VAULT_WRITE_PATH`, `SEC_VAULT_ADDR`.
- **Результат**: Инициализирует Vault с указанными параметрами, генерирует ключи разблокировки и записывает их в указанный путь.

```yaml
default:
  image: MYIMAGE

tokens:
  id_tokens:
    VAULT_ID_TOKEN:
      aud: $CI_JOB_ID

variables:
  VAULT_ADDR: myvaultaddr.mydomain.ru
  VAULT_AUTH_ROLE: myns-myrole
  SEC_VAULT_ADDR: mysecvaultaddr.mydomain.ru
  VAULT_VERBOSE: 3
  VAULT_INIT_THRESHOLD: 3
  VAULT_INIT_SHARES: 5
  VAULT_WRITE_PATH: myns/init-keys

stages:
  - init

init myvault:
  stage: init
  tags:
    - dind
  <<: *tokens
  script:
    - ./hydra init
  when: manual
```

---

### unseal

- **Назначение**: Разблокировка (unseal) экземпляра Vault.
- **Переменные**: `SEC_VAULT_UNSEAL_KEY*`, `SEC_VAULT_ADDR`, `SEC_VAULT_TOKEN`.
- **Результат**: Разблокирует Vault, используя ключи разблокировки. Проверяет успешность операции.

```yaml
default:
  image: MYIMAGE

tokens:
  id_tokens:
    VAULT_ID_TOKEN:
      aud: $CI_JOB_ID

variables:
  VAULT_ADDR: myvaultaddr.mydomain.ru
  VAULT_AUTH_ROLE: myns-myrole
  SEC_VAULT_ADDR: mysecvaultaddr.mydomain.ru
  VAULT_VERBOSE: 3
  VAULT_SECRET_PATH: myns/init-keys

stages:
  - unseal

unseal myvault:
  stage: unseal
  tags:
    - dind
  <<: *tokens
  script:
    - ./hydra unseal
  when: manual
```

---

### inject

- **Назначение**: Извлечение секретов из Vault и запись их в файл окружения.
- **Переменные**: `VAULT_ADDR`, `VAULT_SECRET_PATH`, `VAULT_RECURSIVE`.
- **Результат**: Извлекает секреты из указанного пути и сохраняет их в файле окружения.

```yaml
default:
  image: MYIMAGE

tokens:
  id_tokens:
    VAULT_ID_TOKEN:
      aud: $CI_JOB_ID

variables:
  VAULT_ADDR: myvaultaddr.mydomain.ru
  VAULT_AUTH_ROLE: myns-myrole
  VAULT_VERBOSE: 3
  VAULT_SECRET_PATH: myns/init-keys

stages:
  - inject
  - recursive_inject

inject secrets:
  stage: inject
  tags:
    - dind
  <<: *tokens
  script:
    - ./hydra inject
    - cat tmp/envs
    - echo $SEC_VAULT_UNSEAL_KEY1
    - echo $ID_RSA | base64 -d > .ssh/id_rsa
  when: manual

recursive inject secrets:
  stage: recursive_inject
  variables:
    VAULT_RECURSIVE: true
  tags:
    - dind
  <<: *tokens
  script:
    - ./hydra inject
    - cat tmp/myns/init-keys
    - set -o allexport
    - source tmp/myns/init-keys
    - echo $SEC_VAULT_UNSEAL_KEY1
    - echo $ID_RSA | base64 -d > .ssh/id_rsa
  when: manual
```

---

### okd-sync

- **Назначение**: Синхронизация токенов OpenShift (OKD) с Vault.
- **Переменные**: `OC_USERNAME`, `OC_PASSWORD`, `OC_NAMESPACES`, `OC_CLUSTER`, `VAULT_ADDR`, `VAULT_WRITE_PATH`.
- **Результат**: Авторизуется в OpenShift, извлекает токены сервисных аккаунтов и сохраняет их в Vault.

```yaml
default:
  image: MYIMAGE

tokens:
  id_tokens:
    VAULT_ID_TOKEN:
      aud: $CI_JOB_ID

variables:
  VAULT_ADDR: myvaultaddr.mydomain.ru
  VAULT_AUTH_ROLE: myns-myrole
  VAULT_VERBOSE: 3
  OC_USERNAME: myusername
  OC_PASSWORD: mystrongpassword
  OC_NAMESPACES: "d-myns1, d-myns2"
  OC_CLUSTER: myokd
  VAULT_WRITE_PATH: myns/okd

stages:
  - myokd

okd-sync myokd:
  stage: myokd
  tags:
    - dind
  <<: *tokens
  script:
    - ./hydra okd-sync
  when: manual
```

---

### backup

- **Назначение**: Резервное копирование секретов между Vault.
- **Переменные**: `VAULT_ADDR`, `SEC_VAULT_ADDR`, `VAULT_BACKUP_PATH`.
- **Результат**: Копирует секреты из одного Vault в другой. Проверяет уникальность `cluster_id`.

```yaml
default:
  image: MYIMAGE

tokens:
  id_tokens:
    VAULT_ID_TOKEN:
      aud: $CI_JOB_ID

variables:
  VAULT_ADDR: myvaultaddr.mydomain.ru
  SEC_VAULT_ADDR: mysecvaultaddr.mydomain.ru
  VAULT_AUTH_ROLE: myns-myrole
  VAULT_VERBOSE: 3
  VAULT_BACKUP_PATH: myns

stages:
  - backup

backup myvault to mysecvault:
  stage: backup
  tags:
    - dind
  <<: *tokens
  script:
    - ./hydra backup
  when: manual
```

---

### help

- **Назначение**: Вывод справочной информации по командам.
- **Переменные**: Нет.
- **Результат**: Отображает список доступных команд и их описание.

```yaml
default:
  image: MYIMAGE

stages:
  - help

help:
  stage: help
  tags:
    - dind
  script:
    - ./hydra help
  when: manual
```


### FAQ
- **Что произойдет если у меня одинаковые имена ключей в разных секретах и я вызову inject?**
``` 
Если оба пути до секрета указаны для inject, то Hydra возьмет последний ключ и внесет его в файл envs (то есть постоянно будет перезаписывать один и тот же ключ) - воспользуйтесь VAULT_RECURSIVE: true,  тогда (если секреты называются по разному, но одинаковые ключи) секреты достанутся в разные файлы
```


- **У меня есть два экземпляра вольта, хочу использовать второй как резервный если с первым что нибудь произойдет**
```
Вы можете вызвать Hydra на уровне вашего окружения, обложив предварительными условиями для обработки ошибки (if, else и т.д)
```
- **Хочу ходить в свой экземпляр вольта, но у меня самоподписанный сертификат**
```

Укажите VAULT_INSECURE: true и Hydra будет принудительно доверять вашему сертификату
```
- **На каких ОС и архитектурах может запускаться Hydra?**
```

На данный момент Hydra умеет собираться для ОС семейства Linux/Windows/MacOS под архитектуры arm/amd x86_x64
```

- **Что произойдет если я запущу backup в экземпляр SEC_VAULT_ADDR который восстановлен из основного экземпляра VAULT_ADDR? я потеряю свой engine во втором экземпляре VAULT?**
```


Hydra умеет определять cluster_id экземпляров и выполняет проверку перед бекапом, если cluster_id экземпляров одинаковые, то вы получите ошибку проверки и бекап не запустится, если cluster_id разные, то все ок и Hydra попытается вытащить из VAULT_ADDR весь engine (или если вы указали не весь, то путь рекурсивно) и если в SEC_VAULT_ADDR есть такой же engine то удалит его и создаст новый с описанием, что это бекап из VAULT_ADDR и его датой запуска, если такого же engine там нет, то просто создаст новый с таким же описанием, как описано выше.
Если вы бекапируете не весь engine, а например какой то определенный путь, то надо понимать что все остальное в этом engine во втором экземпляре уничтожится, останется только путь который бекапируете из первого экземпляра
Backup всегда удаляет engine во втором экземпляре, если у него хватит на это прав.

```



