# Руководство по методам авторизации в Hydra


---
### Hydra Auth


## Hydra умеет авторизовываться по трем основным направлениям Token Auth, Gitlab JWT Auth, Kubernetes SA Token Auth - ниже я опишу работу этих методов и их приоритетность

### Token Auth

- **Назначение: Авторизация через токен**
- **Переменные: VAULT_ADDR, VAULT_TOKEN,VAULT_SECRET_PATH,HYDRA_ENABLED**

```yaml
default:
  image: MYIMAGE

variables:
  HYDRA_ENABLED: true # необходим для запуска Hydra 
  VAULT_ADDR: myvaultaddr.mydomain.ru
  VAULT_TOKEN: mysecurevaulttoken
  VAULT_SECRET_PATH:
    myns/path1/secret1

stages:
  - auth

auth with token to myvault:
  stage: auth

  script:
    - ./hydra inject
  when: manual
```
## Описание

```
Как вы можете видеть в примере мы не указываем id_tokens для JWT авторизации, так как идем в экземпляр вольта через токен, в таком случае Hydra использует VAULT_TOKEN и авторизуется по пути myvaultaddr.mydomain.ru/
для Hydra токен это самый приоритетный способ авторизации
Вытащит все ключи из myvaultaddr.mydomain.ru по пути myns/path1/secret1 секрета и положит в переменные окружения из tmp/envs файла
```

### Gitlab JWT Auth

- **Авторизация через Gitlab JWT Token**
- **Переменные: VAULT_ADDR,,VAULT_SECRET_PATH,HYDRA_ENABLED**
- 
```yaml
default:
  image: MYIMAGE

.tokens: &tokens
  id_tokens:
    VAULT_ID_TOKEN: # Эта переменная как раз и является JWT токеном, который гитлаб использует при авторизации в Hashicorp Vault
      aud: # - это должен быть список ваших экземпляров, куда вы хотите авторизоваться
        - myvaultaddr.mydomain.ru

variables:
  VAULT_ADDR: myvaultaddr.mydomain.ru
  VAULT_SECRET_PATH:
    myns/path1/secret1

stages:
  - auth

auth with jwt token to myvault:
  stage: auth
  <<: *tokens # Эта конструкция позволяет нам использовать якорь который сгруппирован в &tokens
  script:
    - ./hydra inject
  when: manual
```
## Описание

```
Для JWT авторизации можно указать свой урл, если он отличается от эталонного auth/jwt/login, для этого нужно задать VAULT_AUTH_URL: auth/git/login например как в SberDevices Vault
Hydra использует VAULT_ID_TOKEN и авторизуется (по умолчанию) по пути myvaultaddr.mydomain.ru/auth/git/login (если не указан свой урл для авторизации в переменной VAULT_AUTH_URL)
Для Hydra JWT токен это второй по приоритетности способ авторизации (если не задан VAULT_TOKEN то используется JWT либо K8S токены)
В итоге Hydra вытащит все ключи из myvaultaddr.mydomain.ru по пути myns/path1/secret1 секрета и положит в переменные окружения из tmp/envs файла
```

### Kubernetes SA Token Auth

- **Назначение: Авторизация через Kubernetes Service Account токен**
- **Переменные: VAULT_ADDR,,VAULT_SECRET_PATH,VAULT_K8S_AUTH,HYDRA_ENABLED**

```yaml
default:
  image: MYIMAGE


variables:
  VAULT_ADDR: myvaultaddr.mydomain.ru
  VAULT_K8S_AUTH: true # Переключаем режим работы авторизации на K8S токен
  VAULT_AUTH_URL: auth/myengine/login # Указываем урл для myengine
  VAULT_SECRET_PATH:
    myns/path1/secret1

stages:
  - auth

auth with k8s token to myvault:
  stage: auth
  script:
    - ./hydra inject
  when: manual
```

## Описание

```
Hydra использует token сервисаккаунта из под которого поднят pod раннера и авторизуется (по умолчанию) по пути myvaultaddr.mydomain.ru/auth/kubernetes/login (если не указан свой урл для авторизации в переменной VAULT_AUTH_URL) в данной ситуации мы будем указывать engine для кластера advosd
Для Hydra K8S токен это третий и самый низкий по приоритетности способ авторизации (если не задан VAULT_TOKEN и VAULT_ID_TOKEN то используем VAULT_K8S_TOKEN токен)
В итоге Hydra вытащит все ключи из myvaultaddr.mydomain.ru по пути myns/path1/secret1 секрета и положит в переменные окружения из tmp/envs файла
```

## Дополнение

```
Важно понимать что этот способ предназначен для работы непосредственно в самом Openshift/Kubernetes окружении - например можно воспользоваться нашими init/agent образами в своем Deployment/StatefulSet/Jobs указав init образ как init контейнер пода, а agent как sidecar контейнер
Это будет работать так
Для пода с вашим приложением, куда вы вносите init/agent контейнеры, необходимо задавать serviceaccount vault (либо ваш которому вы разрешили авторизацию в ваш secret_path внутри политики Hashicorp Vault)
Hydra Init выполнит инициализацию с экземпляром - авторизуется через токен из контейнера и создаст в общей расшаренной на все контейнеры папке(например tmp) секрет файл envs, куда положит все секреты в виде KEY="VALUE" структуры
Hydra Agent будет запускать hydra inject каждые 60 секунд чтобы обновлять секреты в файле tmp/envs
Ваше приложение должно уметь брать из этого файла переменные, либо вы можете выполнить set -o allexport и source tmp/envs чтобы секреты из tmp/envs записались в переменные окружения вашего контейнера с приложением
```