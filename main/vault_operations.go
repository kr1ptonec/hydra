// Hydra Vault - Инструмент для упрощения интеграции с Hashicorp Vault на стадии CI/CD с поддержкой переменных окружения и аргументов для любых архитектур и операционных систем.
// Автор: Kholodov Alexandr Sergeevich
// maito: murcie1337@gmail.com
// Copyright (c) 2025 Kholodov Alexandr Sergeevich

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	vault "github.com/hashicorp/vault/api"
	"log"
	"os"
	"strings"
	"time"
)

func currentTime() string {
	// Устанавливаем часовой пояс на московский
	location, err := time.LoadLocation("Europe/Moscow")
	if err != nil {
		HandleError(err, fmt.Sprintf("Ошибка: %s", err), Error)
	}

	// Получаем текущую дату и время в московском часовом поясе
	currentTime := time.Now().In(location)

	// Форматируем дату в нужном формате
	formattedTime := currentTime.Format("02.01.2006 15:04:05")
	return formattedTime
}

func manageVault(action, SecVaultAddr, vaultWritePath string) {
	vaultInitShares := setVaultInitShares()
	switch action {
	case "init":
		// Инициализация и разблокировка unseal_vault
		unsealClient, err := getUnsealClient(SecVaultAddr, "")
		if err != nil {
			Log(Error, fmt.Sprintf("Ошибка при создании клиента %s: %s", SecVaultAddr, err))
		}

		initResp, err := unsealClient.Sys().Init(&vault.InitRequest{
			SecretShares:    vaultInitShares,
			SecretThreshold: setVaultInitTreshold(),
		})
		if err != nil {
			Log(Error, fmt.Sprintf("Ошибка при инициализации %s: %s", SecVaultAddr, err))
		}

		// Разблокировка unseal_vault
		for _, key := range initResp.KeysB64 {
			_, err := unsealClient.Sys().Unseal(key)
			if err != nil {
				Log(Error, fmt.Sprintf("Ошибка при разблокировке %s: %s", SecVaultAddr, err))
			}
		}
		// Авторизация и запись ключей в основной экземпляр Vault
		mainClient, err := auth(primaryConfig)
		if err != nil {
			HandleError(err, "Ошибка при аутентификации", Error)
			os.Exit(1)
		}
		keysData := generateKeyNamesAndMap(vaultInitShares, initResp)
		WritePath, err := executeKVOperation(mainClient, vaultWritePath, "Write", keysData)
		if err != nil {
			Log(Error, fmt.Sprintf("Ошибка при записи ключей и корневого токена в %s: %s", WritePath, err))
			os.Exit(1)
		}
		if gitlabApiUrl == "" {
			Log(Error, "Не удалось получить CI_API_V4_URL")
			os.Exit(1)
		}
		if gitlabProjectID == "" {
			Log(Error, "Не удалось получить CI_PROJECT_ID")
			os.Exit(1)
		}
		// После успешной записи в Vault, добавляем переменные в GitLab
		gitlabVars := make(map[string]string)
		for i, key := range initResp.KeysB64 {
			gitlabVars[fmt.Sprintf("SEC_VAULT_UNSEAL_KEY%d", i+1)] = key
		}
		gitlabVars["SEC_VAULT_TOKEN"] = initResp.RootToken

		// Вызов функции для добавления переменных в GitLab
		err = setGitLabVars(gitlabProjectID, gitlabApiToken, gitlabVars)
		if err != nil {
			Log(Error, fmt.Sprintf("Ошибка при добавлении переменных в GitLab: %s", err))
			// Не останавливаем выполнение, так как это не критично для инициализации Vault
		} else {
			Log(Info, "Переменные успешно добавлены в GitLab")
		}
		os.Exit(0)
	case "unseal":
		// Создание клиента для разблокировки unseal_vault
		unsealClient, err := getUnsealClient(SecVaultAddr, "")
		if err != nil {
			Log(Error, fmt.Sprintf("Ошибка при создании клиента для %s: %s", SecVaultAddr, err))
		}

		// Разблокировка unseal_vault с использованием ключей из переменных окружения
		for i := 1; i <= vaultInitShares; i++ {
			keyEnv := fmt.Sprintf("SEC_VAULT_UNSEAL_KEY%d", i)
			key := os.Getenv(keyEnv)
			if key == "" {
				Log(Error, "Ключи SEC_VAULT_UNSEAL_KEY пусты, проверьте VAULT_SECRET_PATH")
				os.Exit(1)
			}
			_, err := unsealClient.Sys().Unseal(key)
			if err != nil {
				Log(Error, fmt.Sprintf("Ошибка при разблокировке %s:%s", SecVaultAddr, err))
			}
		}
		checkUnsealclient, err := getUnsealClient(SecVaultAddr, os.Getenv("SEC_VAULT_TOKEN"))
		if err != nil {
			Log(Error, fmt.Sprintf("Ошибка при создании клиента для проверки %s: %s", SecVaultAddr, err))
		}
		_, err = checkUnsealclient.Logical().Read("auth/token/lookup-self")
		if err != nil {
			Log(Error, fmt.Sprintf("ошибка при проверке токена Vault: %s, %v", SecVaultAddr, err))
			os.Exit(1)
		}
		Log(Info, fmt.Sprintf("%s успешно разблокирован.", SecVaultAddr))
	}
}

// Функция для создания клиента Vault Unseal
func getUnsealClient(addr, token string) (*vault.Client, error) {
	clientConfig := &vault.Config{
		Address: addr,
	}
	Log(Info, fmt.Sprintf("Создаем Unseal Client для %s", addr))
	_, tlsConfig, err := configureTLS(certsPath, false)
	if err != nil {
		log.Fatalf("Ошибка настройки TLS: %v", err)
	}

	err = clientConfig.ConfigureTLS(tlsConfig)
	if err != nil {
		HandleError(err, "Ошибка при конфигурации TLS", Error)
		return nil, err // Возвращаем ошибку, если не можем настроить TLS
	}

	client, err := vault.NewClient(clientConfig)
	if err != nil {
		return nil, err
	}
	if token != "" {
		client.SetToken(token)
	}
	return client, nil
}
func backupSecrets(backupPath string) ([]string, error) {
	if vaultAddr == SecVaultAddr {
		Log(Error, "Адреса вольтов не должны совпадать! проверьте переменные VAULT_ADDR SEC_VAULT_ADDR")
		return nil, nil
	}
	clientSrc, err := auth(primaryConfig)
	if err != nil {
		HandleError(err, "Не удалось создать клиента master", Error)
		return nil, err
	}
	clientDst, err := auth(secondaryConfig)
	if err != nil {
		HandleError(err, "Не удалось создать клиента slave", Error)
		return nil, err
	}
	isuniq, err := checkUniqClusterID(clientSrc, clientDst)
	if err != nil {
		HandleError(err, fmt.Sprintf("Ошибка при проверке уникальности clusterID"), Error)
		return nil, err
	}
	if isuniq { // Если кластера неуникальны то возвращаем nil
		return nil, nil
	}
	paths, err := listAllPaths(clientSrc, backupPath)
	if err != nil {
		HandleError(err, "Ошибка при получении списка путей секретов %s", Error)
		return nil, err
	}
	if backupPath != "" {
		// Извлекаем неймспейс до первого слэша
		namespace := strings.Split(backupPath, "/")[0]

		// Проверяем, что namespace не пуст
		if namespace == "" {
			return nil, errors.New(fmt.Sprintf("не удалось определить namespace из бекап пути VAULT_BACKUP_PATH: %s", backupPath))
		}
		err := EngineCheck(clientDst, namespace)
		if err != nil {
			return nil, err
		}
	}
	// Выводим список путей
	for _, path := range paths {
		// Проверяем исключения через excludeString
		excludedPath := excludeString(path)
		if excludedPath == nil {
			// Если строка исключена, возвращаем nil и сообщение об исключении
			Log(Info, fmt.Sprintf("путь '%s' был исключен на основе регулярного выражения", path))
			continue
		}
		secretsJson, err := executeKVOperation(clientSrc, path, "Read", nil)
		if err != nil {
			HandleError(err, fmt.Sprintf("ошибка при получении секрета по пути %s: %v", path, err), Error)
			return nil, err
		}
		data, err := unmarshalSecret(secretsJson, path)
		if err != nil {
			HandleError(err, fmt.Sprintf("ошибка при декодинге секрета по пути %s: %v", path, err), Error)
			return nil, err
		}
		_, err = executeKVOperation(clientDst, path, "Write", data)
		if err != nil {
			HandleError(err, fmt.Sprintf("ошибка при записи секрета по пути %s: %v", path, err), Error)
			return nil, err
		}
	}
	return nil, nil
}

func listAllPaths(client *vault.Client, currentPath string) ([]string, error) {
	// Получаем список секретов или папок в текущем пути
	listPath, err := executeKVOperation(client, currentPath, "List", nil)
	if err != nil {
		return nil, fmt.Errorf("ошибка при получении списка секретов: %v", err)
	}
	// Получаем данные списка секретов или папок
	return listPath, nil
}
func HelloMessage() {
	Log(Debug, "Уровень verbosity: %v", setVerbosity())
	fmt.Println(fmt.Sprintf("\nContribute %s", contributeUrl))
	fmt.Println("\nВерсия приложения:\n", version)
	fmt.Println("\nВерсия Golang:\n", GoVersion)
	flag.BoolVar(&showHelp, "help", false, "Показать справку")
	flag.Parse()
}
func inject() {
	if showHelp || vaultAddr == "" || vaultSecretPaths == "" {
		printUsage()
		os.Exit(2)
	}

	client, err := auth(primaryConfig)
	if err != nil {
		Log(Error, fmt.Sprintf("Ошибка при аутентификации: %s", err))
		HandleError(err, "", 10)
	}
	if !checkVaultRecursiveEnv() {
		secrets, _, err := getSecrets(client, vaultSecretPaths, fileFolderPath, ciProjectDir)
		if err != nil {
			Log(Error, fmt.Sprintf("Ошибка при получении секретов:\n %s", err))
			os.Exit(1)
		}
		envsPath, err := createEnvsFile(ciProjectDir, secrets, "")
		if err != nil {
			Log(Error, fmt.Sprintf("Ошибка при создании файла переменных:\n %v", err))
			os.Exit(1)
		}
		if envsPath != "" {
			Log(Debug, "Файл переменных создан: %s\n", envsPath)
			//createBashFile()
		}
	} else {
		secretPaths := strings.Split(vaultSecretPaths, " ")
		for _, path := range secretPaths {
			RecursivePaths, _ := listAllPaths(client, path)
			for _, recursivePath := range RecursivePaths {
				secrets, _, err := getSecrets(client, recursivePath, fileFolderPath, ciProjectDir)
				if err != nil {
					Log(Error, fmt.Sprintf("Ошибка при получении секретов:\n %s", err))
					os.Exit(1)
				}
				envsPath, err := createEnvsFile(ciProjectDir, secrets, recursivePath)
				if err != nil {
					Log(Error, fmt.Sprintf("Ошибка при создании файла переменных:\n %v", err))
					os.Exit(1)
				}
				if envsPath != "" {
					Log(Debug, "Файл переменных создан: %s\n", envsPath)
				}
			}
		}
	}
}
func getSecrets(client *vault.Client, vaultSecretPaths, fileFolderPath, ciProjectDir string) (map[string]string, string, error) {
	secrets := make(map[string]string)
	var secretName string
	var secretPaths []string
	if checkVaultRecursiveEnv() {
		// Если включен рекурсивный режим, обрабатываем один путь
		Log(Info, fmt.Sprintf("Рекурсивный режим включен, путь: %s", vaultSecretPaths))
		secretPaths = []string{vaultSecretPaths}
	} else {
		// Разделяем пути по пробелам
		secretPaths = strings.Split(vaultSecretPaths, " ")
	}

	for _, path := range secretPaths {
		// Проверяем исключения через excludeString
		excludedPath := excludeString(path)
		if excludedPath == nil {
			// Если строка исключена, возвращаем nil и сообщение об исключении
			Log(Info, fmt.Sprintf("путь '%s' был исключен на основе регулярного выражения", path))
			continue
		}
		Log(Info, fmt.Sprintf("Обрабатываем путь: %s", path))

		vaultNamespace = extractNamespace(path)
		secretName = extractSecretName(path)
		secretDataJSON, err := executeKVOperation(client, path, "Read", nil)
		if secretDataJSON == nil {
			Log(Error, fmt.Sprintf("Не существующий секрет по пути: %s", path))
			Log(Debug, "Пропускаем недоступный путь: %s", path)
			continue
		}

		// Преобразуем JSON структуру в map[string]interface{}
		data, err := unmarshalSecret(secretDataJSON, path)
		if err != nil {
			Log(Error, fmt.Sprintf("Ошибка при чтении секрета из %s: %s", path, err))
			return nil, "", err
		}

		for key, value := range data {
			if isFileKey(key) {
				err := createFile(fileFolderPath, ciProjectDir, key, value)
				if err != nil {
					return nil, "", err
				}
			} else {
				if valid, err := isValidKey(key); valid {
					secrets[processKey(key)] = processValue(value)
					if checkVaultRecursiveEnv() == false {
						Log(Debug, "Ключ '%s' добавлен в переменные окружения\n", processKey(key))
					}
				} else {
					Log(Error, "Ошибка при добавлении ключа %s\n %s", processKey(key), err)
				}
			}
		}
	}

	return secrets, secretName, nil
}

func unmarshalSecret(secretDataJSON []string, path string) (map[string]interface{}, error) {
	var secretDataSlice map[string]interface{}

	if err := json.Unmarshal([]byte(secretDataJSON[0]), &secretDataSlice); err != nil {

		Log(Error, fmt.Sprintf("Ошибка при декодировании JSON секрета из %s: %s", path, err))
		return nil, err
	}
	// Проверяем, что слайс не пустой и содержит данные
	if len(secretDataSlice) > 0 {
		return secretDataSlice, nil
	} else {
		Log(Info, fmt.Sprintf("Пустой секрет: %s", path))
	}
	return nil, nil

}

// executeKVOperation
// Функция для выполнения операций с Vault (чтение, запись, список)
func executeKVOperation(client *vault.Client, pathsString, operation string, data map[string]interface{}) ([]string, error) {
	paths := strings.Split(pathsString, " ")
	var finalResults []string
	var errorsEncountered []string

	for _, path := range paths {
		result, err := performVaultOperation(client, path, operation, data)
		if err != nil {
			errorMessage := fmt.Sprintf("Ошибка при выполнении операции '%s' на пути '%s': %v", operation, path, err)
			errorsEncountered = append(errorsEncountered, errorMessage)
			Log(Error, errorMessage)
		} else {
			finalResults = append(finalResults, result...)
		}
	}

	if len(errorsEncountered) > 0 {
		// Возвращаем как результаты, так и ошибки
		return finalResults, fmt.Errorf("во время выполнения операций возникли ошибки: %s", strings.Join(errorsEncountered, "; "))
	}
	return finalResults, nil
}

// Функция для чтения секрета
func readSecret(client *vault.Client, path string) ([]string, error) {
	Log(Debug, fmt.Sprintf("Пробую прочитать из %s", path))

	// Читаем секрет по исходному пути
	secret, err := client.Logical().Read(path)
	if err != nil {
		Log(Error, "Ошибка при выполнении операции vault по пути: "+path+" Ошибка: "+err.Error())
		return nil, err
	}
	if secret == nil {
		Log(Debug, "Секрет не найден по пути: "+path)
		return nil, nil
	}

	// Проверяем, является ли путь V1, и если да, то обрабатываем его через handleEngineV2
	if !checkPath(path) {
		modifiedPath, err := handleEngineV2(secret, path, "Read", false)
		if err != nil {
			Log(Error, "Ошибка при обработке пути для KV v2: "+err.Error())
			return nil, err
		}
		if modifiedPath != path {
			secret, err = client.Logical().Read(modifiedPath)
			if err != nil {
				Log(Error, "Ошибка при выполнении операции vault по модифицированному пути: "+modifiedPath+" Ошибка: "+err.Error())
				return nil, err
			}
			if secret == nil {
				Log(Debug, "Секрет не найден по модифицированному пути: "+modifiedPath)
				return nil, nil
			}
			path = modifiedPath // Обновляем путь для дальнейшего использования
		}
	}

	// Извлекаем данные из секрета
	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		// Для KV v1 и других случаев, когда данные находятся на верхнем уровне
		data = secret.Data
	}
	secretJSON, err := json.Marshal(data)
	if err != nil {
		Log(Error, "Ошибка при преобразовании данных секрета в JSON: "+err.Error())
		return nil, err
	}
	Log(Info, fmt.Sprintf("Успешное чтение из %s", path))
	return []string{string(secretJSON)}, nil
}

func writeSecret(client *vault.Client, path string, data map[string]interface{}) ([]string, error) {
	Log(Debug, fmt.Sprintf("Пробую записать в %s", path))

	// Определяем, является ли путь совместимым с KV v2
	isV2 := checkPath(path)
	// Если это KV v2, данные оборачиваем в "data"
	var wrappedData map[string]interface{}
	if isV2 {
		wrappedData = map[string]interface{}{
			"data": data,
		}
	} else {
		wrappedData = data
	}

	// Попытка записи в Vault
	result, err := client.Logical().Write(path, wrappedData)
	if err != nil {
		modifiedPath, err := handleEngineV2(result, path, "Write", false)
		if modifiedPath != path {
			path = modifiedPath
			// Повторяем попытку с модифицированным путем
			return writeSecret(client, path, data)
		}
		return nil, err
	}
	Log(Info, fmt.Sprintf("Успешная запись в %s", path))
	// Возвращаем успех, если нет ошибки
	return []string{"success"}, nil
}

// Функция для получения списка секретов
func listSecrets(client *vault.Client, basePath string) ([]string, error) {
	var secretsList []string

	// Начинаем обработку основного пути
	err := walkPath(client, basePath+"/", &secretsList, false)

	if len(secretsList) == 0 {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return secretsList, nil
}

func walkPath(client *vault.Client, currentPath string, secretsList *[]string, isModified bool) error {
	Log(Debug, "Пробуем путь: "+currentPath)

	// Попробуем считать секрет через Read
	secret, err := client.Logical().Read(currentPath)
	if err != nil {
		Log(Debug, "Ошибка при чтении пути: "+currentPath+" Error: "+err.Error())
	}
	if secret != nil && len(secret.Data) > 0 {
		finalPath := modifyPathForDisplay(currentPath)
		*secretsList = append(*secretsList, finalPath)
		Log(Debug, "Секрет найден и добавлен в лист: "+finalPath)
		return nil
	}

	// Если Read вернул nil, пробуем List
	secret, err = client.Logical().List(currentPath)
	if err != nil {
		Log(Debug, "Ошибка при выполнении операции List: "+currentPath+" Error: "+err.Error())
		return err
	}
	if secret == nil {
		Log(Error, fmt.Sprintf("Путь не существует либо пуст: %s", currentPath))
		return nil
	}

	// Проверка на движок V2 (если включено isModified)
	modifiedPath, err := handleEngineV2(secret, currentPath, "List", isModified)
	if err != nil {
		return err
	}
	if modifiedPath != currentPath {
		return walkPath(client, modifiedPath, secretsList, true)
	}

	// Обработка ключей внутри папки
	keysInterface, ok := secret.Data["keys"]
	if !ok {
		Log(Debug, "Нет ключей по пути: "+currentPath)
		return nil
	}

	keys, ok := keysInterface.([]interface{})
	if !ok {
		return fmt.Errorf("Невалидный ключ по пути: %s", currentPath)
	}

	for _, keyInterface := range keys {
		key, ok := keyInterface.(string)
		if !ok {
			continue
		}

		fullPath := currentPath + key
		if strings.HasSuffix(key, "/") {
			// Рекурсивный обход для папки
			err := walkPath(client, fullPath, secretsList, false)
			if err != nil {
				Log(Debug, "Ошибка при переборе пути: "+fullPath+" Error: "+err.Error())
				continue
			}
		} else {
			// Обработка секретов
			finalPath := modifyPathForDisplay(fullPath)
			*secretsList = append(*secretsList, finalPath)
			Log(Debug, "Секрет добавлен в лист: "+finalPath)
		}
	}

	return nil
}

// handleEngineV2 проверяет - если путь V1 и мы получили ошибку о неправильном engine то модифицируем его и возвращаем как V2 иначе просто вернет тот же путь
func handleEngineV2(secret *vault.Secret, path string, operation string, isModified bool) (string, error) {
	if !checkPath(path) && len(secret.Warnings) > 0 && strings.Contains(secret.Warnings[0], "Invalid path for a versioned K/V secrets engine") {
		if !isModified {
			modifiedPath := modifyPathForV2(path, operation)
			Log(Info, fmt.Sprintf("Пробуем V2 engine %s", modifiedPath))
			return modifiedPath, nil
		}
	}
	return path, nil
}

// checkPath проверяет, содержит ли путь после первого слеша подстроки "data" или "metadata".
// Возвращает true, если содержит, и false, если нет.
func checkPath(path string) bool {
	// Находим индекс первого слеша в пути.
	slashIndex := strings.Index(path, "/")
	if slashIndex == -1 {
		// Если слеш не найден, значит, путь не содержит поддиректорий.
		return false
	}

	// Получаем подстроку после первого слеша.
	subPath := path[slashIndex+1:]
	// Проверяем, начинается ли подстрока с "data" или "metadata".
	return strings.HasPrefix(subPath, "data") || strings.HasPrefix(subPath, "metadata")
}

// Функция для выполнения операции с Vault
func performVaultOperation(client *vault.Client, path, operation string, data map[string]interface{}) ([]string, error) {
	switch operation {
	case "Read":
		return readSecret(client, path)
	case "Write":
		return writeSecret(client, path, data)
	case "List":
		return listSecrets(client, path)
	default:
		return nil, fmt.Errorf("неизвестная операция: %s", operation)
	}
}

// EngineCheck проверяет наличие неймспейса, удаляет и создает его с engine v2, если он отсутствует просто создает
func EngineCheck(client *vault.Client, enginePrefix string) error {
	// Путь к engine в Vault
	enginePath := fmt.Sprintf("%s/", enginePrefix)

	// Проверяем наличие engine
	mounts, err := client.Sys().ListMounts()
	if err != nil {
		Log(Error, fmt.Sprintf("не удалось получить список монтирований: %v", err))
		HandleError(err, "", 1)
	}

	// Если engine уже существует, удаляем его перед созданием нового
	if _, ok := mounts[enginePath]; ok {
		Log(Info, fmt.Sprintf("Engine '%s' уже существует, удаляем...", enginePrefix))

		// Создаем контекст с таймаутом 5 минут
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
		defer cancel()

		const maxRetries = 3
		for attempt := 1; attempt <= maxRetries; attempt++ {
			Log(Debug, fmt.Sprintf("Попытка %d: удаление engine '%s'", attempt, enginePrefix))
			err = client.Sys().UnmountWithContext(ctx, enginePath)
			if err == nil {
				Log(Info, fmt.Sprintf("Engine '%s' успешно удалён", enginePrefix))
				break
			}

			Log(Error, fmt.Sprintf("Ошибка при удалении engine '%s' на попытке %d: %v", enginePrefix, attempt, err))
			if attempt < maxRetries {
				time.Sleep(2 * time.Second)
			} else {
				Log(Error, fmt.Sprintf("Не удалось удалить engine '%s' после %d попыток", enginePrefix, maxRetries))
				HandleError(err, "", 1)
			}
		}
	}

	// Создаем engine с типом kv-v2
	Log(Debug, fmt.Sprintf("Создаем engine '%s' с типом kv-v2 %s", enginePrefix, currentTime()))
	err = client.Sys().Mount(enginePath, &vault.MountInput{
		Type:        "kv-v2",
		Description: fmt.Sprintf("[%s] Backup Engine from %s", currentTime(), vaultAddr),
	})
	if err != nil {
		return fmt.Errorf("не удалось создать engine '%s': %v", enginePrefix, err)
	}

	Log(Info, fmt.Sprintf("Engine '%s' успешно создан с типом kv-v2", enginePrefix))
	return nil
}
