// Hydra Vault - Инструмент для упрощения интеграции с Hashicorp Vault на стадии CI/CD с поддержкой переменных окружения и аргументов для любых архитектур и операционных систем.
// Автор: Kholodov Alexandr Sergeevich
// maito: murcie1337@gmail.com
// Copyright (c) 2025 Kholodov Alexandr Sergeevich
//
// Лицензия: MIT License

package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	vault "github.com/hashicorp/vault/api"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

func checkVaultK8sAuthEnv() bool {
	if vaultk8sAuthEnv == "" {
		return false
	}
	vaultk8sAuth, err := strconv.ParseBool(vaultk8sAuthEnv)
	if err != nil {
		Log(Error, fmt.Sprintf("Некорректное значение VAULT_K8S_AUTH: %s. Ожидалось true/false.", vaultk8sAuthEnv))
		vaultk8sAuth = false // Устанавливаем значение по умолчанию
		printUsage()
	}
	return vaultk8sAuth
}

// checkVaultRecursiveEnv
// Вернет true если переменная VAULT_RECURSIVE задана и она true
// по умолчанию false
func checkVaultRecursiveEnv() bool {
	var vaultRecursive bool
	if vaultRecursiveEnv == "" {
		vaultRecursive = false // Устанавливаем значение по умолчанию
		return vaultRecursive
	}
	vaultRecursive, err := strconv.ParseBool(vaultRecursiveEnv)
	if err != nil {
		Log(Error, fmt.Sprintf("Некорректное значение VAULT_RECURSIVE: %s Ожидалось true/false.", vaultRecursiveEnv))
		vaultRecursive = false // Устанавливаем значение по умолчанию
		printUsage()
	}
	return vaultRecursive
}

func Log(level int, message string, args ...interface{}) {
	if setVerbosity() < level {
		return
	}

	var logFunction func(format string, a ...interface{})
	switch level {
	case Error:
		logFunction = red
	case Info:
		logFunction = green
	case Debug:
		logFunction = cyan
	default:
		return
	}

	if len(args) > 0 {
		message = fmt.Sprintf(message, args...)
	}
	logFunction(fmt.Sprintf("[%s] %s\n", levelToString(level), message))
}

func levelToString(level int) string {
	switch level {
	case Error:
		return "ERROR"
	case Info:
		return "INFO"
	case Debug:
		return "DEBUG"
	default:
		return "UNKNOWN"
	}
}

func getOS() string {
	switch runtime.GOOS {
	case "windows", "linux", "darwin":
		return runtime.GOOS
	default:
		HandleError(fmt.Errorf("неизвестная операционная система: %s", runtime.GOOS), "Неизвестная операционная система", Error)
		return ""
	}
}

func HandleError(err error, message string, level int) {
	if err != nil {
		Log(level, "%s: %v", message, err)
		if level == Error {
			os.Exit(1)
		}
		os.Exit(level)
	}
}

func createFile(fileFolderPath, ciProjectDir, key string, value interface{}) error {
	fileFolderPath = determineFileFolderPath(fileFolderPath, ciProjectDir)
	if err := ensureDirectory(fileFolderPath); err != nil {
		return err
	}

	fileName := fmt.Sprintf("%s/%s", fileFolderPath, key)
	return writeToFile(fileName, []byte(fmt.Sprintf("%v", value)))
}

func determineFileFolderPath(fileFolderPath, ciProjectDir string) string {
	if fileFolderPath == "" {
		fileFolderPath = "vault_files"
	}
	if ciProjectDir != "" {
		fileFolderPath = joinPaths(ciProjectDir, fileFolderPath)
	}
	return fileFolderPath
}

func ensureDirectory(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		err := os.MkdirAll(path, os.ModePerm)
		if err != nil {
			return err
		}
		Log(Info, "Создана директория для файлов: %s\n", path)
	}
	return nil
}

func joinPaths(basePath, folderPath string) string {
	if osType == "windows" {
		return basePath + "\\" + folderPath
	}
	return basePath + "/" + folderPath
}

func writeToFile(fileName string, data []byte) error {
	err := os.WriteFile(fileName, data, 0644)
	if err != nil {
		HandleError(err, fmt.Sprintf("Ошибка при создании файла '%s'", fileName), Error)
	}
	return err
}

func extractNamespace(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) >= 1 {
		return parts[0]
	}
	return "" // Если нет слешей в строке, возвращаем пустую строку
}

// Функция всегда возвращает последний элемент массива, что корректно работает для строк без /
func extractSecretName(path string) string {
	parts := strings.Split(path, "/")
	return parts[len(parts)-1]
}
func modifyPathForV2(path string, operation string) string {
	// Удаляем начальный слеш, если он есть
	trimmedPath := strings.TrimPrefix(path, "/")
	parts := strings.Split(trimmedPath, "/")

	// Для операций чтения и записи добавляем "data" после монтирования точки.
	if (operation == "Read" || operation == "Write") && len(parts) > 1 {
		parts = append([]string{parts[0], "data"}, parts[1:]...)
	}

	// Для операции List добавляем "metadata" после монтирования точки.
	if operation == "List" {
		// Если уже есть "metadata", то не добавляем его снова
		if len(parts) > 1 && parts[1] != "metadata" {
			parts = append([]string{parts[0], "metadata"}, parts[1:]...)
		} else if len(parts) == 1 {
			// Если в пути только монтирование точки, добавляем "metadata"
			parts = append(parts, "metadata")
		}
	}

	return strings.Join(parts, "/")
}

// Функция для замены 'metadata' на 'data' в пути для KV V2
func modifyPathForDisplay(path string) string {
	return strings.Replace(path, "metadata/", "data/", 1)
}
func isFileKey(key string) bool {
	fileExtensions := []string{".crt", ".jwks", ".pem", ".p12", ".key", ".file", ".txt", ".conf"}
	for _, ext := range fileExtensions {
		if strings.HasSuffix(key, ext) {
			return true
		}
	}
	return false
}

// Вспомогательная функция для проверки таймаута
func isTimeout(err error) bool {
	var netErr net.Error
	ok := errors.As(err, &netErr)
	return ok && netErr.Timeout()
}

func createEnvsFile(ciProjectDir string, envVars map[string]string, path string) (string, error) {
	//var envsPath string
	// Проверяем, пуст ли массив переменных окружения
	if len(envVars) == 0 {
		Log(Info, "Секреты пустые. Файл не будет создан.")
		return "", nil
	}
	var tmpPath string
	if os.Getenv("HYDRA_SECRETS_DIR") == "" || len(os.Getenv("HYDRA_SECRETS_DIR")) == 0 {
		tmpPath = "tmp"
	} else {
		tmpPath = os.Getenv("HYDRA_SECRETS_DIR")
	}
	// Проверяем исключения через excludeString
	excludedPath := excludeString(path)
	if excludedPath == nil {
		Log(Info, fmt.Sprintf("Путь '%s' был исключен, файл создан не будет", path))
		return "", nil
	}

	// Подготовка содержимого для файла
	envsContent := ""
	for key, value := range envVars {
		envsContent += fmt.Sprintf("%s=%s\n", key, value)
	}
	// Убираем "/data" из пути, если он есть и отрезаем "/" в конце
	sanitizedPath := strings.TrimSuffix(strings.Replace(path, "/data/", "/", -1), "/")

	basePath := filepath.Base(sanitizedPath)
	parentPath := filepath.Dir(sanitizedPath)
	dirPath := filepath.Join(ciProjectDir, tmpPath, parentPath)

	if osType == "windows" {
		dirPath = filepath.Join(ciProjectDir, tmpPath, strings.ReplaceAll(parentPath, "/", "\\"))
	}
	if checkVaultRecursiveEnv() {
		// Если включен рекурсивный режим, создаём структуру директорий
		envsPath = filepath.Join(dirPath, basePath)
	} else {
		// Если рекурсивный режим отключен, создаём единый файл
		if osType == "linux" || osType == "darwin" {
			envsPath = filepath.Join(ciProjectDir, tmpPath, "envs")
		} else {
			envsPath = filepath.Join(ciProjectDir, tmpPath, "envs")
		}
	}
	// Создаем директорию, включая все промежуточные каталоги
	mkdirerr := os.MkdirAll(dirPath, 0755)
	if mkdirerr != nil {
		return "", mkdirerr
	}
	// Записываем содержимое в файл
	err := os.WriteFile(envsPath, []byte(envsContent), 0644)
	if err != nil {
		HandleError(err, "Ошибка при записи в файл", 1)
	}

	Log(Info, fmt.Sprintf("Файл успешно создан по пути: %s", envsPath))
	return envsPath, nil
}

func isValidKey(key string) (bool, string) {
	validKeyRegex := regexp.MustCompile("^[a-zA-Z0-9_]+(_[a-zA-Z0-9_]+)*$")

	if !validKeyRegex.MatchString(key) {
		var forbiddenChars []rune
		for _, char := range key {
			if !validKeyRegex.MatchString(string(char)) {
				forbiddenChars = append(forbiddenChars, char)
			}
		}
		if len(forbiddenChars) > 0 {
			forbiddenCharsStr := strings.Join([]string{string(forbiddenChars), " "}, "")
			Log(Error, "Ключ '%s' не прошел проверку. Запрещенные символы: %s", key, forbiddenCharsStr)
			return false, ""
		}
	}

	return true, ""
}

func setVerbosity() int {
	verbosityStr := os.Getenv("VAULT_VERBOSE")
	verbosity, err := strconv.Atoi(verbosityStr)
	if err != nil {
		verbosity = 1 // Default level is Info
	}
	return verbosity
}
func setVaultInitShares() int {
	vaultInitSharesStr := os.Getenv("VAULT_INIT_SHARES")
	vaultInitShares, err := strconv.Atoi(vaultInitSharesStr)
	if err != nil {
		vaultInitShares = 5 // Default Key Init Numbers
	}
	return vaultInitShares
}
func setVaultInitTreshold() int {
	VaultInitTresholdStr := os.Getenv("VAULT_INIT_THRESHOLD")
	VaultInitTreshold, err := strconv.Atoi(VaultInitTresholdStr)
	if err != nil {
		VaultInitTreshold = 3 // Default Theshold Keys
	}
	return VaultInitTreshold
}

// Генерирует карту ключей на основе количества ключей и добавляет SEC_VAULT_ROOT_TOKEN в конце
func generateKeyNamesAndMap(vaultInitShares int, initResp *vault.InitResponse) map[string]interface{} {
	keysData := make(map[string]interface{})

	// Генерация ключей на основе количества
	for i := 1; i <= vaultInitShares; i++ {
		keyName := fmt.Sprintf("SEC_VAULT_UNSEAL_KEY%d", i)
		keysData[keyName] = initResp.KeysB64[i-1] // Присваиваем ключ по порядку
	}

	// Добавляем SEC_VAULT_TOKEN в конец
	keysData["SEC_VAULT_TOKEN"] = initResp.RootToken

	return keysData
}

func printUsage() {
	fmt.Println("Использование: ./hydra [ОПЦИИ]")

	fmt.Println("\nОпции для операций с Vault:")
	fmt.Println("  - ./hydra init             - (для новых установок) Инициализация и разблокировка вашего $SEC_VAULT_ADDR и запись ключей в $VAULT_ADDR $VAULT_WRITE_PATH")
	fmt.Println("  - ./hydra unseal           - только разблокировка $SEC_VAULT_ADDR с использованием переменных из $VAULT_ADDR $VAULT_SECRET_PATH")
	fmt.Println("  - ./hydra inject           - инъекция секретов из $VAULT_ADDR $VAULT_SECRET_PATH в файл окружения")
	fmt.Println("  - ./hydra okd-sync         - извлечение всех токенов авторизации из учетных записей служб в указанных пространствах имен и запись их в $VAULT_ADDR по пути $VAULT_WRITE_PATH + /$OC_CLUSTER/NAMESPACE/SERVICEACCOUNT")
	fmt.Println("  - ./hydra backup           - Рекурсивное извлечение всех секретов из пути, указанного в VAULT_BACKUP_PATH, и запись их в SEC_VAULT_ADDR с пересозданием пространства имен и комментарием о дате резервного копирования.")
	fmt.Println("  - ./hydra help             - вывод этого сообщения о помощи")

	fmt.Println("\nОбязательные переменные окружения:")
	fmt.Println("  - VAULT_ADDR               : https://vault.***.ru                   # (обязательно) URL master сервера Vault")
	fmt.Println("  - SEC_VAULT_ADDR           : https://vault.***.ru                   # (обязательно, если вызван init/unseal/backup) URL Second сервера Vault")
	fmt.Println("  - VAULT_WRITE_PATH         : mysecret/path1                         # **(обязательно, если вызван init/unseal/okd-sync) Путь для записи ключей")
	fmt.Println("  - VAULT_AUTH_ROLE          : dev                                    # (обязательно, если используется JWT) Роль аутентификации в Primary Vault")
	fmt.Println("  - SEC_VAULT_AUTH_ROLE      : sec-dev                                # (обязательно, если используется JWT) Роль аутентификации в Second Vault")
	fmt.Println("  - VAULT_SECRET_PATH        : mysecret/path1 mysecret/path2          # **(обязательно) Пробелами разделенный список путей секретов")

	fmt.Println("\nНеобязательные переменные окружения:")
	fmt.Println("  - VAULT_TOKEN              : MYPrimaryTOKEN                         # (не обязательно) Токен для авторизации в Primary экземпляр Vault")
	fmt.Println("  - SEC_VAULT_TOKEN          : MYSecondaryTOKEN                       # (не обязательно) Токен для авторизации в Second экземпляр Vault")
	fmt.Println("  - VAULT_AUTH_URL           : auth/MYJWTURL/login                    # (не обязательно) URL для входа в Primary Vault")
	fmt.Println("  - SEC_VAULT_AUTH_URL       : auth/MYJWTURL/login                    # (не обязательно) URL для входа в Second Vault")
	fmt.Println("  - VAULT_FILES_PATH         : mydir                                  # **(не обязательно) Пользовательский путь для файлов")
	fmt.Println("  - VAULT_K8S_AUTH           : true/false                             # **(не обязательно)(по умолчанию false) Включает аутентификацию Kubernetes")
	fmt.Println("  - VAULT_VERBOSE            : 1 (ERROR,INFO,DEBUG - 1,2,3)           # **(по умолчанию 1) Уровень подробности логирования")
	fmt.Println("  - VAULT_CA_PATH            : cert/mycert.cer                        # **(не обязательно) Путь SSL сертификатов")
	fmt.Println("  - VAULT_RECURSIVE          : true/false                             # **(не обязательно)(по умолчанию false) Включает рекурсивное чтение секретов")
	fmt.Println("  - VAULT_REGEX_EXCLUDE      : p-.*?                                  # (не обязательно) Исключение имен секретов с использованием regex")

	fmt.Println("\nДля синхронизации с Openshift/K8S:")
	fmt.Println("  - OC_USERNAME              : tuz_vapupkin                           # (обязательно для okd-sync) Имя пользователя Openshift/K8S")
	fmt.Println("  - OC_PASSWORD              : mY$tRonGPa$$W0rD                       # (обязательно для okd-sync) Пароль Openshift/K8S")
	fmt.Println("  - OC_NAMESPACES            : myns1, myns2, myns3                    # (обязательно для okd-sync) Пространства имен через запятую")
	fmt.Println("  - OC_CLUSTER               : mycluster                              # (обязательно для okd-sync) Имя кластера")

	fmt.Println("\nДля Init/Unseal Vault:")
	fmt.Println("  - VAULT_INIT_SHARES        : 5                                      # (не обязательно)(по умолчанию 5) Количество ключей для инициализации")
	fmt.Println("  - VAULT_INIT_THRESHOLD     : 3                                      # (не обязательно)(по умолчанию 3) Количество ключей для успешной разблокировки")
	fmt.Println("  - SEC_VAULT_UNSEAL_KEY*    : MYUNSEALKEY1                           # (обязательно для unseal) Ключи для успешной разблокировки")

	fmt.Println("\nДополнительные заметки:")
	fmt.Println("  - Убедитесь, что обязательные переменные окружения настроены правильно перед запуском операций Vault.")
	fmt.Println("  - Используйте `VAULT_VERBOSE` для управления уровнем логирования (1 для ERROR, 2 для INFO, 3 для DEBUG).")
	fmt.Println("  - Переменная SEC_VAULT_UNSEAL_KEY* начинается с SEC_VAULT_UNSEAL_KEY1 и заканчивается на SEC_VAULT_UNSEAL_KEY32.")
	fmt.Println("  - **Общие переменные используются для обоих экземпляров Vault.")
}
func processKey(key string) string {
	return strings.ToUpper(key)
}
func processValue(value interface{}) string {
	if strValue, ok := value.(string); ok {
		if strings.Contains(strValue, "\n") {
			// Если есть символ новой строки, всегда бейсим строку
			valueBase64 := base64.StdEncoding.EncodeToString([]byte(strValue))
			if osType == "linux" || osType == "darwin" {
				return "\"" + valueBase64 + "\""
			} else {
				return valueBase64
			}
		}

		// Экранируем знак доллара только в однострочных строках
		strValue = strings.ReplaceAll(strValue, "$", "\\$")
		if osType == "linux" || osType == "darwin" {
			return "\"" + strValue + "\""
		} else {
			return strValue
		}
	}
	if osType == "linux" || osType == "darwin" {
		return "\"" + fmt.Sprintf("%v", value) + "\""
	} else {
		return fmt.Sprintf("%v", value)
	}
}

// Функция для настройки TLS конфигурации
func configureTLS(certsPath string, forHTTP bool) (*tls.Config, *vault.TLSConfig, error) {
	// Проверка на insecure режим
	if insecure == "true" {
		Log(Info, "Выбрана авторизация без сертификата (insecure)")
		if forHTTP {
			return &tls.Config{InsecureSkipVerify: true}, nil, nil
		}
		return nil, &vault.TLSConfig{Insecure: true}, nil
	}

	// Выбор источника сертификата
	var certData []byte
	var err error
	if certsPath != "" {
		Log(Info, fmt.Sprintf("Указан путь для сертификата %s, пробуем TLS", certsPath))
		certData, err = os.ReadFile(certsPath)
		if err != nil {
			return nil, nil, fmt.Errorf("не удалось прочитать сертификат по пути %s: %v", certsPath, err)
		}
	}

	// Декодирование сертификата
	block, _ := pem.Decode(certData)
	if block == nil {
		return nil, nil, fmt.Errorf("не удалось декодировать сертификат")
	}

	// Создание пула сертификатов
	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM(certData) {
		return nil, nil, fmt.Errorf("не удалось добавить сертификат в пул")
	}

	// Возвращаем соответствующую конфигурацию
	if forHTTP {
		return &tls.Config{RootCAs: rootCAs}, nil, nil
	}
	return nil, &vault.TLSConfig{CACertBytes: certData, Insecure: false}, nil
}

// Запрашивает clusterID экземпляра Vault
func getClusterID(client *vault.Client) (string, error) {
	// Выполняем запрос к эндпоинту sys/health
	//req := client.NewRequest("GET", "/v1/sys/health")
	resp, err := client.Logical().ReadRaw("/sys/health")
	if err != nil {
		return "", fmt.Errorf("ошибка при запросе /sys/health: %w", err)
	}
	defer resp.Body.Close()

	// Декодируем ответ
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("ошибка декодирования ответа: %w", err)
	}

	// Получаем cluster_id
	if clusterID, ok := result["cluster_id"].(string); ok {
		return clusterID, nil
	}

	return "", fmt.Errorf("cluster_id не найден в ответе")
}

// Сравнивает clusterID у двух переданных клиентов - если одинаковые вернет true
func checkUniqClusterID(clientSrc *vault.Client, clientDst *vault.Client) (bool, error) {
	clusterIDDST, err := getClusterID(clientDst)
	if err != nil {
		HandleError(err, fmt.Sprintf("Ошибка при проверке ClusterID"), Error)
		return true, err
	}
	clusterIDSRC, err := getClusterID(clientSrc)
	if err != nil {
		HandleError(err, fmt.Sprintf("Ошибка при проверке ClusterID"), Error)
		return true, err
	}
	if clusterIDSRC == clusterIDDST {
		Log(Error, "ClusterID вольтов не должны совпадать! проверьте переменные VAULT_ADDR SEC_VAULT_ADDR")
		return true, nil
	}
	return false, nil
}

// filterString принимает строку и регулярное выражение исключения.
// Если строка совпадает с регулярным выражением, возвращает nil и выводит ошибку.
// Иначе возвращает саму строку.
func excludeString(input string) *string {
	if VaultExcludeRegex != "" {
		// Компилируем регулярное выражение
		re, err := regexp.Compile(VaultExcludeRegex)
		if err != nil {
			// Если регулярное выражение некорректно, выбрасываем панику
			panic(fmt.Sprintf("Некорректное регулярное выражение: %v", err))
		}

		// Проверяем, совпадает ли строка с регулярным выражением
		if re.MatchString(input) {
			// Если совпадает, выводим ошибку и возвращаем nil
			Log(Info, fmt.Sprintf("'%s' попала под regex и будет исключена из списка\n", input))
			return nil
		}
	}
	// Если строка не совпадает с регулярным выражением, возвращаем её
	return &input
}
