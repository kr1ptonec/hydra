// Hydra Vault - Инструмент для упрощения интеграции с Hashicorp Vault на стадии CI/CD с поддержкой переменных окружения и аргументов для любых архитектур и операционных систем.
// Автор: Kholodov Alexandr Sergeevich
// maito: murcie1337@gmail.com
// Copyright (c) 2025 Kholodov Alexandr Sergeevich
//
// Лицензия: MIT License

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	vault "github.com/hashicorp/vault/api"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

func okdSync() {
	client, err := auth(primaryConfig)
	if err != nil {
		HandleError(err, "Ошибка при аутентификации", Error)
		os.Exit(1)
	}
	okdClient, err := createHTTPClient(certsPath)
	if err != nil {
		Log(Error, fmt.Sprintf("Ошибка при создании клиента: %s", err))
		HandleError(err, "", 1)
	}
	sha256Token, csrfToken, err := getOkdToken(okdClient, okdUsername, okdPassword, oauthURL+"/oauth/token/request")
	if err != nil {
		HandleError(err, "Ошибка при получении sha256Token, csrfToken", Error)
	}
	okdToken, err := FinalOkdToken(okdClient, okdUsername, okdPassword, oauthURL, sha256Token, csrfToken)
	if err != nil {
		HandleError(err, "Ошибка при аутентификации в OKD", Error)
	}
	err = WriteTokensToVault(okdClient, client, okdToken, apiURL, ocCluster, ocNameSpaces)
	if err != nil {
		HandleError(err, "Ошибка при аутентификации", Error)
	}
}

// getToken для получения токенов codeToken csrfToken
func getOkdToken(okdClient *http.Client, username, password, url string) (string, string, error) {
	authHeader := fmt.Sprintf("%s:%s", username, password)
	encodedAuthHeader := base64.StdEncoding.EncodeToString([]byte(authHeader))
	authHeaderValue := fmt.Sprintf("Basic %s", encodedAuthHeader)

	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		HandleError(err, "ошибка при создании запроса:", 1)
	}
	req.Header.Set("Authorization", authHeaderValue)

	resp, err := okdClient.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
			HandleError(err, "таймаут 500ms превышен", 1)
		}
		//return "", "", fmt.Errorf("ошибка при запросе токена: %s", err)
		HandleError(err, "ошибка при запросе токена:", 1)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(resp.Body)

	csrfToken := resp.Cookies()[0].Value

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		HandleError(err, "ошибка чтения тела ответа:", 1)
	}

	sha256Token := extractTokens(string(body))
	if sha256Token == "" {
		Log(Error, "токен не найден")
		os.Exit(1)
	}

	return sha256Token, csrfToken, nil
}

// extractTokens для извлечения токена
func extractTokens(body string) string {
	sha256Regex := regexp.MustCompile(`value="(sha256~[^"]+)"`)
	sha256Match := sha256Regex.FindStringSubmatch(body)
	if len(sha256Match) > 1 {
		return sha256Match[1]
	}

	return ""
}
func createHTTPClient(certsPath string) (*http.Client, error) {
	tlsConfig, _, err := configureTLS(certsPath, true)
	if err != nil {
		HandleError(err, "ошибка настройки TLS: ", 1)
	}

	tr := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	return &http.Client{Transport: tr, Timeout: 5 * time.Second}, nil
}

// FinalOkdToken для запроса извлечения конечного API токена
func FinalOkdToken(okdClient *http.Client, username, password, openshiftURL, sha256Token, csrfToken string) (string, error) {
	authHeader := fmt.Sprintf("%s:%s", username, password)
	encodedAuthHeader := base64.StdEncoding.EncodeToString([]byte(authHeader))
	authHeaderValue := fmt.Sprintf("Basic %s", encodedAuthHeader)

	// Подготовка запроса POST и добавление cookie и параметров
	req, err := http.NewRequest(
		"POST",
		openshiftURL+"/oauth/token/display?code="+sha256Token+"&csrf="+csrfToken,
		nil,
	)
	if err != nil {
		HandleError(err, "ошибка при создании запроса: ", 1)
	}

	req.Header.Set("Cookie", "csrf="+csrfToken)
	req.Header.Set("Authorization", authHeaderValue)

	respDisplay, err := okdClient.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
			HandleError(err, "таймаут 500ms превышен", 1)
		}
		//return "", fmt.Errorf("ошибка при запросе отображения токена: %s", err)
		HandleError(err, "ошибка при запросе отображения токена: ", 1)
	}
	defer respDisplay.Body.Close()

	bodyDisplay, err := io.ReadAll(respDisplay.Body)
	if err != nil {
		//return "", fmt.Errorf("ошибка чтения тела ответа отображения токена: %s", err)
		HandleError(err, "ошибка чтения тела ответа отображения токена: ", 1)
	}

	// Извлечение токена из ответа
	tokenRegex := regexp.MustCompile(`<code>(sha256~[^<]+)</code>`)
	match := tokenRegex.FindStringSubmatch(string(bodyDisplay))

	if len(match) > 1 {
		//fmt.Println(match[1])
		return match[1], nil
	} else {
		Log(Error, "Токен не найден")
		os.Exit(1)
	}
	return "", nil
}

// ################################# Перебор секретов и их токенов #####################################

func makeRequest(okdClient *http.Client, url, token, method string, data map[string]interface{}) (*http.Response, error) {
	var req *http.Request
	var err error

	if data != nil && (method == "POST" || method == "PUT") {
		jsonData, err := json.Marshal(data)
		if err != nil {
			HandleError(err, "Ошибка при десериализации json: ", 1)
		}
		req, err = http.NewRequest(method, url, bytes.NewBuffer(jsonData))
		if err != nil {
			HandleError(err, "Ошибка при обработке создания request: ", 1)
		}
		req.Header.Set("Content-Type", "application/json")
	} else {
		req, err = http.NewRequest(method, url, nil)
	}

	if err != nil {
		HandleError(err, "Ошибка при создании request: ", 1)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := okdClient.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
			HandleError(err, "таймаут 500ms превышен", 1)
		}
		HandleError(err, "Ошибка при создании request клиента: ", 1)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("ошибка HTTP: статус %d", resp.StatusCode)
	}

	return resp, nil
}

func getSecretNames(okdClient *http.Client, token, url string) ([]string, error) {
	resp, err := makeRequest(okdClient, url, token, "GET", nil)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(resp.Body)

	var secretList struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		} `json:"items"`
	}

	err = json.NewDecoder(resp.Body).Decode(&secretList)
	if err != nil {
		return nil, err
	}

	var secretNames []string
	for _, secret := range secretList.Items {
		secretNames = append(secretNames, secret.Metadata.Name)
	}

	return secretNames, nil
}

func secretInfo(secret map[string]interface{}) (string, error) {
	tokenData, exists := secret["data"].(map[string]interface{})["token"]
	if exists {
		tokenBytes, err := base64.StdEncoding.DecodeString(tokenData.(string))
		if err != nil {
			return "", fmt.Errorf("ошибка декодирования токена: %s\n", err)
		}
		return string(tokenBytes), nil
	}
	Log(Error, "токен не найден в секрете")
	return "", fmt.Errorf("токен не найден в секрете")
}

func splitStringToList(input string, separator string) []string {
	result := strings.Split(input, separator)
	for i, val := range result {
		result[i] = strings.TrimSpace(val)
	}
	return result
}

func WriteTokensToVault(okdClient *http.Client, client *vault.Client, token, openshiftURL, ocCluster string, namespaces []string) error {
	for _, namespace := range namespaces {
		serviceAccounts, err := getServiceAccounts(okdClient, token, openshiftURL+"/api/v1/namespaces/"+namespace+"/serviceaccounts")
		if err != nil {
			Log(Error, fmt.Sprintf("ошибка при получении сервисных аккаунтов в неймспейсе %s: %s\n", namespace, err))
			continue
		}

		for _, sa := range serviceAccounts {
			// Проверяем наличие секрета с токеном для сервисного аккаунта
			tokenValue, err := getTokenFromSecret(okdClient, token, openshiftURL, namespace, sa)
			if err != nil {
				// Если секрет не существует, создаем новый и извлекаем токен
				Log(Info, fmt.Sprintf("Токен для serviceaccount %s не существует в неймспейсе %s, создаю новый", sa, namespace))
				tokenValue, err = createServiceAccountToken(okdClient, token, openshiftURL, namespace, sa)
				if err != nil {
					Log(Error, fmt.Sprintf("ошибка при создании/извлечении токена для сервисного аккаунта %s в неймспейсе %s: %s\n", sa, namespace, err))
					continue
				}
				Log(Info, fmt.Sprintf("%s-token создан успешно в неймспейсе %s", sa, namespace))
			}

			// Записываем токен в Vault
			vaultPath := fmt.Sprintf("%s/%s/%s/%s", vaultWritePath, ocCluster, namespace, sa)
			err = writeTokenToVault(client, vaultPath, tokenValue, sa, namespace)
			if err != nil {
				Log(Error, fmt.Sprintf("ошибка при записи токена в Vault для сервисного аккаунта %s в неймспейсе %s: %s\n", sa, namespace, err))
			}
		}
	}
	return nil
}

// Функция для создания токена сервисного аккаунта или извлечения из существующего секрета
func createServiceAccountToken(okdClient *http.Client, token, openshiftURL, namespace, serviceAccountName string) (string, error) {
	// Если секрет не существует, создаем новый секрет
	url := fmt.Sprintf("%s/api/v1/namespaces/%s/secrets", openshiftURL, namespace)
	secretName := fmt.Sprintf("%s-token", serviceAccountName)
	secret := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata": map[string]interface{}{
			"name": secretName,
			"annotations": map[string]interface{}{
				"kubernetes.io/service-account.name": serviceAccountName,
			},
		},
		"type": "kubernetes.io/service-account-token",
	}

	resp, err := makeRequest(okdClient, url, token, "POST", secret)
	if err != nil {
		return "", fmt.Errorf("ошибка при отправке запроса: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		bodyString := string(bodyBytes)
		return "", fmt.Errorf("ошибка при создании секрета: %v, %s", resp.StatusCode, bodyString)
	}

	var createdSecret map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&createdSecret)
	if err != nil {
		return "", fmt.Errorf("ошибка при декодировании ответа: %v", err)
	}

	// Извлекаем токен из созданного секрета
	return getTokenFromSecret(okdClient, token, openshiftURL, namespace, serviceAccountName)
}

// Функция для получения токена из секрета
func getTokenFromSecret(okdClient *http.Client, token, openshiftURL, namespace, serviceAccountName string) (string, error) {
	secretNames, err := getSecretNames(okdClient, token, openshiftURL+"/api/v1/namespaces/"+namespace+"/secrets")
	if err != nil {
		return "", fmt.Errorf("ошибка при получении секретов в неймспейсе %s: %s\n", namespace, err)
	}

	for _, secretName := range secretNames {
		resp, err := makeRequest(okdClient, openshiftURL+"/api/v1/namespaces/"+namespace+"/secrets/"+secretName, token, "GET", nil)
		if err != nil {
			Log(Error, fmt.Sprintf("ошибка при получении секрета %s в неймспейсе %s: %s\n", secretName, namespace, err))
			continue
		}
		defer resp.Body.Close()

		var secret map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&secret)
		if err != nil {
			Log(Error, fmt.Sprintf("ошибка чтения тела ответа для секрета %s в неймспейсе %s: %s\n", secretName, namespace, err))
			continue
		}

		secretType, typeExists := secret["type"].(string)
		if typeExists && secretType == "kubernetes.io/service-account-token" {
			saName, saExists := secret["metadata"].(map[string]interface{})["annotations"].(map[string]interface{})["kubernetes.io/service-account.name"].(string)
			if saExists && saName == serviceAccountName {
				tokenValue, err := secretInfo(secret)
				if err != nil {
					Log(Error, fmt.Sprintf("ошибка при извлечении информации о секрете %s в неймспейсе %s: %s\n", secretName, namespace, err))
					continue
				}
				return tokenValue, nil
			}
		}
	}

	return "", fmt.Errorf("секрет с токеном для сервисного аккаунта %s в неймспейсе %s не найден", serviceAccountName, namespace)
}

// Функция для записи токена в Vault
func writeTokenToVault(client *vault.Client, vaultPath, tokenValue, secretName, namespace string) error {
	Log(Info, fmt.Sprintf("%s %s ", vaultPath, "Done"))
	data := map[string]interface{}{
		"OPENSHIFT_TOKEN":  tokenValue,
		"OPENSHIFT_SERVER": apiURL,
	}
	result, err := writeSecret(client, vaultPath, data)
	if err != nil {
		return fmt.Errorf("ошибка при записи токена в Vault для секрета %s в неймспейсе %s: %s", secretName, namespace, err)
	}
	Log(Info, fmt.Sprintf("Результат : %s", result))
	return nil
}

// Пример функции для получения списка сервисных аккаунтов
func getServiceAccounts(okdClient *http.Client, token, url string) ([]string, error) {
	resp, err := makeRequest(okdClient, url, token, "GET", nil)
	if err != nil {
		return nil, fmt.Errorf("ошибка при выполнении запроса: %v", err)
	}
	defer resp.Body.Close()

	var serviceAccountsResponse struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		} `json:"items"`
	}
	err = json.NewDecoder(resp.Body).Decode(&serviceAccountsResponse)
	if err != nil {
		return nil, fmt.Errorf("ошибка при декодировании ответа: %v", err)
	}

	var serviceAccounts []string
	for _, item := range serviceAccountsResponse.Items {
		serviceAccounts = append(serviceAccounts, item.Metadata.Name)
	}

	return serviceAccounts, nil
}
