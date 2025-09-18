// Hydra Vault - Инструмент для упрощения интеграции с Hashicorp Vault на стадии CI/CD с поддержкой переменных окружения и аргументов для любых архитектур и операционных систем.
// Автор: Kholodov Alexandr Sergeevich
// maito: murcie1337@gmail.com
// Copyright (c) 2025 Kholodov Alexandr Sergeevich
//
// Лицензия: MIT License

package main

import (
	"fmt"
	vault "github.com/hashicorp/vault/api"
	"io"
	"os"
)

// Структура для конфигурации авторизации
type AuthConfig struct {
	VaultAddr  string
	VaultToken string
	K8sToken   string
	IDToken    string
	AuthUrl    string
	VaultRole  string
}

// Функция для аутентификации в Vault
func auth(authConfig AuthConfig) (*vault.Client, error) {
	// Проверяем, что адрес Vault задан
	if authConfig.VaultAddr == "" {
		Log(Error, "не задан адрес Vault")
		os.Exit(10)
	}
	Log(Info, fmt.Sprintf("Авторизуемся в %s", authConfig.VaultAddr))
	// Получаем клиента Vault
	client, err := createClient(authConfig.VaultAddr)
	if err != nil {
		Log(Error, fmt.Sprintf("Ошибка при создании клиента Vault: %s", err))
		HandleError(err, "", 10)
	}

	// Если в конфиге задан путь авторизации (authPath), используем его
	authPath := authConfig.AuthUrl
	if authPath == "" {
		// Иначе выбираем путь на основе типа токена
		authPath = selectAuthPathByToken(authConfig)
	}
	// Если используется Vault Token, проверяем его с помощью lookup-self
	if authConfig.VaultToken != "" {
		client.SetToken(authConfig.VaultToken)
		_, err := client.Logical().Read("auth/token/lookup-self")
		if err != nil {
			Log(Error, fmt.Sprintf("Ошибка при проверке токена: %s", err))
			os.Exit(10)
		}
		return client, nil
	}

	// Если не Vault Token, то аутентификация с использованием другого токена (K8s или ID)
	token := selectToken(authConfig)
	if token == "" {
		HandleError(err, "не выбран токен для аутентификации", 1)
	}

	// Аутентификация с K8s или ID Token
	loginResp, err := client.Logical().Write(authPath, map[string]interface{}{
		"jwt":  token,
		"role": authConfig.VaultRole,
	})
	if err != nil {
		Log(Error, fmt.Sprintf("Ошибка при аутентификации с токеном: %s", err))
		HandleError(err, "", 10)
	}

	client.SetToken(loginResp.Auth.ClientToken)
	return client, nil
}

// Определяет путь аутентификации на основе доступных токенов
func selectAuthPathByToken(authConfig AuthConfig) string {
	switch {
	case authConfig.VaultToken != "":
		return "/" // Vault Token (root path)
	case authConfig.K8sToken != "":
		return "auth/kubernetes/login" // Kubernetes Token
	case authConfig.IDToken != "":
		return "auth/git/login" // ID Token
	default:
		return ""
	}
}

// Определяет приоритет на основе доступных токенов
func selectToken(authConfig AuthConfig) string {
	switch {
	case authConfig.VaultToken != "":
		return authConfig.VaultToken
	case authConfig.K8sToken != "":
		return authConfig.K8sToken
	case authConfig.IDToken != "":
		return authConfig.IDToken
	default:
		return ""
	}
}

// Функция для создания клиента Vault
func createClient(vaultAddr string) (*vault.Client, error) {
	clientConfig := &vault.Config{Address: vaultAddr}
	_, tlsConfig, err := configureTLS(certsPath, false)
	if err != nil {
		HandleError(err, "ошибка настройки TLS:", 1)
	}

	err = clientConfig.ConfigureTLS(tlsConfig)
	if err != nil {
		HandleError(err, "ошибка при конфигурации TLS:", 1)
	}

	client, err := vault.NewClient(clientConfig)
	if err != nil {
		Log(Error, fmt.Sprintf("ошибка при создании клиента Vault: %s", err))
		HandleError(err, "", 10)
	}
	return client, nil
}

// Читает token serviceaccount внутри пода для авторизации по k8s
func vaultk8s(vaultk8sAuth bool) string {
	if !vaultk8sAuth {
		return ""
	}
	filePath := "./var/run/secrets/kubernetes.io/serviceaccount/token"
	file, err := os.Open(filePath)
	if err != nil {
		HandleError(err, "Невозможно открыть токен service account:", 1)
		return ""
	}
	defer file.Close()

	fileContent, err := io.ReadAll(file)
	if err != nil {
		HandleError(err, "Невозможно прочитать токен service account:", 1)
		return ""
	}

	return string(fileContent)
}
