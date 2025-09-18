// Hydra Vault - Инструмент для упрощения интеграции с Hashicorp Vault на стадии CI/CD с поддержкой переменных окружения и аргументов для любых архитектур и операционных систем.
// Автор: Kholodov Alexandr Sergeevich
// maito: murcie1337@gmail.com
// Copyright (c) 2025 Kholodov Alexandr Sergeevich

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

const contributeUrl = "https://github.com/kr1ptonec/hydra" // My contribute Url
const domain = "mydomain.local"                            // YOUR DOMAIN HERE
const RootCertPathNexus = "https://mycertpath/root.crt"    // Your static path to certificate

// RootCertContent читает содержимое сертификата с указанного пути в Nexus сохранения на диск.
func RootCertContent() (string, error) {
	client := &http.Client{Timeout: 5 * time.Second}

	content, err := fetchCertFromURL(client, RootCertPathNexus)
	if err == nil {
		return content, nil
	}

	return "", fmt.Errorf("не удалось получить сертификат: %v", err)
}

// fetchCertFromURL выполняет HTTP GET-запрос и возвращает содержимое сертификата.
func fetchCertFromURL(client *http.Client, url string) (string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("ошибка при создании запроса: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
			return "", fmt.Errorf("таймаут при запросе к %s", url)
		}
		return "", fmt.Errorf("ошибка при выполнении запроса к %s: %v", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("сервер %s вернул статус %d", url, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("ошибка при чтении ответа от %s: %v", url, err)
	}

	return string(body), nil
}
