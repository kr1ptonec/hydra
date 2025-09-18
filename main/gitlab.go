// Hydra Vault - Инструмент для упрощения интеграции с Hashicorp Vault на стадии CI/CD с поддержкой переменных окружения и аргументов для любых архитектур и операционных систем.
// Автор: Kholodov Alexandr Sergeevich
// maito: murcie1337@gmail.com
// Copyright (c) 2025 Kholodov Alexandr Sergeevich
//
// Лицензия: MIT License

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func setGitLabVars(projectID, token string, vars map[string]string) error {
	gitlabAPIURL := fmt.Sprintf("%s/projects/", gitlabApiUrl)

	for key, value := range vars {
		url := fmt.Sprintf("%s%s/variables", gitlabAPIURL, projectID)
		payload := map[string]string{
			"key":   key,
			"value": value,
		}
		payloadBytes, err := json.Marshal(payload)
		if err != nil {
			return err
		}

		req, err := http.NewRequest("POST", url, bytes.NewBuffer(payloadBytes))
		if err != nil {
			return err
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("PRIVATE-TOKEN", token)

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("Ошибка чтения тела ответа: %s", err)
		}
		if resp.StatusCode == http.StatusCreated {
			continue // Переменная успешно создана, переходим к следующей
		} else if resp.StatusCode == http.StatusBadRequest {
			// Проверяем, существует ли переменная
			var respError map[string]interface{}
			if err := json.Unmarshal(body, &respError); err != nil {
				return fmt.Errorf("Ошибка при чтении тела ответа: %s", err)
			}

			if message, ok := respError["message"].(map[string]interface{}); ok {
				if _, exists := message["key"]; exists {
					// Переменная существует, обновляем ее с помощью метода PUT
					url := fmt.Sprintf("%s%s/variables/%s", gitlabAPIURL, projectID, key)
					req, err := http.NewRequest("PUT", url, bytes.NewBuffer(payloadBytes))
					if err != nil {
						return err
					}

					req.Header.Set("Content-Type", "application/json")
					req.Header.Set("PRIVATE-TOKEN", token)

					resp, err := client.Do(req)
					if err != nil {
						return err
					}
					defer resp.Body.Close()

					if resp.StatusCode != http.StatusOK {
						return fmt.Errorf("Ошибка обновления Gitlab переменных: %s, код ответа: %d, ответ: %s", key, resp.StatusCode, string(body))
					}
				}
			}
		} else {
			return fmt.Errorf("Ошибка создания Gitlab переменных: %s, код ответа: %d, ответ: %s", key, resp.StatusCode, string(body))
		}
	}

	return nil
}
