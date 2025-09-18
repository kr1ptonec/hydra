// Hydra Vault - Инструмент для упрощения интеграции с Hashicorp Vault на стадии CI/CD с поддержкой переменных окружения и аргументов для любых архитектур и операционных систем.
// Автор: Kholodov Alexandr Sergeevich
// maito: murcie1337@gmail.com
// Copyright (c) 2025 Kholodov Alexandr Sergeevich

package main

import (
	"fmt"
	"github.com/fatih/color"
	vault "github.com/hashicorp/vault/api"
	"os"
	"strings"
)

const GoVersion = "1.23.4"
const version = "4.0.3"

var (
	showHelp       bool
	token          string
	authPath       string
	authToken      string
	secretpath     string
	vaultNamespace string
	operation      string
	verbosity      int
	verbosityint   int
	red            = color.New(color.FgRed).PrintfFunc()
	green          = color.New(color.FgGreen).PrintfFunc()
	cyan           = color.New(color.FgCyan).PrintfFunc()
	Error          = 1
	Info           = 2
	Debug          = 3

	envsPath          string
	client            *vault.Client
	vaultAddr         = strings.TrimRight(os.Getenv("VAULT_ADDR"), "\r")
	vaultAuthRole     = os.Getenv("VAULT_AUTH_ROLE")
	vaultSecretPaths  = os.Getenv("VAULT_SECRET_PATH")
	vaultIDToken      = os.Getenv("VAULT_ID_TOKEN")
	vaultk8sAuthEnv   = os.Getenv("VAULT_K8S_AUTH")
	vaultk8sToken     = vaultk8s(checkVaultK8sAuthEnv())
	fileFolderPath    = os.Getenv("VAULT_FILES_PATH")
	ciProjectDir      = os.Getenv("CI_PROJECT_DIR") // Для Gitlab
	certsPath         = os.Getenv("VAULT_CA_PATH")
	vaultAuthUrl      = os.Getenv("VAULT_AUTH_URL")
	vaultToken        = os.Getenv("VAULT_TOKEN")
	gitlabGroupID     = os.Getenv("CI_PROJECT_NAMESPACE_ID")
	vaultWritePath    = os.Getenv("VAULT_WRITE_PATH")
	gitlabApiUrl      = os.Getenv("CI_API_V4_URL")
	gitlabProjectID   = os.Getenv("CI_PROJECT_ID")
	gitlabApiToken    = os.Getenv("GITLAB_API_TOKEN")
	backupPath        = os.Getenv("VAULT_BACKUP_PATH")
	osType            = getOS()
	insecure          = os.Getenv("VAULT_INSECURE")
	vaultRecursiveEnv = os.Getenv("VAULT_RECURSIVE")
	VaultExcludeRegex = os.Getenv("VAULT_EXCLUDE_REGEX")
	SecVaultAddr      = os.Getenv("SEC_VAULT_ADDR")
	SecVaultToken     = os.Getenv("SEC_VAULT_TOKEN")
	SecVaultAuthRole  = os.Getenv("SEC_VAULT_AUTH_ROLE")
	SecVaultAuthUrl   = os.Getenv("SEC_VAULT_AUTH_URL")

	/// OPENSHIFT-SYNC ///

	okdUsername  = strings.TrimRight(os.Getenv("OC_USERNAME"), "\r")
	okdPassword  = strings.TrimRight(os.Getenv("OC_PASSWORD"), "\r")
	ocNameSpaces = splitStringToList(os.Getenv("OC_NAMESPACES"), ",")
	ocCluster    = strings.TrimRight(os.Getenv("OC_CLUSTER"), "\r")
	oauthURL     = strings.TrimRight("https://oauth-openshift.apps."+ocCluster+"."+domain, "\r")
	apiURL       = strings.TrimRight("https://api."+ocCluster+"."+domain+":6443", "\r")

	/// Auth Configs ///
	primaryConfig = AuthConfig{
		VaultAddr:  vaultAddr,
		VaultToken: vaultToken,
		K8sToken:   vaultk8sToken,
		IDToken:    vaultIDToken,
		AuthUrl:    vaultAuthUrl,
		VaultRole:  vaultAuthRole,
	}
	secondaryConfig = AuthConfig{
		VaultAddr:  SecVaultAddr,
		VaultToken: SecVaultToken,
		K8sToken:   vaultk8sToken,
		IDToken:    vaultIDToken,
		AuthUrl:    SecVaultAuthUrl,
		VaultRole:  SecVaultAuthRole,
	}
)

func main() {
	if osType == "" {
		HandleError(fmt.Errorf("не удалось определить операционную систему"), "Ошибка при определении ОС", Error)
	} else {
		Log(Debug, "Операционная система: %s", osType)
	}
	HelloMessage()
	switch os.Args[1] {
	case "help":
		{
			printUsage()
		}
	case "init", "unseal":
		if SecVaultAddr == "" || vaultWritePath == "" {
			Log(Debug, fmt.Sprintf("Не заданы необходимые переменные, SEC_VAULT_ADDR: %s, VAULT_WRITE_PATH: %s", SecVaultAddr, vaultWritePath))
			printUsage()
			os.Exit(2)
		} else {
			manageVault(os.Args[1], SecVaultAddr, vaultWritePath)
		}

	case "inject":
		if vaultAddr == "" || vaultSecretPaths == "" {
			Log(Debug, fmt.Sprintf("Не заданы необходимые переменные, VAULT_ADDR: %s, VAULT_SECRET_PATHS: %s", vaultAddr, vaultSecretPaths))
			printUsage()
			os.Exit(2)
		} else {
			inject()
		}
	case "backup":
		if backupPath == "" || SecVaultAddr == "" {
			Log(Debug, fmt.Sprintf("Не заданы необходимые переменные, VAULT_BACKUP_PATH: %s, SEC_VAULT_ADDR: %s", backupPath, SecVaultAddr))
			printUsage()
			os.Exit(2)
		} else {
			backupSecrets(backupPath)

		}
	case "okd-sync":
		if okdUsername == "" || okdPassword == "" || ocNameSpaces == nil || ocCluster == "" {
			Log(Debug, fmt.Sprintf("Не заданы необходимые переменные, проверьте переменные окружения OC_USERNAME, OC_PASSWORD, OC_NAMESPACES: %s, OC_CLUSTER: %s", ocNameSpaces, ocCluster))
			printUsage()
			os.Exit(2)
		} else {
			okdSync()
		}
	default:
		fmt.Println("Ошибка: неизвестный аргумент, ожидается 'help', 'init', 'unseal', 'inject', 'okd-sync', 'backup'")
		os.Exit(2)
	}
}
