pipeline {
    agent any
    environment {
        // Пример объявления переменных (замените на актуальные)
        DOCKER_HUB_REPO = 'avetis74/node-media-server'
        DOCKER_IMAGE_TAG = 'latest'
        ZAP_REPORT_DIR = './zap-reports/'
        ZAP_REPORT = 'report_site.xml'
        DD_URL = 'https://s410-exam.cyber-ed.space:8083'
        DOCKER_HUB_CREDS_PSW = 'dckr_pat_OCWAhXGnlo9pP5fpInJRUnh2HrU'
        DOCKER_HUB_CREDS_USR = 'avetis74'
        DD_API_TOKEN = 'Authorization: Token 5c45847565eea7c9c5551f49ad8d72c64a72fa36'
        DT_API_TOKEN = 'odt_SfCq7Csub3peq7Y6lSlQy5Ngp9sSYpJl'
        TRIVY_CACHE_DIR = '.trivycache'
        
    }
    parameters {
        choice(
            name: 'STAGE',
            choices: [
                'all',
                'hadolint',
                'build',
                'sast-semgrep',
                'owasp_zap',
                'dependency_track',
                'trivy',
                'defectdojo',
                'security_gate',
                'Toxic_Repo_Check',
            ],
            description: 'Выберите "all" для выполнения всех стадий или конкретную стадию'
        )
        booleanParam(
            name: 'ALLOW_FAILURE',
            defaultValue: true,
            description: 'Разрешить продолжение пайплайна при ошибке в стадии'
        )
    }

    stages {
        stage('hadolint') {
            when {
                beforeAgent true
                anyOf {
                    expression { params.STAGE == 'all' }
                    expression { params.STAGE == 'hadolint' }
                }
            }
            options {
                timeout(time: 1, unit: 'HOURS')  // Таймаут для stage
                retry(0)  // Отключаем повторные попытки
            }
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                    script {
                        sh """
                            wget -O /usr/local/bin/hadolint https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-x86_64
                            chmod +x /usr/local/bin/hadolint
                            hadolint Dockerfile -f json > hadolint.json || exit 0
                        """
                        archiveArtifacts artifacts: 'hadolint.json', allowEmptyArchive: true
                    }
                }        
            }
        }

        stage('sast-semgrep') {
            when {
                beforeAgent true
                anyOf {
                    expression { params.STAGE == 'all' }
                    expression { params.STAGE == 'sast-semgrep' }
                }
            }
            options {
                timeout(time: 1, unit: 'HOURS')  // Таймаут для stage
                retry(0)  // Отключаем повторные попытки
            }
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                    script {
                        sh '''
                            apk add --update python3 py3-pip py3-virtualenv
                            python3 -m venv venv
                            . venv/bin/activate
                            pip install semgrep
                            venv/bin/semgrep --config=auto --verbose --json > report_semgrep.json 
                            '''
                        archiveArtifacts artifacts: 'report_semgrep.json', allowEmptyArchive: true
                    }
                }
            }
        }

        stage('build') {
            when {
                beforeAgent true
                anyOf {
                    expression { params.STAGE == 'all' }
                    expression { params.STAGE == 'build' }
                }
            }
            options {
                timeout(time: 1, unit: 'HOURS')  // Таймаут для stage
                retry(0)  // Отключаем повторные попытки
            }
            environment {
                DOCKER_HUB_CREDS = credentials('docker_hub')
            }
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                    script {
                        env.COMMIT_HASH = sh(script: "git rev-parse --short HEAD", returnStdout: true).trim()                    
                        sh """
                            docker build -t ${DOCKER_HUB_REPO}:${DOCKER_IMAGE_TAG} .
                            docker tag ${DOCKER_HUB_REPO}:${DOCKER_IMAGE_TAG} ${DOCKER_HUB_REPO}:${env.COMMIT_HASH}
                            echo "${DOCKER_HUB_CREDS_PSW}" | docker login -u "${DOCKER_HUB_CREDS_USR}" --password-stdin
                            docker push ${DOCKER_HUB_REPO}:${DOCKER_IMAGE_TAG}
                            docker push ${DOCKER_HUB_REPO}:${env.COMMIT_HASH}
                            docker logout
                        """
                    }
                }
            }
        }
        
        stage('trivy') {
            when {
                beforeAgent true
                anyOf {
                    expression { params.STAGE == 'all' }
                    expression { params.STAGE == 'trivy' }
                }
            }
            options {
                timeout(time: 1, unit: 'HOURS')  // Таймаут для stage
                retry(0)  // Отключаем повторные попытки
            }
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                    script {
                        sh '''
                           apk add --update curl jq

                            # Получаем версию Trivy через jq (более надежный способ)
                            export TRIVY_VERSION=$(curl -s "https://api.github.com/repos/aquasecurity/trivy/releases/latest" | jq -r '.tag_name' | sed 's/^v//')
                            echo "Устанавливаем Trivy версии: $TRIVY_VERSION"
                            # Скачиваем и распаковываем Trivy
                            curl -L "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" -o trivy.tar.gz
                            tar -zxvf trivy.tar.gz
                            rm trivy.tar.gz                           
                            # Проверяем версию
                            ./trivy --version
                            # Анализируем образ
                            docker pull "${DOCKER_HUB_REPO}:${DOCKER_IMAGE_TAG}"
                            ./trivy image --exit-code 1 "${DOCKER_HUB_REPO}:${DOCKER_IMAGE_TAG}" cyclonedx --output sbom.cyclonedx.json
                            '''
                        archiveArtifacts artifacts: 'sbom.cyclonedx.json', allowEmptyArchive: true
                    }
                }
            }
        }
        
        stage('owasp_zap') {
            when {
                beforeAgent true
                anyOf {
                    expression { params.STAGE == 'all' }
                    expression { params.STAGE == 'owasp_zap' }
                }
            }
            options {
                timeout(time: 1, unit: 'HOURS')  // Таймаут для stage
                retry(0)  // Отключаем повторные попытки
            }
            steps {
                script {
                    sh """
                        # Устанавливаем зависимости
                        apk add --no-cache openjdk11-jre-headless python3 py3-pip curl git
                        pip3 install python-owasp-zap-v2.4 --break-system-packages

                        # Скачиваем и распаковываем ZAP
                        ZAP_VERSION=\$(curl -s "https://api.github.com/repos/zaproxy/zaproxy/releases/latest" | grep -oP '"tag_name": "\\K[^"]+')
                        curl -sL "https://github.com/zaproxy/zaproxy/releases/download/\${ZAP_VERSION}/ZAP_\${ZAP_VERSION#v}_Linux.tar.gz" | tar -xz -C /opt
                        ln -s /opt/ZAP_*/zap.sh /usr/local/bin/zap

                        # Создаем директорию для отчетов
                        mkdir -p "${ZAP_REPORT_DIR}"

                        # Запускаем сканирование
                        python3 /opt/ZAP_*/zap-full-scan.py \
                            -I -j -m 10 -T 60 \
                            -t "https://s410-exam.cyber-ed.space:8084" \
                            -x "${ZAP_REPORT_DIR}/${ZAP_REPORT}"
                        # Копируем отчет
                        cp "${ZAP_REPORT_DIR}/${ZAP_REPORT}" .
                    """
                    archiveArtifacts artifacts: "${ZAP_REPORT}", allowEmptyArchive: true
                    stash(name: 'zap-report', includes: "${ZAP_REPORT}")
                }
            }
        }

        stage('dependency_track') {
            when {
                beforeAgent true
                anyOf {
                    expression { params.STAGE == 'all' }
                    expression { params.STAGE == 'dependency_track' }
                }
            }
            options {
                timeout(time: 1, unit: 'HOURS')  // Таймаут для stage
                retry(0)  // Отключаем повторные попытки
            }
            steps {
                script {
                    sh """
                        apk --update add openjdk11 maven curl nodejs npm
                        npm install -g @cyclonedx/cdxgen
                        cdxgen -r -o ${WORKSPACE}/dependency-track-report.json
                        curl -k -vv -X POST https://s410-exam.cyber-ed.space:8080/api/v1/bom \
                        -H "Content-type:multipart/form-data" \
                        -H "X-Api-Key:${DT_API_TOKEN}" \
                        -F "autoCreate=true" \
                        -F "projectName=${JOB_NAME}" \
                        -F "projectVersion=${BUILD_NUMBER}" \
                        -F "bom=@${WORKSPACE}/dependency-track-report.json"
                    """
                    archiveArtifacts artifacts: "bom.json", allowEmptyArchive: true
                }
            }
        }
        
        stage('DefectDojo') {
            steps {
                script {
                        def scans = [
                            [scanType: 'Hadolint Dockerfile check', file: 'hadolint.json'],
                            [scanType: 'Semgrep JSON Report', file: 'report_semgrep.json'],
                            [scanType: 'ZAP Scan', file: "${ZAP_REPORT}"],
                            [scanType: 'Trivy', file: "${ZAP_REPORT}"],
                            [scanType: 'Trivy Scan', file: "sbom.cyclonedx.json"],
                            [scanType: 'Dependency Track Finding Packaging Format (FPF) Export', file: "dependency-track-report.json"],
                        ]
                        scans.each { scan ->
                            if (fileExists(scan.file)) {
                                sh """
                                    curl -v -X POST "\${DD_URL}/import-scan/" \
                                    -H "Authorization: Token ${DD_API_TOKEN}" \
                                    -H "Content-Type: multipart/form-data" \
                                    -F "scan_type=${scan.scanType}" \
                                    -F "file=@${scan.file}" \
                                    -F "engagement=5" \
                                    -F "verified=true" \
                                    -F "skip_duplicates=true"
                                """
                    
                        }
                    }
                }
            }
        }
        stage('security_gate') {
            steps {
                catchError(buildResult: 'FAILED', stageResult: 'FAILED') {
                    script { 
                        sh 'apk add --update jq'
                        withCredentials([string(credentialsId: 'defectdojo_api_key', variable: 'DD_API_TOKEN')]) {
                            def findings = sh(script: """
                                curl -X GET "${DD_URL}/findings/?severity=High,Critical&risk_accepted=false&engagement=5" \
                                -H "Authorization: Token ${DD_API_TOKEN}" \
                                | jq '.count'
                            """, returnStdout: true).trim()

                            if (findings.toInteger() > 0) {
                                error "Security Gate failed due to ${findings} High/Critical vulnerabilities. Пишите код корректно, блин!"
                            } else {
                                echo "Security Gate passed."
                            }
                        }
                    }
                }
            }
        }

        stage('Toxic_Repo_Check') {
            when {
                beforeAgent true
                anyOf {
                    expression { params.STAGE == 'all' }
                    expression { params.STAGE == 'Toxic_Repo_Check' }
                }
            }
            options {
                timeout(time: 1, unit: 'HOURS')  // Таймаут для stage
                retry(0)  // Отключаем повторные попытки
            }
            steps {
                script {
                    // Получаем информацию о репозитории
                    def repoUrl = scm.getUserRemoteConfigs()[0].getUrl()
                    def repoName = repoUrl.replaceFirst(/^https?:\/\/[^\/]+\//, "").replace(/\.git$/, "")
                    
                    echo "Проверяем репозиторий ${repoName} на toxic-repos.ru..."
                    
                    // Выполняем запрос к API toxic-repos.ru
                    def response = httpRequest url: "https://toxic-repos.ru/api/v1/check?repo=${URLEncoder.encode(repoName, 'UTF-8')}",
                                             validResponseCodes: '200:404'
                    
                    if (response.status == 200) {
                        def result = readJSON text: response.content
                        
                        // Критические проблемы - прерываем сборку
                        def criticalIssues = ['malware', 'ddos', 'broken_assembly']
                        def foundCritical = result.issues.any { issue -> criticalIssues.contains(issue.type) }
                        
                        if (foundCritical) {
                            error "Обнаружены критические проблемы в репозитории: " +
                                  result.issues.findAll { criticalIssues.contains(it.type) }.collect { it.type }.join(', ')
                        }
                        
                        // Не критические проблемы - просто выводим предупреждение
                        def otherIssues = result.issues.findAll { !criticalIssues.contains(it.type) }
                        if (otherIssues) {
                            echo "Обнаружены не критические проблемы:"
                            otherIssues.each { issue ->
                                echo "  - ${issue.type}: ${issue.description}" 
                                echo "    Подробнее: ${issue.details_url}"
                            }
                        } else {
                            echo "Репозиторий чист, проблем не обнаружено"
                        }
                    } else if (response.status == 404) {
                        echo "Информация о репозитории не найдена в базе toxic-repos.ru"
                    } else {
                        echo "Не удалось проверить репозиторий (HTTP ${response.status})"
                    }
                }
            }
        }
    }
    post {
        always {
            // очистка рабочего пространства / раннера
            cleanWs()
        }
        failure {
            echo "Pipeline failed due to security gate violation"
        }
        success {
            echo "Pipeline completed - no High/Critical vuln. found"
        }
    }
}
