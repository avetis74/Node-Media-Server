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

        stage('trivy') {
            agent {
                label 'jenkins-agent-dind'
            }
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
                            apk add --no-cache curl jq

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
            agent { label 'docker-agent-zap' }
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
                        pip3 install python-owasp-zap-v2.4

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
            agent { label 'docker-agent-zap' }
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
                        apk --update add openjdk11 maven curl
                        npm install -g @cyclonedx/cdxgen
                        cdxgen -r -o ${WORKSPACE}/bom.json
                        curl -vv -X POST https://s410-exam.cyber-ed.space:8080/api/v1/bom \
                        -H "Content-type:multipart/form-data" \
                        -H "X-Api-Key:${DT_API_TOKEN}" \
                        -F "autoCreate=true" \
                        -F "projectName=${JOB_NAME}" \
                        -F "projectVersion=${BUILD_NUMBER}" \
                        -F "bom=@${WORKSPACE}/bom.json"
                    """
                    archiveArtifacts artifacts: "bom.json", allowEmptyArchive: true
                }
            }
        }
        
        stage('DefectDojo') {
            steps {
                script {
                    withCredentials([string(credentialsId: 'defectdojo_api_key', variable: 'DD_API_TOKEN')]) {
                        def scans = [
                            [scanType: 'Hadolint Dockerfile check', file: 'hadolint.json'],
                            [scanType: 'Semgrep JSON Report', file: 'report_semgrep.json'],
                            [scanType: 'ZAP Scan', file: "${ZAP_REPORT}"]
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
        }
    }
    post {
        always { cleanWs() }
    }
}
