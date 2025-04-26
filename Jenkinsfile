pipeline {
    agent any
    environment {
        // Пример объявления переменных (замените на актуальные)
        DOCKER_HUB_REPO = 'your/repo'
        DOCKER_IMAGE_TAG = 'latest'
        ZAP_REPORT_DIR = './zap-reports/'
        ZAP_REPORT = 'report_site.xml'
        DD_URL = 'https://defectdojo.example.com'
    }
    stages {
        stage('hadolint') {
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
        // Остальные стадии (аналогичные исправления)...
        stage('owasp_zap') {
            agent { label 'docker-agent-zap' }
            steps {
                script {
                    sh """
                        mkdir -p "${ZAP_REPORT_DIR}"
                        python3 /zap/zap-full-scan.py -I -j -m 10 -T 60 -t http://192.168.5.3:8089/insecure-bank/ \
                            -x "${ZAP_REPORT_DIR}/${ZAP_REPORT}" \
                            --hook=/zap/auth_hook.py \
                            -z "auth.loginurl=http://192.168.5.3:8089/insecure-bank/login ..."
                        cp "${ZAP_REPORT_DIR}/${ZAP_REPORT}" .
                    """
                    archiveArtifacts artifacts: "${ZAP_REPORT}", allowEmptyArchive: true
                    stash(name: 'zap-report', includes: "${ZAP_REPORT}")
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
