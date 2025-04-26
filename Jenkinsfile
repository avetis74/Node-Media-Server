pipeline {
    agent any
    stages {
        stage('hadolint') {
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
        stage('owasp_zap') {
            agent {
                label 'docker-agent-zap'
            }            
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                    script {
                        sh "ls -la . || true"
                        sh "ls -la /zap/ || true"
                        sh """
                            mkdir -p ${ZAP_REPORT_DIR}
                            python3 /zap/zap-full-scan.py -I -j -m 10 -T 60 -t http://192.168.5.3:8089/insecure-bank/ \
                                -x ${ZAP_REPORT} \
                                --hook=/zap/auth_hook.py \
                                -z "auth.loginurl=http://192.168.5.3:8089/insecure-bank/login \
                                    auth.username=${DAST_CREDS_USR} \
                                    auth.password=${DAST_CREDS_PSW} \
                                    auth.username_field=username \
                                    auth.password_field=password \
                                    auth.submit_field=submit"
                            cp ${ZAP_REPORT_DIR}${ZAP_REPORT} ${ZAP_REPORT}
                        """
                        archiveArtifacts artifacts: 'report_site.xml', allowEmptyArchive: true
                        stash(name: 'zap-report', includes: 'report_site.xml')
                    }
                }
            }
        }
        stage('DefectDojo') {
            steps {
                script {
                    // Проверка наличия файлов
                    withCredentials([string(credentialsId: 'defectdojo_api_key', variable: 'DD_API_TOKEN')]) {
                        def scans = [
                            [scanType: 'Hadolint Dockerfile check', file: 'hadolint.json'],
                            [scanType: 'Semgrep JSON Report', file: 'report_semgrep.json'],
                            [scanType: 'Anchore Grype', file: 'sca-image-report.json'],
                            [scanType: 'ZAP Scan', file: 'report_site.xml']
                        ]

                        scans.each { scan ->
                            // Используем переменные через параметризацию
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
                                echo "Security Gate passed. Молодцы, ребята! Так держать!"
                            }
                        }
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

      



