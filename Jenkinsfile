pipeline {
  agent {
    node {
      label 'built-in'
      customWorkspace "${env.JOB_NAME}-ws2"
    }
  }

  options { timestamps(); skipDefaultCheckout(true) }

  parameters {
    booleanParam(name: 'FAIL_ON_HIGH_CRIT', defaultValue: false,
      description: 'Se true, marca UNSTABLE quando houver HIGH/CRITICAL')
    string(name: 'ZAP_TARGET', defaultValue: 'http://localhost:8080',
      description: 'URL alvo para ZAP Baseline (homolog)')
  }

  environment {
    // ===== DefectDojo =====
    DEFECTDOJO_URL   = 'http://10.103.1.18:8081'
    DD_TOKEN         = credentials('TOKEN_DEFECTDOJO')
    DD_ENG_SAST      = '3'
    DD_ENG_DAST      = '4'

    // ===== Caches locais =====
    TRIVY_CACHE_DIR  = "${WORKSPACE}/.trivy-cache"
    SEMGREP_CACHE    = "${WORKSPACE}/.semgrep-cache"
  }

  stages {
    stage('Checkout') {
      steps {
        checkout scm
        sh 'pwd && ls -la'
      }
    }

    stage('Semgrep (SAST)') {
      steps {
        sh '''
          mkdir -p "$SEMGREP_CACHE"
          docker run --rm -u $(id -u):$(id -g) \
            -e SEMGREP_CACHE_PATH=/semgrep-cache \
            -v "$PWD":/src -v "$SEMGREP_CACHE":/semgrep-cache \
            returntocorp/semgrep semgrep scan --config=auto \
            --json --output semgrep-report.json || true
        '''
      }
      post {
        always {
          archiveArtifacts artifacts: 'semgrep-report.json', allowEmptyArchive: true
          script {
            uploadToDojo('Semgrep JSON Report', 'semgrep-report.json', env.DD_ENG_SAST)
            considerUnstable('semgrep-report.json')
          }
        }
      }
    }

    stage('Trivy FS (SCA vuln)') {
      steps {
        sh '''
          mkdir -p "$TRIVY_CACHE_DIR"
          docker run --rm -u $(id -u):$(id -g) \
            -e TRIVY_CACHE_DIR=/trivycache \
            -v "$PWD":/app -v "$TRIVY_CACHE_DIR":/trivycache \
            aquasec/trivy fs /app --scanners vuln \
            --severity HIGH,CRITICAL --format json \
            --output trivy-fs-report.json || true
        '''
      }
      post {
        always {
          archiveArtifacts artifacts: 'trivy-fs-report.json', allowEmptyArchive: true
          script {
            uploadToDojo('Trivy Scan', 'trivy-fs-report.json', env.DD_ENG_SAST)
            considerUnstable('trivy-fs-report.json')
          }
        }
      }
    }

    stage('Gitleaks (Secrets)') {
      steps {
        sh '''
          docker run --rm -u $(id -u):$(id -g) -v "$PWD":/repo \
            zricethezav/gitleaks:latest detect --source=/repo \
            --report-format=json --report-path=/repo/gitleaks-report.json || true
        '''
      }
      post {
        always {
          archiveArtifacts artifacts: 'gitleaks-report.json', allowEmptyArchive: true
          script {
            uploadToDojo('Gitleaks Scan', 'gitleaks-report.json', env.DD_ENG_SAST)
            considerUnstable('gitleaks-report.json')
          }
        }
      }
    }

    stage('ZAP Baseline (DAST)') {
      steps {
        sh '''
          docker run --rm -t -u $(id -u):$(id -g) \
            -v "$PWD":/zap/wrk:rw \
            owasp/zap2docker-stable zap-baseline.py \
              -t "${ZAP_TARGET}" -J zap-report.json || true
        '''
      }
      post {
        always {
          archiveArtifacts artifacts: 'zap-report.json', allowEmptyArchive: true
          script {
            uploadToDojo('OWASP ZAP JSON Report', 'zap-report.json', env.DD_ENG_DAST)
            considerUnstable('zap-report.json')
          }
        }
      }
    }
  }

  post {
    always {
      echo "[status] ${currentBuild.currentResult}"
    }
  }
}

/**
 * Marca UNSTABLE se FAIL_ON_HIGH_CRIT=true e o JSON tiver HIGH/CRITICAL.
 * Heurística simples por regex para evitar dependências de parser/jq.
 */
def considerUnstable(String file) {
  if (!params.FAIL_ON_HIGH_CRIT) return
  if (!fileExists(file)) return
  def txt = readFile(file)
  // procura palavras HIGH/CRITICAL no relatório
  if (txt =~ /CRITICAL|HIGH/) {
    currentBuild.result = 'UNSTABLE'
    echo "[gate] Marcado UNSTABLE por altas/críticas em ${file}"
  }
}

/**
 * Envia relatório ao DefectDojo via API v2 /import-scan/
 * scanType deve ser exatamente um dos tipos suportados:
 *   - 'Semgrep JSON Report'
 *   - 'Trivy Scan'
 *   - 'Gitleaks Scan'
 *   - 'OWASP ZAP JSON Report'
 */
def uploadToDojo(String scanType, String reportPath, String engagementId) {
  if (!fileExists(reportPath)) {
    echo "[dojo] arquivo não existe: ${reportPath}"
    return
  }
  sh """
    curl -sS -X POST "${env.DEFECTDOJO_URL}/api/v2/import-scan/" \
      -H "Authorization: Token ${env.DD_TOKEN}" \
      -F scan_type="${scanType}" \
      -F engagement="${engagementId}" \
      -F file=@${reportPath} \
      -F active=true -F verified=false -F close_old_findings=false \
      -o dojo-response.json || true
  """
  archiveArtifacts artifacts: 'dojo-response.json', allowEmptyArchive: true
  echo "[dojo] enviado: ${scanType} -> engagement ${engagementId}"
}

