@Library('jenkins-lib@main') _
securityPipeline(
  label: '',                          // ou 'docker' / 'linux' se quiser amarrar
  customWorkspace: "${env.JOB_NAME}-ws2",

  // DAST
  zapTarget: 'http://localhost:8080',

  // DefectDojo
  ddUrl: 'http://10.103.1.18:8081',
  ddTokenCredId: 'TOKEN_DEFECTDOJO',
  ddEngSast: '3',
  ddEngDast: '4',

  // Gate
  failOnHighCrit: false               // não bloquear a esteira
)
