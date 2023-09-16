pipeline {
    agent any
    
    stages {
        stage('Git Checkout') {
            steps {
                checkout scm: [$class: 'GitSCM', branches: [[name: '*/main']], userRemoteConfigs: [[url: 'https://github.com/mallick700/Ekart.git']]]
            }
        }
        
        stage('Maven Build') {
            steps {
                script {
                    def mavenHome = tool name: 'maven', type: 'maven'
                    def mvnCmd = "${mavenHome}/bin/mvn"
                    
                    sh "${mvnCmd} clean install"
                }
            }
        }
    }
}
