pipeline {
    agent any
     tools{
        jdk  'java'
        maven  'maven'
    }
    
    stages {
        stage('Git Checkout') {
            steps {
                checkout scm: [$class: 'GitSCM', branches: [[name: '*/main']], userRemoteConfigs: [[url: 'https://github.com/mallick700/Ekart.git']]]
            }
        }
         stage('COMPILE') {
            steps {
                sh "mvn clean compile -DskipTests=true"
            }
        }
    }
}
