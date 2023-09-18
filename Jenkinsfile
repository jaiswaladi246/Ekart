pipeline {
    agent any
     tools{
        jdk  'java'
        maven  'maven'
    }
    environment{
        SCANNER_HOME= tool 'sonar'
    }
    stages {
        stage('Git Checkout') {
            steps {
                checkout scm: [$class: 'GitSCM', branches: [[name: '*/main']], userRemoteConfigs: [[url: 'https://github.com/mallick700/Ekart.git']]]
            }
        }
         stage('COMPILE') {
            steps {
                sh "mvn clean compile"
            }
        }
       stage('OWASP Scan') {
            steps {
                dependencyCheck additionalArguments: '--scan ./ ', odcInstallation: 'dc'
                dependencyCheckPublisher pattern: '**/dependency-check-report.xml'
            }
        }
        stage('sonarqube') {
            steps {
                   withSonarQubeEnv('sonar') {
                     sh ''' $SCANNER_HOME/bin/sonar-scanner -Dsonar.projectName=Shopping-Cart \
                     -Dsonar.java.binaries=. \
                     -Dsonar.projectKey=Shopping-Cart '''
            }
        }
        }     
            stage('Build') {
              steps {
                   sh "mvn clean"
                   sh "mvn package"
            }
        }
    }
}
