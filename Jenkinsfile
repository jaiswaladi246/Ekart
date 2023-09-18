pipeline {
    agent any
     tools{
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
                   sh "mvn clean package -DskipTests=true"
            }
        }
          stage('Deploy To Nexus') {
              steps {
                  withMaven(globalMavenSettingsConfig: 'global-settings') {
                  sh "mvn deploy -DskipTests=true"
              }
          }
          }
          stage('Build and Tag Docker Image') {
    steps {
        script {
            withDockerRegistry(credentialsId: 'docker-credd', toolName: 'docker') {
                sh " docker build -t shopping-cart:dev -f docker/Dockerfile . "
                sh "docker tag shopping-cart:dev mallick700/shopping-cart:dev"
            }
        }
    }
}

stage('Push Docker Image') {
    steps {
        script {
           withDockerRegistry(credentialsId: 'docker-credd', toolName: 'docker') {
                sh "docker push mallick700/shopping-cart:dev"
            }
        }
    }
}
}

}
