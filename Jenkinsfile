import java.net.URLDecoder
timeout(time: 15, unit: 'MINUTES') {
    node('asg-workers') {
        def STATUS = 'success'
        def GIT_COMMIT_HASH = ""
        def AUTHOR = ""
        def REPO_URL = ""
        def recipient = 'santhosh.kumar@digitap.ai,sanjay@digitap.ai'
        def sender = 'devops@digitap.ai'
        stage('Checkout Code') {
            checkout scm
            GIT_COMMIT_HASH = sh(script: "git log -n 1 --pretty=format:'%H'", returnStdout: true).trim()
            AUTHOR = sh(script: "git log -n 1 --pretty=format:'%an'", returnStdout: true).trim()
            REPO_URL = sh(script: "git config --get remote.origin.url", returnStdout: true).trim()
            if (REPO_URL.startsWith("git@")) {
                REPO_URL = REPO_URL.replaceAll("git@github.com:", "https://github.com/")
            }
        }
        try {
            echo "Repo author: ${AUTHOR}"
            echo "commit SHA: ${GIT_COMMIT_HASH}"

        } catch (Exception e) {
            STATUS = 'failure'
            echo "✗ Pipeline failed: ${e.message}"
            archiveArtifacts artifacts: 'dependency_vulnerability_report.html', allowEmptyArchive: true
            error("Pipeline failed: ${e.message}")
        } finally {
            postBuildStatusToGitHub(STATUS, GIT_COMMIT_HASH, REPO_URL)
            sendEmailAlert(STATUS, recipient, sender)
            cleanWorkspace()
        }
    }
}