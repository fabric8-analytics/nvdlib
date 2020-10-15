#!/bin/bash -ex

here="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"

load_jenkins_vars() {
    if [ -e "jenkins-env.json" ]; then
        eval "$(./env-toolkit load -f jenkins-env.json \
                JENKINS_URL \
                GIT_BRANCH \
                GIT_COMMIT \
                BUILD_NUMBER \
                ghprbSourceBranch \
                ghprbActualCommit \
                BUILD_URL \
                ghprbPullId)"
    fi
}

prep() {
    yum -y update
    yum install -y epel-release
    yum install -y git which gcc python36-devel python36-pip python36-requests openssl-devel
}

load_jenkins_vars
prep

