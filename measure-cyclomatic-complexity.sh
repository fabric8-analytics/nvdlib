#!/bin/bash

function prepare_venv() {
    # we want tests to run on python3.6
    printf 'checking alias `python3.6` ... ' >&2
    PYTHON=$(which python3.6 2> /dev/null)
    if [ "$?" -ne "0" ]; then
        printf "%sNOT FOUND%s\n" "${YELLOW}" "${NORMAL}" >&2

        printf 'checking alias `python3` ... ' >&2
        PYTHON=$(which python3 2> /dev/null)

        let ec=$?
        [ "$ec" -ne "0" ] && printf "${RED} NOT FOUND ${NORMAL}\n" && return $ec
    fi

    printf "%sOK%s\n" "${GREEN}" "${NORMAL}" >&2

    ${PYTHON} -m venv "venv" && source venv/bin/activate && pip install pycodestyle >&2
}

[ "$NOVENV" == "1" ] || prepare_venv || exit 1

radon cc -s -a -i venv .

if [[ "$1" == "--fail-on-error" ]]
then
    defects="$(radon cc -s -n D -i venv . | wc -l)"
    if [[ $defects -gt 0 ]]
    then
        echo "File(s) with too high cyclomatic complexity detected!"
        exit 1
    fi
fi
