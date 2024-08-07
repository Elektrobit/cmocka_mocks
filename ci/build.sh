#!/bin/bash
set -e -u

CMD_PATH=$(realpath "$(dirname "$0")")
BASE_DIR=${CMD_PATH%/*}
CMAKE_PARAM=${CMAKE_PARAM:-""}
NINJA_PARAM=${NINJA_PARAM:-"-j$(nproc)"}
SOURCES_URI=${SOURCES_URI:-https://github.com/Elektrobit/}

CMOCKA_EXTENSIONS_REPO_NAME=${CMOCKA_EXTENSIONS_REPO_NAME:-cmocka_extensions.git}
CMOCKA_EXTENSIONS_REPO_PATH=${CMOCKA_EXTENSIONS_REPO_PATH:-${SOURCES_URI}/${CMOCKA_EXTENSIONS_REPO_NAME}}

DEFAULT_BRANCH="integration"
if [ "$SOURCES_URI" = "https://github.com/Elektrobit/" ]; then
    DEFAULT_BRANCH="main"
fi
CMOCKA_EXTENSIONS_REPO_REF=${CMOCKA_EXTENSIONS_REPO_REF:-${DEFAULT_BRANCH}}

PARAM=""
OPTION_CI=0
OPTION_CLEAN=0
OPTION_VERBOSE=0
OPTION_PACKAGE=0
while [ $# -gt 0 ]; do
    case ${1} in
        --ci)          OPTION_CI=1 ;;
        --clean|-c)    OPTION_CLEAN=1 ;;
        --verbose|-v)  OPTION_VERBOSE=1 ;;
	--package)     OPTION_PACKAGE=1 ;;
        -D)            CMAKE_PARAM="${CMAKE_PARAM} -D ${2}"
                       shift ;;
        -D*)           CMAKE_PARAM="${CMAKE_PARAM} ${1}" ;;
        -*)          echo "error: unknown option: ${1}"; exit 1 ;;
        *)           PARAM="${PARAM} ${1}" ;;
    esac
    shift
done

set -- $PARAM
if [ $# -gt 1 ]; then
    echo "error: only one build-type allowed"
    exit 1
elif [ $OPTION_CI -eq 1 ]; then
    if [ $# -eq 0 ]; then
        echo "error: build-type must be explicitely set in CI mode"
        exit 1
    fi
    CMAKE_PARAM="${CMAKE_PARAM} -DENABLE_CI=1"
    OPTION_CLEAN=1
    OPTION_VERBOSE=1
fi

BUILD_TYPE="${1:-Debug}"

if [ $OPTION_PACKAGE -eq 1 ]; then
    CMAKE_PARAM="${CMAKE_PARAM} -D PACKAGING=true"
    BUILD_TYPE=Release
    OPTION_CLEAN=1
fi

CMAKE_PARAM="${CMAKE_PARAM} -D CMOCKA_EXTENSIONS_URI=${CMOCKA_EXTENSIONS_REPO_PATH} \
                            -D CMOCKA_EXTENSIONS_REF=${CMOCKA_EXTENSIONS_REPO_REF}"

BUILD_DIR="$BASE_DIR/build/$BUILD_TYPE"
RESULT_DIR="$BUILD_DIR/result"
DIST_DIR="$BUILD_DIR/dist"
CMAKE_BUILD_DIR="$BUILD_DIR/cmake"
export LOCAL_INSTALL_DIR=${LOCAL_INSTALL_DIR:-"$DIST_DIR"}
CMAKE_PARAM="${CMAKE_PARAM} -D INSTALL_DIR=${LOCAL_INSTALL_DIR}"

DEP_BUILD_PARAM=""
if [ $OPTION_CLEAN -eq 1 ]; then
    DEP_BUILD_PARAM="$DEP_BUILD_PARAM -c"
    if [ -e "$BUILD_DIR" ]; then
        echo "Removing $BUILD_DIR ..."
        rm -rf "$BUILD_DIR"
    fi
fi
if [ $OPTION_VERBOSE -eq 1 ]; then
    DEP_BUILD_PARAM="$DEP_BUILD_PARAM -v"
    NINJA_PARAM="$NINJA_PARAM -v"
fi

echo -e "\n#### Configuring cmocka_mocks ($BUILD_TYPE) ####"
mkdir -p "$RESULT_DIR" "$DIST_DIR"
if [ ! -e "$CMAKE_BUILD_DIR/build.ninja" ]; then
    cmake -B "$CMAKE_BUILD_DIR" "$BASE_DIR" "-DCMAKE_BUILD_TYPE=$BUILD_TYPE" -G Ninja $CMAKE_PARAM
fi

echo -e "\n#### Building cmocka_mocks ($BUILD_TYPE) ####"
DESTDIR="$LOCAL_INSTALL_DIR" \
ninja -C "$CMAKE_BUILD_DIR" $NINJA_PARAM all install 2>&1 | tee "$RESULT_DIR/build_log.txt"

re=${PIPESTATUS[0]}

"$BASE_DIR/ci/check_build_log.py" "$RESULT_DIR/build_log.txt"

exit "$re"
