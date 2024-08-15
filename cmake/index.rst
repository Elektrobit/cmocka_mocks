CMake options
=============

ENABLE_ASAN=[on|off]
--------------------
default: on

Control if cmocka_mocks should be build with address sanitizer

ENABLE_GIT_VERSION=[on|off]
---------------------------
default: on

Control if the version should also use the git hash or run without needing git


Usage of find_package
=====================

* Always specify a version. `find_package(dependecy X.Y.Z REQUIRED)`
* Specify the version used for development


* The version doesn't guarantee that in the future the build still works with this version.
* The version does not necessarily say the previous versions will not work.
* The version is just an indicator for later issue or bug tracking, to say: "It was developed with this version and it worked".
* Usually we always build against the latest available version of our dependencies, so we only can guarantee that the latest upstream version will work.
