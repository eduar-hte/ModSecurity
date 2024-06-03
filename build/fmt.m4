dnl Check for FMT Libraries
dnl CHECK_FMTLIB(ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND])

AC_DEFUN([CHECK_FMTLIB], [

# Possible names for the fmt library/package (pkg-config)
FMT_POSSIBLE_LIB_NAMES="fmt"

# Possible extensions for the library
FMT_POSSIBLE_EXTENSIONS="so la sl dll dylib"

# Possible paths (if pkg-config was not found, proceed with the file lookup)
FMT_POSSIBLE_PATHS="/usr/lib /usr/local/lib /usr/local/libfmt /usr/local/fmt /usr/local /opt/libfmt /opt/fmt /opt /usr /usr/lib64"

# Variables to be set by this very own script.
FMT_VERSION=""
FMT_CFLAGS=""
FMT_CPPFLAGS=""
FMT_LDADD=""
FMT_LDFLAGS=""

AC_ARG_WITH(
    fmt,
    [AS_HELP_STRING([--with-fmt=PATH],[Path to fmt prefix or config script])]
)

FMT_MANDATORY=yes
AC_MSG_NOTICE([fmt is mandatory])


if test "x${with_fmt}" == "x" || test "x${with_fmt}" == "xyes"; then
    # Nothing about FMT was informed, using the pkg-config to figure things out.
    if test -n "${PKG_CONFIG}"; then
        FMT_PKG_NAME=""
        for x in ${FMT_POSSIBLE_LIB_NAMES}; do
            if ${PKG_CONFIG} --exists ${x}; then
                FMT_PKG_NAME="$x"
                break
            fi
        done
    fi
    AC_MSG_NOTICE([Nothing about FMT was informed during the configure phase. Trying to detect it on the platform...])
    if test -n "${FMT_PKG_NAME}"; then
        # Package was found using the pkg-config scripts
        FMT_VERSION="`${PKG_CONFIG} ${FMT_PKG_NAME} --modversion`"
        FMT_CFLAGS="`${PKG_CONFIG} ${FMT_PKG_NAME} --cflags`"
        FMT_LDADD="`${PKG_CONFIG} ${FMT_PKG_NAME} --libs-only-l`"
        FMT_LDFLAGS="`${PKG_CONFIG} ${FMT_PKG_NAME} --libs-only-L --libs-only-other`"
    else
        # If pkg-config did not find anything useful, go over file lookup.
        for x in ${FMT_POSSIBLE_PATHS}; do
            CHECK_FOR_FMTLIB_AT(${x})
            if test -n "${FMT_LDADD}"; then
                break
            fi
        done
    fi
elif test "x${with_fmt}" != "x"; then
    # A specific path was informed, let's check.
    CHECK_FOR_FMTLIB_AT(${with_fmt})
fi

if test -z "${FMT_LDADD}"; then
    AC_MSG_ERROR([FMT is mandatory but it was not found])
    FMT_FOUND=-1
else
    FMT_FOUND=1
    AC_MSG_NOTICE([using FMT v${FMT_VERSION}])
    FMT_CFLAGS="${FMT_CFLAGS}"
    FMT_DISPLAY="${FMT_LDADD}, ${FMT_CFLAGS}"
    AC_SUBST(FMT_VERSION)
    AC_SUBST(FMT_LDADD)
    AC_SUBST(FMT_LDFLAGS)
    AC_SUBST(FMT_CFLAGS)
    AC_SUBST(FMT_DISPLAY)
fi



AC_SUBST(FMT_FOUND)

]) # AC_DEFUN [CHECK_FMTLIB]


AC_DEFUN([CHECK_FOR_FMTLIB_AT], [
    path=$1
    for y in ${FMT_POSSIBLE_EXTENSIONS}; do
        for z in ${FMT_POSSIBLE_LIB_NAMES}; do
           if test -e "${path}/${z}.${y}"; then
               fmt_lib_path="${path}/"
               fmt_lib_name="${z}"
               fmt_lib_file="${fmt_lib_path}/${z}.${y}"
               break
           fi
           if test -e "${path}/lib${z}.${y}"; then
               fmt_lib_path="${path}/"
               fmt_lib_name="${z}"
               fmt_lib_file="${fmt_lib_path}/lib${z}.${y}"
               break
           fi
           if test -e "${path}/lib/lib${z}.${y}"; then
               fmt_lib_path="${path}/lib/"
               fmt_lib_name="${z}"
               fmt_lib_file="${fmt_lib_path}/lib${z}.${y}"
               break
           fi
           if test -e "${path}/lib/x86_64-linux-gnu/lib${z}.${y}"; then
               fmt_lib_path="${path}/lib/x86_64-linux-gnu/"
               fmt_lib_name="${z}"
               fmt_lib_file="${fmt_lib_path}/lib${z}.${y}"
               break
           fi
       done
       if test -n "$fmt_lib_path"; then
           break
       fi
    done
    if test -e "${path}/include/format.h"; then
        fmt_inc_path="${path}/include"
    elif test -e "${path}/format.h"; then
        fmt_inc_path="${path}"
    elif test -e "${path}/include/fmt/format.h"; then
        fmt_inc_path="${path}/include"
    fi

    if test -n "${fmt_lib_path}"; then
        AC_MSG_NOTICE([FMT library found at: ${fmt_lib_file}])
    fi

    if test -n "${fmt_inc_path}"; then
        AC_MSG_NOTICE([FMT headers found at: ${fmt_inc_path}])
    fi

    if test -n "${fmt_lib_path}" -a -n "${fmt_inc_path}"; then
        # TODO: Compile a piece of code to check the version.
        FMT_CFLAGS="-I${fmt_inc_path}"
        FMT_LDADD="-l${fmt_lib_name}"
        FMT_LDFLAGS="-L${fmt_lib_path}"
    fi
]) # AC_DEFUN [CHECK_FOR_FMTLIB_AT]
