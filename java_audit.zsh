# java_audit.zsh - a set of companion tools needed by everyday job during Java
# source code audits
#
# Copyright 2022 Paolo Perego <paolo.perego@suse.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

VERSION="0.7"
TARGET_DIR="`pwd`"
OLD_PS1=$PS1

# Search where there are reads from HTTP requests. Useful to spot sinks in web
# applications.
function read_from_http {
    grep -r -w "request.getParameter" * | cut -f1 -d ":" | sort | uniq
}

function set_target_dir {

    if ! [[ -z "${AUDIT_TARGET_DIR}"  ]]; then
        TARGET_DIR="${AUDIT_TARGET_DIR}"
    fi

    if [ $# -eq 1 ]; then
        TARGET_DIR=$1
    else
        TARGET_DIR="`pwd`"
    fi

    return 0

}

function target {
    echo "${TARGET_DIR}"
}

function version {
    echo "Java audit companion tools v$VERSION (C) 2022 - paolo.perego@suse.com"
    return 0
}

function debug {
    if [ ! -z $JAVA_AUDIT_DEBUG ]; then
        echo "[+]: $1"
    fi
    return 0
}

# https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html#whitebox-review_2
# Checks if a Java class is vulnerable to deserialization. It requires che
# filename as parameter.
function is_vulnerable_to_deserialization {
    if [ $# -eq 0 ]; then
        echo "usage is_vulnerable_to_deserialization class filename"
        return 1
    fi
    grep -q "implements Serializable" $1
    if [ $? -eq 0 ]; then
        debug "$1 implements serializable"
        grep -q "void readObject" $1
        if [ $? -ne 0 ]; then
            debug "$1 doesn't override readObject"
            debug "$1 is vulnerable"
            return 1
        fi
    fi

    grep -q "extends ObjectInputStream" $1
    if [ $? -eq 0 ]; then
        debug "$1 extends ObjectInputStream"
        grep -q "resolveClass" $1
        if [ $? -ne 0 ]; then
            debug "$1 doesn't override resolveClass"
            debug "$1 is vulnerable"
            return 1
        fi
    fi

    debug "$1 is not vulnerable"
    return 0

}

# Top 10 of most imported packages.
# This should give an idea of the most used package in an application.
#
# Usage
#   $ imported_packages_top_10      => shows the 10 most imported classes
#   $ imported_packages_top_10 5    => shows the 5  most impoted classes
#   $ imported_packages_top_10 5 com.suse com.rhn => shows the 5  most impoted
#                                                    classes that matches
#                                                    com.suse or com.rhn
#                                                    namespace
function imported_packages_top_10 {
    if [ $# -eq 0 ]; then
        COUNT=10
        CUSTOM_NAMESPACES=""
    else
        re='^[0-9]+$'
        if [[ $yournumber =~ $re  ]] ; then
            # if the first argument is a number, then use it as COUNT and shift
            # the arg array vector.
            COUNT=$1
            shift 1
        else
            COUNT=10
        fi
        CUSTOM_NAMESPACES=""
        # https://stackoverflow.com/questions/2701400/remove-first-element-from-in-bash
        for item in "$@" ; do
            CUSTOM_NAMESPACES+=("-e $item")
        done
    fi
    if [ -z "$CUSTOM_NAMESPACES" ]; then
    echo $TARGET_DIR
        grep -rw "^import" --include \*.java $TARGET_DIR | awk -F/ '{ print $NF  }'| cut -f 2 -d ":" | sort | uniq -c | sort -nr | head -$COUNT
    else
        grep -rw "^import" --include \*.java $TARGET_DIR | awk -F/ '{ print $NF  }'| cut -f 2 -d ":" | sort | uniq -c | sort -nr | grep $CUSTOM_NAMESPACES | head -$COUNT

    fi
}

function seo {
    if [ $# -eq 0 ]; then
        return 0
    fi

    MYNAME=`echo "$1" | tr "." "/"`
    OUT=`find . -iwholename "*$MYNAME.java"`
    echo $OUT
}

function triage {
    TRIAGE="// TRIAGE \n"
    TRIAGE+="// Lines of comments: `count_comments $1`\n"
    grep -q "HttpRequest" $1
    if [ $? -eq 0 ]; then
        TRIAGE+="// !!! It reads input from HTTP requests\n"
    fi
    grep -qw "Statement" $1
    if [ $? -eq 0 ]; then
        TRIAGE+="// !!! It seems Statement class is used\n"
    fi
    grep -qw --ignore-case "password" $1
    if [ $? -eq 0 ]; then
        TRIAGE+="// !!! The 'password' word is present. Check for false positives\n"
    fi


    COUNT=`grep "public" $1 | wc -l`
    if [ $COUNT -gt 0 ]; then
        TRIAGE+="// It has $((COUNT-1)) public methods\n"
    else
        TRIAGE+="// !!! There are no public methods\n"
    fi
    COUNT=`grep "import" $1 | wc -l`
    if [ $COUNT -eq 0 ]; then
        TRIAGE+="// There are no import statements\n"
    else
        TRIAGE+="// It has $COUNT import statements\n"
    fi

    DEEPDEP_OUTPUT_TRIAGE=1
    TRIAGE+=`deepdep $1`
    unset DEEPDEP_OUTPUT_TRIAGE

    `is_vulnerable_to_deserialization $1`
    if [ $? -eq 1 ]; then
        TRIAGE+="// Vulnerable to deserialization attacks"
    fi
    echo $TRIAGE
}
function audit {

    if [ "$1" = "start" ]; then

        grep -q "AUDIT START: " $2
        if [ $? -eq 0 ]; then
            echo "audit already started"
            return -2
        fi
        STRING="// AUDIT START: `date \"+%c\"`\n"
        STRING+="`triage $2`\n"
        echo $STRING > "$2_tmp.audit_start"
        cat $2 >> "$2_tmp.audit_start"
        mv "$2_tmp.audit_start" $2
        return 0
    fi

    if [ "$1" = "report" ]; then

        grep -q "AUDIT END: " $2
        if [ $? -eq 0 ]; then
            echo "audit already completed"
            return -2
        fi

        if [ -z $3 ]; then
            echo "audit: report message can't be blank"
            return -3
        fi


        echo "// AUDIT REPORT: $3" >> $2

        STRING="// AUDIT END: `date \"+%c\"`"
        echo $STRING >> $2
        return 0
    fi

    echo -e "usage:\n\taudit start filename\n\taudit report filename message"
    return -1
}

function count_comments {

    if [ $# -ne 1  ]; then
        echo "usage: count_comments file"
        return -1
    fi

    MULTILINE=`sed -n '/\/\*/, /\*\//p' $1 | wc -l`
    SINGLELINE=`grep // $1 | wc -l`

    echo $(($MULTILINE + $SINGLELINE))
}

function where_is_method_used {
    if [ $# -ne 1  ]; then
        echo "usage: where_is_method_used method"
        return -1
    fi
    echo $1
    grep -w -r $1 $TARGET_DIR | awk -F/ '{ print $NF   }' |  cut -f 1 -d ":" | sort | uniq

}
function where_is_class_used {
    if [ $# -ne 1  ]; then
        echo "usage: where_is_class_used classname"
        return -1
    fi
    LIST=`grep -w -r $1 $TARGET_DIR | awk -F/ '{ print $NF   }'| grep import | cut -f 1 -d ":"`
    for i in $LIST
    do
        echo `basename $i`
    done
}

function deepdep {

    if [ $# -ne 1 ]; then
        echo "usage: deepdep javafile"
        return -1
    fi

    if [ ! -e $1 ]; then
        echo "deepdep: file not found"
        return -1
    fi

    if [ ! -f $1 ]; then
        echo "deepdep: $1 is not a file"
        return -1
    fi

    API_DIR_ARRAY=( "./" "$HOME/.deepdep/" "$HOME/" "/usr/share/deepdep/" )
    API_FILENAME="api.txt"

    for str in ${API_DIR_ARRAY[@]}; do
        API_FILE="$str$API_FILENAME"
        if [ -f $API_FILE ]; then
            break
        fi
    done

    if [ -z $API_FILE ]; then
        echo "deepdep: api.txt file not found"
        return -1
    fi

    strings=( `cat $1 | grep import | cut -f 2 -d ' ' | tr -d ';' `)

    for string in $strings;
    do
        exact_match=`grep "\<$string\>" $API_FILE`
        if [ ! -z "$exact_match" ]; then
            if [ "$exact_match" = "$string" ]; then
                if [[ $DEEPDEP_OUTPUT_TRIAGE -eq 1 ]]; then
                    echo "// $string is deprecated"
                else
                    echo "$1: $string is deprecated"
                fi
            fi
        else
            # no an explicit import org.package.DeprecatedClass call
            # let's say the source file is written this way:
            # import org.package.*;
            # ...
            # DeprecatedClass foo = new DeprecatedClass()
            IFS='.' read -r  tokens <<< "$string"
            if [ "${tokens[-1]}" = "*" ]; then
                to_search=`echo $string | tr -d "*" | sed 's/.$//'`
                back_strings=`cat $API_FILE | grep $to_search | tr -d ';'`
                for back_string in $back_strings;
                do
                    # 1. tokenize the FQDN of the deprecated API
                    # 2. last token is the deprecated Class
                    # 3. grep the source file for the deprecated class only
                    IFS='.' read -r deprecated_tokens <<< "$back_string"
                    deprecated_class=${deprecated_tokens[-1]}
                    found=`grep $deprecated_class $1`
                    if [ ! -z $found ]; then
                        if [ $DEEPDEP_OUTPUT_TRIAGE -eq 1 ]; then
                            echo "// $string is deprecated"
                        else
                            echo "$1: $string is deprecated"
                        fi
                    fi
                done
            fi
        fi
    done
}
