#!/bin/sh

# Copyright (C) 2015, Wazuh Inc.
# Variables - do not modify them
CHF="compiled_rules.h"

# Checking the location.
ls -la register_rule.sh > /dev/null 2>&1
if [ ! $? = 0 ]; then
    LOCALDIR=`dirname $0`;
    cd ${LOCALDIR}

    ls -la register_rule.sh > /dev/null 2>&1
    if [ ! $? = 0 ]; then
        echo "ERROR: You must run this script from the same directory."
        exit 1;
    fi
fi

# Arguments
if [ "x$1" = "x" -o "x$1" = "xhelp" -o "x$1" = "x-h" ]; then
    echo "$0 add <function_name>"
    echo "$0 list"
    echo "$0 build"
    echo "$0 save"
    echo "$0 restore"
    exit 0;
fi

if [ "x$1" = "xlist" ]; then
    echo "*Available functions: "
    cat .function_list | sort | uniq;
    exit 0;

elif [ "x$1" = "xsave" ]; then
    if [ "X${2}" = "X" ]; then
        echo "ERROR: You must specify the installation path. i.e.: ${0} $1 WAZUH_HOME"
        exit 1;
    fi    
    WAZUH_HOME=${2}

    eval $(${WAZUH_HOME}/bin/openarmor-control info 2>/dev/null)    
    if [ "X$WAZUH_TYPE" = "X" ]; then
        echo "ERROR: Unable to save rules. You must have Wazuh installed to do so."
        exit 1;
    fi
    if [ "$WAZUH_TYPE" = "agent" ]; then
        echo "ERROR: You must execute this script on Wazuh Manager"
        exit 1;
    fi

    ls ${WAZUH_HOME}/compiled_rules > /dev/null 2>&1
    if [ ! $? = 0 ]; then
        mkdir ${WAZUH_HOME}/compiled_rules > /dev/null 2>&1
        if [ ! $? = 0 ]; then
            echo "ERROR: Unable to save rules. You must be root to do so."
            exit 1;
        fi
    fi

    cp .function_list ${WAZUH_HOME}/compiled_rules/function_list > /dev/null 2>&1
    if [ ! $? = 0 ]; then
        echo "ERROR: Unable to save rules. You must be root to do so."
        exit 1;
    fi

    for i in `ls *.c`; do
        if [ ! "x$i" = "xgeneric_samples.c" ]; then
            cp $i ${WAZUH_HOME}/compiled_rules/ > /dev/null 2>&1
        fi
    done
    echo "*Save completed at ${WAZUH_HOME}/compiled_rules/";
    exit 0;

elif [ "x$1" = "xrestore" ]; then
    if [ "X${2}" = "X" ]; then
        echo "ERROR: You must specify the installation path. i.e.: ${0} $1 WAZUH_HOME"
        exit 1;
    fi    
    WAZUH_HOME=${2}
    
    eval $(${WAZUH_HOME}/bin/openarmor-control info 2>/dev/null)    
    if [ "X$WAZUH_TYPE" = "X" ]; then
        echo "ERROR: Unable to save rules. You must have Wazuh installed to do so."
        exit 1;
    fi
    if [ "$WAZUH_TYPE" = "agent" ]; then
        echo "ERROR: You must execute this script on Wazuh Manager"
        exit 1;
    fi

    ls ${WAZUH_HOME}/compiled_rules/function_list > /dev/null 2>&1
    if [ ! $? = 0 ]; then
        echo "*No local compiled rules available to restore."
        exit 0;
    fi

    cat  ${WAZUH_HOME}/compiled_rules/function_list >> .function_list
    if [ ! $? = 0 ]; then
        echo "ERROR: Unable to restore rules. Function list not present."
        exit 1;
    fi

    for i in `ls ${WAZUH_HOME}/compiled_rules/*.c`; do
        if [ ! "x$i" = "xgeneric_samples.c" ]; then
            cp $i ./ > /dev/null 2>&1
        fi
    done
    echo "*Restore completed from ${WAZUH_HOME}/compiled_rules/";
    exit 0;

elif [ "x$1" = "xbuild" ]; then
    ls -la .function_list > /dev/null 2>&1
    if [ ! $? = 0 ]; then
        echo "ERROR: Unable to build. No function is registered."
        exit 1;
    fi

    # Auto generating the file.
    echo "/* This file is auto generated by $0. Do not touch it. */" > ${CHF}
    echo "" >> ${CHF};

    echo "/* Adding the function definitions. */" >> ${CHF};
    for i in `cat .function_list | sort| uniq`; do
        echo "void *$i(Eventinfo *lf);" >> ${CHF};
    done
    echo "" >> ${CHF};

    echo "/* Adding the rules list. */" >> ${CHF};
    echo "void *(compiled_rules_list[]) = " >> ${CHF};
    echo "{" >> ${CHF};
    for i in `cat .function_list | sort| uniq`; do
        echo "    $i," >> ${CHF};
    done
    echo "    NULL" >> ${CHF};
    echo "};" >> ${CHF};
    echo "" >> ${CHF};

    echo "/* Adding the rules list names. */" >> ${CHF};
    echo "const char *(compiled_rules_name[]) = " >> ${CHF};
    echo "{" >> ${CHF};
    for i in `cat .function_list |sort | uniq`; do
        echo "    \"$i\"," >> ${CHF};
    done
    echo "    NULL" >> ${CHF};
    echo "};" >> ${CHF};
    echo "" >> ${CHF};
    echo "/* EOF */" >> ${CHF};

    echo "*Build completed."

elif [ "x$1" = "xadd" ]; then
    if [ "x$2" = "x" ]; then
        echo "ERROR: Missing function name.";
        echo "ex: $0 add <function_name>";
        exit 1;
    fi

    grep $2 ./*.c > /dev/null 2>&1
    if [ ! $? = 0 ]; then
        echo "ERROR: Function '$2' not found.";
        exit 1;
    fi

    grep $2 .function_list > /dev/null 2>&1
    if [ $? = 0 ]; then
        echo "ERROR: Function '$2' already added.";
        exit 1;
    fi

    echo $2 >> .function_list;
    echo "*Function $2 added."

else
    echo "ERROR: Invalid argument.";
    exit 1;

fi

