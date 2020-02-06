# -*- coding: utf-8 -*-
# import module snippets
import sys
import traceback


def error_result(e):
    exception_fail(e)
    state = "ERROR"
    if isinstance(e, ValueError):
        code = 500
        message = "JSON Parse error (%s)" % str(e)
        state = "ERROR"
    else:
        message = str(e)
        code = 500
        state = "CRITICAL"

    return {
        "state": state,
        "message": message,
        "code": code
    }


def exception_fail(e):
    info = sys.exc_info()
    tbinfo = traceback.format_tb(info[2])
    exception_name = str(info[1])
    result = {}
    result["msg"] = exception_name
    result["trace"] = []
    for info in tbinfo:
        message = info.split("\n")
        temp = message[0].split(", ")
        del message[0]
        places = {
            "file": temp[0].replace("  File", ""),
            "line": temp[1].replace("line ", ""),
            "func": temp[2].replace("in ", ""),
            "trac": message
        }
        result["trace"].append(places)
    return result
