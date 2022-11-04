templates = {
    # client
    "SYN": {"command": "SYN"},
    "AUTH": {
        "command": "AUTH",
        "data": {"username": "", "password": ""},
    },
    "UDP": {"command": "UDP"},
    "UED": {"command": "UED"},
    "SCS": {"command": "SCS"},
    "DTE": {"command": "DTE"},
    "AED": {"command": "AED"},
    "OUT": {"command": "OUT"},
    # server
    "SYN_OK": {"command": "SYN_OK", "message": "please log in"},
    "AUTH_INV_PASS": {
        "command": "AUTH_INV_PASS",
        "message": "invalid password. please try again",
    },
    "AUTH_INV_PASS_MAX": {
        "command": "AUTH_INV_PASS_MAX",
        "message": "invalid Password. your account has been blocked. please try again later",
    },
    "AUTH_INV_USER": {
        "command": "AUTH_INV_USER",
        "message": "username does not match any on record. please try again",
    },
    "AUTH_INV_BAN": {
        "command": "AUTH_INV_BAN",
        "message": "your account is blocked due to multiple authentication failures. please try again later",
    },
    "AUTH_OK": {"command": "AUTH_OK", "message": "welcome!"},
    "UED_OK": {"command": "UED_OK"},
    "SCS_OK": {"command": "SCS_OK"},
    "SCS_INV": {
        "command": "SCS_INV",
        "message": "a file with that file ID does not exist on the server, please try another number",
    },
    "AED_OK": {"command": "AED_OK"},
    "DTE_OK": {"command": "DTE_OK"},
    "DTE_INV": {
        "command": "DTE_INV",
        "message": "a file with that file ID does not exist on the server, please try another number",
    },
    "OUT_OK": {"command": "OUT_OK"},
    "ERR": {
        "command": "ERR",
        "message": "[Server]: error has been encountered",
    },
}
