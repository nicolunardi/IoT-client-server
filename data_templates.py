templates = {
    # client
    "SYN": {"command": "SYN"},
    "AUTH": {
        "command": "AUTH",
        "data": {"username": "", "password": ""},
    },
    "UDP": {"command": "UDP"},
    "OUT": {"command": "OUT"},
    # server
    "SYN_OK": {"command": "SYN_OK", "message": "Please log in"},
    "AUTH_INV_PASS": {
        "command": "AUTH_INV_PASS",
        "message": "Invalid password. Please try again",
    },
    "AUTH_INV_PASS_MAX": {
        "command": "AUTH_INV_PASS_MAX",
        "message": "Invalid Password. Your account has been blocked. Please try again later",
    },
    "AUTH_INV_USER": {
        "command": "AUTH_INV_USER",
        "message": "Username does not match any on record. Please try again",
    },
    "AUTH_INV_BAN": {
        "command": "AUTH_INV_BAN",
        "message": "Your account is blocked due to multiple authentication failures. Please try again later",
    },
    "AUTH_OK": {"command": "AUTH_OK", "message": "Welcome!"},
    "OUT_OK": {"command": "OUT_OK"},
    "ERR": {
        "command": "ERR",
        "message": "[Server]: Error has been encountered",
    },
}
