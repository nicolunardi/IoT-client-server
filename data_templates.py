templates = {
    "SYN": {"command": "SYN"},
    "SYN_OK": {"command": "SYN_OK", "message": "Please log in"},
    "AUTH": {
        "command": "AUTH",
        "data": {"username": "", "password": ""},
    },
    "AUTH_INV_PASS": {
        "command": "AUTH_INV_PASS",
        "message": "Invalid password. Please try again",
    },
    "AUTH_INV_USER": {
        "command": "AUTH_INV_USER",
        "message": "Username does not match any on record. Please try again",
    },
    "OUT": {"command": "OUT"},
    "ERR": {
        "command": "ERR",
        "message": "[Server]: Error has been encountered",
    },
}
