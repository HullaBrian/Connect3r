
def detect_platform() -> str:
    try:
        import platform
    except Exception:
        raise ModuleNotFoundError("Platform package not found! Are you on macOS?")

    system = platform.system().lower()

    if "windows" in system:
        return "windows"
    elif "linux" in system:
        return "linux"
    elif "mac" in system or "darwin" in system:
        return "mac"
    else:
        return "unknown"


if __name__ == "__main__":
    print(detect_platform())
