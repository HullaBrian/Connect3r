import os


def get_templates() -> dict:
    TEMPLATES: dict[str:list] = {}

    templates_path = os.path.join(os.getcwd()[:os.getcwd().index("Connect3r")], "Connect3r", "connect3r", "templates")

    for template in os.listdir(templates_path):
        if not template.endswith(".packet"):
            continue
        TEMPLATES[template.removesuffix(".packet")] = [line.replace("\n", "") for line in open(os.path.join(templates_path, template), "r").readlines()]

    return TEMPLATES
