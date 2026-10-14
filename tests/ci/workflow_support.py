import yaml


def parse_workflow(text):
    document = yaml.safe_load(text)
    # PyYAML uses YAML 1.1: GitHub's unquoted `on` is parsed as True.
    if True in document:
        document['on'] = document.pop(True)
    return document
