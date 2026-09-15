from pathlib import Path

from jinja2 import Environment, FileSystemLoader


def test_all_templates_parse():
    root = Path(__file__).resolve().parents[1] / "torpanel" / "templates"
    env = Environment(loader=FileSystemLoader(str(root)))
    templates = sorted(root.rglob("*.html"))
    assert templates
    for path in templates:
        source = path.read_text(encoding="utf-8")
        env.parse(source)
