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



def test_location_country_uses_select_catalog_not_manual_code_input():
    root = Path(__file__).resolve().parents[1] / "torpanel" / "templates"
    source = (root / "location_form.html").read_text(encoding="utf-8")
    assert 'select name="country_code"' in source
    assert "data-country-select" in source
    assert 'pattern="[A-Za-z]{2}"' not in source
