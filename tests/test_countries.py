from torpanel.countries import TOR_COUNTRIES, TOR_COUNTRY_BY_CODE, country_flag


def test_country_catalog_is_complete_and_unique():
    assert len(TOR_COUNTRIES) == 249
    codes = [row["code"] for row in TOR_COUNTRIES]
    assert len(codes) == len(set(codes))
    assert all(len(code) == 2 and code.isupper() for code in codes)


def test_common_tor_exit_country_codes_are_available():
    assert TOR_COUNTRY_BY_CODE["DE"]["name"] == "Germany"
    assert TOR_COUNTRY_BY_CODE["NL"]["name"].startswith("Netherlands")
    assert TOR_COUNTRY_BY_CODE["US"]["name"] == "United States of America"
    assert TOR_COUNTRY_BY_CODE["IR"]["name"].startswith("Iran")


def test_country_flag_generation():
    assert country_flag("DE") == "🇩🇪"
    assert country_flag("us") == "🇺🇸"
    assert country_flag("") == ""
