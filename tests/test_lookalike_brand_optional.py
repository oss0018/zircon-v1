from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_lookalike_rule_brand_id_nullable_in_model():
    models_source = (REPO_ROOT / "app" / "models.py").read_text(encoding="utf-8")
    assert 'brand_id = Column(Integer, ForeignKey("brands.id"), nullable=True)' in models_source


def test_lookalike_rule_create_accepts_optional_brand_id():
    api_source = (REPO_ROOT / "app" / "api" / "lookalike.py").read_text(encoding="utf-8")
    assert "brand_id: Optional[int] = None" in api_source
