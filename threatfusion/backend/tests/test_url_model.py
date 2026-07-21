"""Tests for the character-level neural URL model building blocks."""

from __future__ import annotations

import torch

from app.ml.url_model import (
    PAD_TOKEN,
    UNK_TOKEN,
    UrlFusionConfig,
    UrlFusionNet,
    build_vocab,
    encode_url,
    load_checkpoint,
    save_checkpoint,
)


def test_vocab_has_special_tokens() -> None:
    vocab = build_vocab()
    assert vocab[PAD_TOKEN] == 0
    assert vocab[UNK_TOKEN] == 1
    # Common URL characters must be present.
    for ch in "abc0123-./":
        assert ch in vocab


def test_encode_pads_and_truncates() -> None:
    vocab = build_vocab()
    ids = encode_url("http://a.com", vocab, max_len=8)
    assert len(ids) == 8  # truncated to max_len

    ids2 = encode_url("ab", vocab, max_len=6)
    assert len(ids2) == 6
    assert ids2[2:] == [vocab[PAD_TOKEN]] * 4  # right-padded


def test_encode_unknown_char_maps_to_unk() -> None:
    vocab = build_vocab()
    # A cyrillic homoglyph is not in the ASCII alphabet → UNK.
    ids = encode_url("а", vocab, max_len=3)  # noqa: RUF001 (intentional cyrillic)
    assert ids[0] == vocab[UNK_TOKEN]


def test_forward_shapes() -> None:
    config = UrlFusionConfig(n_tabular_features=19)
    model = UrlFusionNet(config)
    model.eval()

    char_ids = torch.zeros(4, config.max_len, dtype=torch.long)
    tab = torch.zeros(4, 19)
    fused, text, tabl = model.forward_all(char_ids, tab)

    for out in (fused, text, tabl):
        assert out.shape == (4, 1)


def test_saliency_is_non_negative_and_sized() -> None:
    config = UrlFusionConfig(n_tabular_features=19)
    model = UrlFusionNet(config)

    char_ids = torch.zeros(1, config.max_len, dtype=torch.long)
    sal = model.text_saliency(char_ids)
    assert sal.shape == (config.max_len,)
    assert torch.all(sal >= 0)


def test_checkpoint_roundtrip(tmp_path) -> None:
    config = UrlFusionConfig(
        n_tabular_features=19,
        feature_names=[f"f{i}" for i in range(19)],
        tab_mean=[0.0] * 19,
        tab_std=[1.0] * 19,
    )
    model = UrlFusionNet(config)
    model.eval()

    char_ids = torch.randint(0, config.vocab_size, (2, config.max_len))
    tab = torch.randn(2, 19)
    with torch.no_grad():
        before, _ = model(char_ids, tab)

    weights = tmp_path / "neural_fusion.pt"
    save_checkpoint(model, config, weights)
    assert weights.exists()
    assert weights.with_name("neural_fusion_config.json").exists()

    loaded, loaded_cfg = load_checkpoint(weights)
    loaded.eval()
    with torch.no_grad():
        after, _ = loaded(char_ids, tab)

    assert loaded_cfg.feature_names == config.feature_names
    assert torch.allclose(before, after, atol=1e-6)
