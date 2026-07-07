"""
lstm_model.py
-------------
PyTorch LSTM Sequence Autoencoder for behavioural anomaly detection.

Architecture:
  Embedding (vocab=10 event types, dim=32)
  → LSTM Encoder (hidden=128, layers=2, bidirectional=False)
  → Linear bottleneck (128 → 64)
  → LSTM Decoder (hidden=128, layers=1)
  → Linear output (128 → vocab_size)
  → Cross-entropy reconstruction loss

Anomaly score = mean reconstruction loss, normalised to [0, 1]
via a sigmoid-like mapping calibrated during training.

Training is unsupervised: only normal sequences are used.
At inference, high reconstruction loss → the model did NOT expect
this sequence → anomalous.
"""

import os
from typing import List, Optional, Tuple

try:
    import numpy as np
except Exception:  # pragma: no cover - exercised only when numpy is absent
    np = None

try:
    import torch
    import torch.nn as nn
    TORCH_AVAILABLE = True
except Exception:  # pragma: no cover - exercised only when torch is absent
    torch = None
    nn = None
    TORCH_AVAILABLE = False

# ── Constants ─────────────────────────────────────────────────────────────────
VOCAB_SIZE  = 10      # number of event types (matches EVENT_TYPE_MAP)
EMBED_DIM   = 32
HIDDEN_SIZE = 128
NUM_LAYERS  = 2
MAX_SEQ_LEN = 50
PAD_IDX     = 0       # padding token (same as NORMAL event code)

MODEL_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "models", "lstm_anomaly.pt"
)


# ── Model Definition ──────────────────────────────────────────────────────────

if TORCH_AVAILABLE:
    class LSTMAutoencoder(nn.Module):
        """
        LSTM-based sequence autoencoder.
        Encodes an event-type sequence, then decodes it step-by-step.
        Reconstruction error is the anomaly signal.
        """

        def __init__(
            self,
            vocab_size: int = VOCAB_SIZE,
            embed_dim: int  = EMBED_DIM,
            hidden_size: int = HIDDEN_SIZE,
            num_layers: int  = NUM_LAYERS,
        ):
            super().__init__()
            self.vocab_size  = vocab_size
            self.embed_dim   = embed_dim
            self.hidden_size = hidden_size
            self.num_layers  = num_layers

            # Shared embedding layer
            self.embedding = nn.Embedding(
                num_embeddings=vocab_size,
                embedding_dim=embed_dim,
                padding_idx=PAD_IDX,
            )

            # Encoder LSTM
            self.encoder = nn.LSTM(
                input_size=embed_dim,
                hidden_size=hidden_size,
                num_layers=num_layers,
                batch_first=True,
                dropout=0.2 if num_layers > 1 else 0.0,
            )

            # Bottleneck: compress encoder output
            self.bottleneck = nn.Linear(hidden_size, hidden_size // 2)
            self.bn_act      = nn.ReLU()
            self.expand      = nn.Linear(hidden_size // 2, hidden_size)

            # Decoder LSTM
            self.decoder = nn.LSTM(
                input_size=embed_dim,
                hidden_size=hidden_size,
                num_layers=1,
                batch_first=True,
            )

            # Project decoder output to vocab logits
            self.output_proj = nn.Linear(hidden_size, vocab_size)

            # Dropout for regularisation
            self.dropout = nn.Dropout(0.1)

        def encode(self, x: torch.Tensor) -> Tuple[torch.Tensor, tuple]:
            """
            Encode a padded sequence of event-type tokens.
            x: (batch, seq_len) int tensor
            Returns: (context_vector, decoder_init_hidden)
            """
            embedded = self.dropout(self.embedding(x))          # (B, L, E)
            _, (hidden, cell) = self.encoder(embedded)          # hidden: (layers, B, H)

            # Use top encoder layer for bottleneck
            top_hidden = hidden[-1]                             # (B, H)
            compressed = self.bn_act(self.bottleneck(top_hidden))  # (B, H/2)
            expanded   = self.expand(compressed)               # (B, H)

            # Initialise decoder with expanded context
            dec_h = expanded.unsqueeze(0)                       # (1, B, H)
            dec_c = torch.zeros_like(dec_h)
            return expanded, (dec_h, dec_c)

        def forward(self, x: torch.Tensor) -> torch.Tensor:
            """
            Full autoencoder forward pass.
            x: (batch, seq_len) int tensor
            Returns: logits (batch, seq_len, vocab_size)
            """
            _, (dec_h, dec_c) = self.encode(x)

            # Teacher-forced decoding: feed embedded input sequence to decoder
            embedded = self.dropout(self.embedding(x))          # (B, L, E)
            dec_out, _ = self.decoder(embedded, (dec_h, dec_c)) # (B, L, H)
            logits = self.output_proj(dec_out)                  # (B, L, V)
            return logits

        def reconstruction_loss(self, x: torch.Tensor) -> torch.Tensor:
            """
            Compute mean cross-entropy reconstruction loss per sample.
            x: (batch, seq_len) int tensor
            Returns: (batch,) float tensor — per-sample loss
            """
            logits = self.forward(x)                            # (B, L, V)
            B, L, V = logits.shape

            # Flatten for cross-entropy
            logits_flat = logits.reshape(B * L, V)
            targets_flat = x.reshape(B * L)

            loss_fn = nn.CrossEntropyLoss(ignore_index=PAD_IDX, reduction="none")
            per_token_loss = loss_fn(logits_flat, targets_flat)  # (B*L,)
            per_sample_loss = per_token_loss.reshape(B, L).mean(dim=1)  # (B,)
            return per_sample_loss
else:
    class LSTMAutoencoder:  # pragma: no cover - used only without torch
        pass


# ── Inference Utilities ───────────────────────────────────────────────────────

_model: Optional[LSTMAutoencoder] = None
# Calibration thresholds (populated after training or loaded from checkpoint)
_threshold_normal: float = 0.5   # typical loss for normal sequences
_threshold_attack: float = 2.0   # typical loss for attack sequences


def _clip01(value: float) -> float:
    if np is not None:
        return float(np.clip(value, 0.0, 1.0))
    return 0.0 if value < 0.0 else 1.0 if value > 1.0 else float(value)


def load_model(model_path: str = MODEL_PATH) -> Optional[LSTMAutoencoder]:
    """
    Load LSTM model from disk. Returns None if weights not found
    (system falls back to heuristic scoring).
    """
    global _model, _threshold_normal, _threshold_attack

    if not TORCH_AVAILABLE:
        return None

    if _model is not None:
        return _model

    if not os.path.exists(model_path):
        return None

    checkpoint = torch.load(model_path, map_location="cpu", weights_only=False)
    model = LSTMAutoencoder()
    model.load_state_dict(checkpoint["model_state_dict"])
    model.eval()

    # Load calibration thresholds if present
    _threshold_normal = checkpoint.get("threshold_normal", 0.5)
    _threshold_attack  = checkpoint.get("threshold_attack", 2.0)

    _model = model
    return _model


def pad_sequence(seq: List[int], max_len: int = MAX_SEQ_LEN) -> List[int]:
    """Pad or truncate sequence to fixed length."""
    if len(seq) >= max_len:
        return seq[:max_len]
    return seq + [PAD_IDX] * (max_len - len(seq))


def _heuristic_score(sequence: List[int]) -> float:
    HIGH_RISK_CODES = {5, 6, 7, 8, 9}
    MEDIUM_RISK_CODES = {1, 3}  # LOGIN, OUTBOUND_CONN

    if not sequence:
        return 0.0

    high_count   = sum(1 for c in sequence if c in HIGH_RISK_CODES)
    medium_count = sum(1 for c in sequence if c in MEDIUM_RISK_CODES)
    total = len(sequence)

    unique_high = len(set(sequence) & HIGH_RISK_CODES)
    chain_bonus = min(unique_high * 0.1, 0.3)

    import math
    effective_total = math.sqrt(total) if total > 1 else 1.0

    raw_score = (high_count * 0.5 + medium_count * 0.2) / effective_total + chain_bonus
    return round(min(raw_score, 1.0), 4)

def score_sequence(sequence: List[int]) -> float:
    """
    Score a single event sequence for anomaly.

    Returns float in [0.0, 1.0]:
      0.0 = completely normal
      1.0 = highly anomalous

    Falls back to a heuristic scoring if model not trained, 
    and uses heuristic as a baseline guardrail.
    """
    global _model

    heuristic = _heuristic_score(sequence)

    if _model is None:
        _model = load_model()

    if _model is None:
        return heuristic

    # ── Neural model scoring ──────────────────────────────────────────────
    padded = pad_sequence(sequence)
    tensor = torch.tensor([padded], dtype=torch.long)  # (1, max_len)

    with torch.no_grad():
        loss = _model.reconstruction_loss(tensor)  # (1,)
        raw_loss = loss.item()

    # Normalise to [0, 1] using calibration range
    span = max(_threshold_attack - _threshold_normal, 0.1)
    normalised = (raw_loss - _threshold_normal) / span
    
    neural_score = round(_clip01(normalised), 4)
    # Guardrail: Never let the neural model suppress blatant heuristic flags
    return max(neural_score, heuristic)


# ═══════════════════════════════════════════════════════════════════════════════
# TRAINED NETWORK FLOW LSTM MODEL (from train_lstm.py)
# ═══════════════════════════════════════════════════════════════════════════════

NETWORK_FLOW_MODEL_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "models", "lstm_network_flow.pt"
)

_nf_model = None          # NetworkFlowLSTMAutoencoder instance
_nf_threshold: float = 1.0
_nf_mean_err: float = 0.0
_nf_std_err: float = 1.0
_nf_scaler_mean = None    # np.ndarray
_nf_scaler_scale = None   # np.ndarray
_nf_num_features: int = 0
_nf_seq_length: int = 20


def _load_network_flow_model():
    """Lazy-load trained network flow LSTM model."""
    global _nf_model, _nf_threshold, _nf_mean_err, _nf_std_err
    global _nf_scaler_mean, _nf_scaler_scale, _nf_num_features, _nf_seq_length

    if _nf_model is not None:
        return _nf_model

    if not TORCH_AVAILABLE or not os.path.exists(NETWORK_FLOW_MODEL_PATH):
        return None

    try:
        from backend.models.train_lstm import NetworkFlowLSTMAutoencoder
    except ImportError:
        return None

    checkpoint = torch.load(NETWORK_FLOW_MODEL_PATH, map_location="cpu", weights_only=False)
    _nf_num_features = checkpoint["num_features"]
    _nf_seq_length = checkpoint.get("seq_length", 20)
    _nf_threshold = checkpoint["threshold"]
    _nf_mean_err = checkpoint.get("mean_error", 0.0)
    _nf_std_err = checkpoint.get("std_error", 1.0)

    model = NetworkFlowLSTMAutoencoder(num_features=_nf_num_features)
    model.load_state_dict(checkpoint["model_state_dict"])
    model.eval()
    _nf_model = model

    # Load scaler parameters
    if "scaler_mean" in checkpoint and "scaler_scale" in checkpoint:
        _nf_scaler_mean = np.array(checkpoint["scaler_mean"], dtype=np.float32)
        _nf_scaler_scale = np.array(checkpoint["scaler_scale"], dtype=np.float32)

    return _nf_model


def score_network_flow(features: "np.ndarray") -> float:
    """
    Score a network flow feature matrix using the trained LSTM Autoencoder.

    Args:
        features: np.ndarray of shape (num_rows, num_features) — raw (unscaled)
                  network flow feature values. Rows should be temporally ordered.

    Returns:
        float in [0.0, 1.0]: anomaly score
          0.0 = completely normal
          1.0 = highly anomalous

    Falls back to 0.0 if the trained model is not available.
    """
    if np is None:
        return 0.0

    model = _load_network_flow_model()
    if model is None:
        return 0.0

    features = np.array(features, dtype=np.float32)
    if features.ndim == 1:
        features = features.reshape(1, -1)

    # Scale using saved scaler parameters
    if _nf_scaler_mean is not None and _nf_scaler_scale is not None:
        # Pad or truncate feature columns to match training
        if features.shape[1] < len(_nf_scaler_mean):
            pad_width = len(_nf_scaler_mean) - features.shape[1]
            features = np.pad(features, ((0, 0), (0, pad_width)), constant_values=0)
        elif features.shape[1] > len(_nf_scaler_mean):
            features = features[:, :len(_nf_scaler_mean)]

        scale = _nf_scaler_scale.copy()
        scale[scale == 0] = 1.0  # avoid divide-by-zero
        features = (features - _nf_scaler_mean) / scale
        features = np.clip(features, -10, 10)

    # Create sequence: use sliding window or pad to seq_length
    if len(features) >= _nf_seq_length:
        # Use last seq_length rows as one sequence
        seq = features[-_nf_seq_length:]
    else:
        # Pad with zeros (first rows)
        pad = np.zeros((_nf_seq_length - len(features), features.shape[1]), dtype=np.float32)
        seq = np.vstack([pad, features])

    tensor = torch.tensor(seq, dtype=torch.float32).unsqueeze(0)  # (1, L, F)

    with torch.no_grad():
        error = model.reconstruction_error(tensor).item()

    # Normalise to [0, 1] using threshold calibration
    # Errors below threshold → low score; errors above → approach 1.0
    if _nf_std_err > 0:
        normalised = (error - _nf_mean_err) / (3 * _nf_std_err)
    else:
        normalised = error / max(_nf_threshold, 0.01)

    return round(_clip01(normalised), 4)


def is_network_flow_model_loaded() -> bool:
    """Check if the trained network flow LSTM model is available."""
    return _load_network_flow_model() is not None

