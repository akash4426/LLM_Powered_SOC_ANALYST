"""
train_lstm.py
-------------
Train an LSTM Autoencoder on CIC-IDS2017 network flow data for anomaly detection.

Usage:
    python -m backend.models.train_lstm                # full train
    python -m backend.models.train_lstm --evaluate-only # evaluate saved model

Architecture:
    Encoder: Linear(num_features→128) → LSTM(128, 2 layers) → Linear(128→64)
    Decoder: Linear(64→128) → LSTM(128, 1 layer) → Linear(128→num_features)
    Loss: MSE reconstruction on BENIGN-only sequences

Dataset: lstm.csv (CIC-IDS2017), ~2.2M rows × 79 columns
    - BENIGN rows used for training (unsupervised)
    - All attack types used for evaluation
"""

import os
import sys
import time
import json
import logging
import argparse
import pickle
from typing import Tuple, Dict, Any

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════════
# PATHS
# ═══════════════════════════════════════════════════════════════════════════════

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CSV_PATH = os.path.join(PROJECT_ROOT, "lstm.csv")
MODEL_SAVE_PATH = os.path.join(PROJECT_ROOT, "backend", "models", "lstm_network_flow.pt")

# ═══════════════════════════════════════════════════════════════════════════════
# HYPERPARAMETERS
# ═══════════════════════════════════════════════════════════════════════════════

SEQ_LENGTH = 20        # sliding window size
STRIDE = 5             # sliding window stride
HIDDEN_SIZE = 128
LATENT_DIM = 64
NUM_LAYERS_ENC = 2
BATCH_SIZE = 256
EPOCHS = 30
LEARNING_RATE = 1e-3
VAL_SPLIT = 0.2
MAX_TRAIN_SEQUENCES = 200_000   # cap to prevent OOM
MAX_EVAL_SEQUENCES = 50_000

# ═══════════════════════════════════════════════════════════════════════════════
# 1. DATA LOADING
# ═══════════════════════════════════════════════════════════════════════════════

def load_data(csv_path: str, sample_frac: float = 0.3) -> pd.DataFrame:
    """Load CSV with chunking, sample for memory efficiency."""
    logger.info(f"Loading {csv_path} ...")
    t0 = time.time()

    chunks = []
    for chunk in pd.read_csv(csv_path, chunksize=50_000, low_memory=False):
        chunks.append(chunk)
    df = pd.concat(chunks, ignore_index=True)

    # Strip whitespace from column names
    df.columns = df.columns.str.strip()
    logger.info(f"Loaded {len(df)} rows, {len(df.columns)} columns in {time.time()-t0:.1f}s")

    # Sample if too large
    if sample_frac < 1.0 and len(df) > 500_000:
        # Stratified-ish: keep all attack rows, sample benign
        attacks = df[df["Label"] != "BENIGN"]
        benign = df[df["Label"] == "BENIGN"].sample(frac=sample_frac, random_state=42)
        df = pd.concat([benign, attacks], ignore_index=True).sample(frac=1, random_state=42)
        logger.info(f"Sampled to {len(df)} rows (kept all attacks, sampled {sample_frac:.0%} benign)")

    return df


# ═══════════════════════════════════════════════════════════════════════════════
# 2. PREPROCESSING
# ═══════════════════════════════════════════════════════════════════════════════

def preprocess(df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray, StandardScaler, list]:
    """Clean, encode labels, scale features. Returns (X, y, scaler, feature_names)."""
    logger.info("Preprocessing ...")

    # Binary label: 0=BENIGN, 1=ATTACK
    df["is_attack"] = (df["Label"].str.strip() != "BENIGN").astype(int)
    y = df["is_attack"].values

    # Drop non-numeric columns
    drop_cols = ["Label", "is_attack"]
    for col in df.columns:
        if df[col].dtype == object and col not in drop_cols:
            drop_cols.append(col)

    feature_cols = [c for c in df.columns if c not in drop_cols]

    X = df[feature_cols].copy()

    # Convert to numeric, coerce errors
    X = X.apply(pd.to_numeric, errors="coerce")

    # Replace Inf with NaN, then fill NaN with 0
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    X.fillna(0, inplace=True)

    # Drop constant columns (zero variance)
    variances = X.var()
    const_cols = variances[variances == 0].index.tolist()
    if const_cols:
        logger.info(f"Dropping {len(const_cols)} constant columns")
        X.drop(columns=const_cols, inplace=True)

    feature_names = X.columns.tolist()
    logger.info(f"Features: {len(feature_names)}")

    # Scale using BENIGN-only data
    scaler = StandardScaler()
    benign_mask = y == 0
    scaler.fit(X[benign_mask])
    X_scaled = scaler.transform(X).astype(np.float32)

    # Clip extreme values
    X_scaled = np.clip(X_scaled, -10, 10)

    return X_scaled, y, scaler, feature_names


# ═══════════════════════════════════════════════════════════════════════════════
# 3. SEQUENCE CREATION
# ═══════════════════════════════════════════════════════════════════════════════

def create_sequences(X: np.ndarray, seq_len: int = SEQ_LENGTH, stride: int = STRIDE) -> np.ndarray:
    """Sliding window over rows to create (N, seq_len, num_features) sequences."""
    sequences = []
    for i in range(0, len(X) - seq_len + 1, stride):
        sequences.append(X[i : i + seq_len])
    result = np.array(sequences, dtype=np.float32)
    logger.info(f"Created {len(result)} sequences of shape {result.shape}")
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# 4. MODEL ARCHITECTURE
# ═══════════════════════════════════════════════════════════════════════════════

class NetworkFlowLSTMAutoencoder(nn.Module):
    """
    LSTM Autoencoder for continuous-valued network flow feature vectors.

    Encoder: Linear → LSTM (2 layers) → bottleneck
    Decoder: expand → LSTM (1 layer) → Linear → reconstruct
    """

    def __init__(self, num_features: int, hidden_size: int = HIDDEN_SIZE,
                 latent_dim: int = LATENT_DIM, num_layers: int = NUM_LAYERS_ENC):
        super().__init__()
        self.num_features = num_features
        self.hidden_size = hidden_size
        self.latent_dim = latent_dim

        # Encoder
        self.enc_input = nn.Linear(num_features, hidden_size)
        self.encoder = nn.LSTM(
            input_size=hidden_size, hidden_size=hidden_size,
            num_layers=num_layers, batch_first=True,
            dropout=0.2 if num_layers > 1 else 0.0
        )
        self.enc_bottleneck = nn.Linear(hidden_size, latent_dim)

        # Decoder
        self.dec_expand = nn.Linear(latent_dim, hidden_size)
        self.decoder = nn.LSTM(
            input_size=hidden_size, hidden_size=hidden_size,
            num_layers=1, batch_first=True
        )
        self.dec_output = nn.Linear(hidden_size, num_features)

        self.dropout = nn.Dropout(0.1)
        self.relu = nn.ReLU()

    def encode(self, x: torch.Tensor) -> torch.Tensor:
        """x: (B, L, F) → latent: (B, latent_dim)"""
        projected = self.relu(self.enc_input(x))          # (B, L, H)
        projected = self.dropout(projected)
        _, (hidden, _) = self.encoder(projected)          # hidden: (layers, B, H)
        latent = self.relu(self.enc_bottleneck(hidden[-1]))  # (B, latent_dim)
        return latent

    def decode(self, latent: torch.Tensor, seq_len: int) -> torch.Tensor:
        """latent: (B, latent_dim) → reconstructed: (B, L, F)"""
        expanded = self.relu(self.dec_expand(latent))      # (B, H)
        # Repeat for each timestep
        repeated = expanded.unsqueeze(1).repeat(1, seq_len, 1)  # (B, L, H)
        dec_h = expanded.unsqueeze(0)                      # (1, B, H)
        dec_c = torch.zeros_like(dec_h)
        decoded, _ = self.decoder(repeated, (dec_h, dec_c))  # (B, L, H)
        output = self.dec_output(decoded)                  # (B, L, F)
        return output

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        latent = self.encode(x)
        return self.decode(latent, x.size(1))

    def reconstruction_error(self, x: torch.Tensor) -> torch.Tensor:
        """Per-sample MSE reconstruction error. Returns (B,) tensor."""
        recon = self.forward(x)
        mse = ((x - recon) ** 2).mean(dim=(1, 2))  # mean over (seq_len, features)
        return mse


# ═══════════════════════════════════════════════════════════════════════════════
# 5. TRAINING
# ═══════════════════════════════════════════════════════════════════════════════

def train_model(train_seqs: np.ndarray, val_seqs: np.ndarray,
                num_features: int, epochs: int = EPOCHS) -> Tuple[NetworkFlowLSTMAutoencoder, list]:
    """Train LSTM Autoencoder on BENIGN sequences."""
    device = torch.device("mps" if torch.backends.mps.is_available() else
                          "cuda" if torch.cuda.is_available() else "cpu")
    logger.info(f"Training on device: {device}")

    model = NetworkFlowLSTMAutoencoder(num_features=num_features).to(device)

    train_tensor = torch.tensor(train_seqs, dtype=torch.float32)
    val_tensor = torch.tensor(val_seqs, dtype=torch.float32)

    train_loader = DataLoader(TensorDataset(train_tensor), batch_size=BATCH_SIZE, shuffle=True)
    val_loader = DataLoader(TensorDataset(val_tensor), batch_size=BATCH_SIZE)

    optimizer = torch.optim.Adam(model.parameters(), lr=LEARNING_RATE)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, patience=3, factor=0.5)
    criterion = nn.MSELoss()

    history = []
    best_val_loss = float("inf")
    best_state = None

    for epoch in range(1, epochs + 1):
        # Train
        model.train()
        train_loss = 0.0
        for (batch,) in train_loader:
            batch = batch.to(device)
            optimizer.zero_grad()
            recon = model(batch)
            loss = criterion(recon, batch)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            train_loss += loss.item() * batch.size(0)
        train_loss /= len(train_tensor)

        # Validate
        model.eval()
        val_loss = 0.0
        with torch.no_grad():
            for (batch,) in val_loader:
                batch = batch.to(device)
                recon = model(batch)
                loss = criterion(recon, batch)
                val_loss += loss.item() * batch.size(0)
        val_loss /= len(val_tensor)

        scheduler.step(val_loss)
        lr = optimizer.param_groups[0]["lr"]
        history.append({"epoch": epoch, "train_loss": train_loss, "val_loss": val_loss, "lr": lr})
        logger.info(f"Epoch {epoch:02d}/{epochs} — train_loss: {train_loss:.6f} | val_loss: {val_loss:.6f} | lr: {lr:.1e}")

        if val_loss < best_val_loss:
            best_val_loss = val_loss
            best_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}

    if best_state:
        model.load_state_dict(best_state)
    model.cpu()
    return model, history


# ═══════════════════════════════════════════════════════════════════════════════
# 6. THRESHOLD CALIBRATION
# ═══════════════════════════════════════════════════════════════════════════════

def calibrate_threshold(model: NetworkFlowLSTMAutoencoder,
                        normal_seqs: np.ndarray) -> Tuple[float, float, float]:
    """Compute threshold from normal data reconstruction errors."""
    model.eval()
    errors = []
    loader = DataLoader(TensorDataset(torch.tensor(normal_seqs, dtype=torch.float32)),
                        batch_size=BATCH_SIZE)
    with torch.no_grad():
        for (batch,) in loader:
            err = model.reconstruction_error(batch)
            errors.extend(err.numpy().tolist())

    errors = np.array(errors)
    mean_err = float(np.mean(errors))
    std_err = float(np.std(errors))
    threshold = float(np.percentile(errors, 95))
    threshold_2std = mean_err + 2 * std_err
    # Use the more conservative (lower) threshold
    final_threshold = min(threshold, threshold_2std)

    logger.info(f"Normal errors — mean: {mean_err:.6f}, std: {std_err:.6f}")
    logger.info(f"Threshold (95th pctl): {threshold:.6f}")
    logger.info(f"Threshold (mean+2σ):   {threshold_2std:.6f}")
    logger.info(f"Final threshold:       {final_threshold:.6f}")

    return final_threshold, mean_err, std_err


# ═══════════════════════════════════════════════════════════════════════════════
# 7. EVALUATION
# ═══════════════════════════════════════════════════════════════════════════════

def evaluate(model: NetworkFlowLSTMAutoencoder, test_seqs: np.ndarray,
             test_labels: np.ndarray, threshold: float) -> Dict[str, Any]:
    """Evaluate on mixed normal + attack sequences."""
    model.eval()
    all_errors = []
    loader = DataLoader(TensorDataset(torch.tensor(test_seqs, dtype=torch.float32)),
                        batch_size=BATCH_SIZE)
    with torch.no_grad():
        for (batch,) in loader:
            err = model.reconstruction_error(batch)
            all_errors.extend(err.numpy().tolist())

    all_errors = np.array(all_errors)
    predictions = (all_errors > threshold).astype(int)

    prec = precision_score(test_labels, predictions, zero_division=0)
    rec = recall_score(test_labels, predictions, zero_division=0)
    f1 = f1_score(test_labels, predictions, zero_division=0)
    cm = confusion_matrix(test_labels, predictions)

    metrics = {
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "threshold": round(threshold, 6),
        "mean_normal_error": round(float(all_errors[test_labels == 0].mean()), 6),
        "mean_attack_error": round(float(all_errors[test_labels == 1].mean()), 6),
        "confusion_matrix": cm.tolist(),
    }

    logger.info("=" * 60)
    logger.info("EVALUATION RESULTS")
    logger.info("=" * 60)
    logger.info(f"  Precision: {prec:.4f}")
    logger.info(f"  Recall:    {rec:.4f}")
    logger.info(f"  F1 Score:  {f1:.4f}")
    logger.info(f"  Threshold: {threshold:.6f}")
    logger.info(f"  Normal error (mean):  {metrics['mean_normal_error']:.6f}")
    logger.info(f"  Attack error (mean):  {metrics['mean_attack_error']:.6f}")
    logger.info(f"  Confusion matrix:\n{cm}")
    logger.info("=" * 60)

    return metrics


# ═══════════════════════════════════════════════════════════════════════════════
# 8. SAVE / LOAD
# ═══════════════════════════════════════════════════════════════════════════════

def save_artifacts(model: NetworkFlowLSTMAutoencoder, scaler: StandardScaler,
                   feature_names: list, threshold: float, mean_err: float,
                   std_err: float, metrics: Dict, save_path: str = MODEL_SAVE_PATH):
    """Save model weights, scaler, threshold, and metadata."""
    checkpoint = {
        "model_state_dict": model.state_dict(),
        "num_features": model.num_features,
        "hidden_size": model.hidden_size,
        "latent_dim": model.latent_dim,
        "seq_length": SEQ_LENGTH,
        "threshold": threshold,
        "mean_error": mean_err,
        "std_error": std_err,
        "scaler_mean": scaler.mean_.tolist(),
        "scaler_scale": scaler.scale_.tolist(),
        "feature_names": feature_names,
        "metrics": metrics,
    }
    torch.save(checkpoint, save_path)
    logger.info(f"Saved model + artifacts to {save_path}")
    logger.info(f"  Features: {len(feature_names)}")
    logger.info(f"  File size: {os.path.getsize(save_path) / 1024:.1f} KB")


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="Train LSTM Autoencoder for anomaly detection")
    parser.add_argument("--evaluate-only", action="store_true", help="Only evaluate saved model")
    parser.add_argument("--csv", default=CSV_PATH, help="Path to lstm.csv")
    parser.add_argument("--epochs", type=int, default=EPOCHS)
    parser.add_argument("--sample", type=float, default=0.3, help="Fraction of benign to sample")
    args = parser.parse_args()

    epochs = args.epochs

    # ── Load & preprocess ─────────────────────────────────────────────────
    df = load_data(args.csv, sample_frac=args.sample)
    X_scaled, y, scaler, feature_names = preprocess(df)
    num_features = X_scaled.shape[1]
    del df  # free memory

    # ── Split BENIGN / ATTACK ─────────────────────────────────────────────
    benign_X = X_scaled[y == 0]
    attack_X = X_scaled[y == 1]
    logger.info(f"BENIGN rows: {len(benign_X)}, ATTACK rows: {len(attack_X)}")

    # ── Create sequences ──────────────────────────────────────────────────
    benign_seqs = create_sequences(benign_X, SEQ_LENGTH, STRIDE)
    attack_seqs = create_sequences(attack_X, SEQ_LENGTH, STRIDE)

    # Cap sequences for memory
    if len(benign_seqs) > MAX_TRAIN_SEQUENCES:
        idx = np.random.RandomState(42).choice(len(benign_seqs), MAX_TRAIN_SEQUENCES, replace=False)
        benign_seqs = benign_seqs[idx]
        logger.info(f"Capped benign sequences to {MAX_TRAIN_SEQUENCES}")

    if len(attack_seqs) > MAX_EVAL_SEQUENCES:
        idx = np.random.RandomState(42).choice(len(attack_seqs), MAX_EVAL_SEQUENCES, replace=False)
        attack_seqs = attack_seqs[idx]

    # Train/val split on benign
    n_val = int(len(benign_seqs) * VAL_SPLIT)
    val_seqs = benign_seqs[:n_val]
    train_seqs = benign_seqs[n_val:]
    logger.info(f"Train: {len(train_seqs)} seqs, Val: {len(val_seqs)} seqs, Attack: {len(attack_seqs)} seqs")

    if args.evaluate_only:
        # Load and evaluate
        if not os.path.exists(MODEL_SAVE_PATH):
            logger.error(f"No model found at {MODEL_SAVE_PATH}")
            sys.exit(1)
        checkpoint = torch.load(MODEL_SAVE_PATH, map_location="cpu", weights_only=False)
        model = NetworkFlowLSTMAutoencoder(num_features=checkpoint["num_features"])
        model.load_state_dict(checkpoint["model_state_dict"])
        threshold = checkpoint["threshold"]
    else:
        # ── Train ─────────────────────────────────────────────────────────
        t0 = time.time()
        model, history = train_model(train_seqs, val_seqs, num_features, epochs=epochs)
        logger.info(f"Training completed in {time.time()-t0:.1f}s")

        # ── Calibrate threshold ───────────────────────────────────────────
        threshold, mean_err, std_err = calibrate_threshold(model, val_seqs)

    # ── Evaluate on mixed data ────────────────────────────────────────────
    # Take some normal val sequences + attack sequences
    n_eval_normal = min(len(val_seqs), 10000)
    eval_normal = val_seqs[:n_eval_normal]
    eval_attack = attack_seqs[:min(len(attack_seqs), 10000)]

    test_seqs = np.concatenate([eval_normal, eval_attack])
    test_labels = np.concatenate([
        np.zeros(len(eval_normal), dtype=int),
        np.ones(len(eval_attack), dtype=int)
    ])

    metrics = evaluate(model, test_seqs, test_labels, threshold)

    if not args.evaluate_only:
        save_artifacts(model, scaler, feature_names, threshold, mean_err, std_err, metrics)

    logger.info("Done!")


if __name__ == "__main__":
    main()
