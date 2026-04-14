import logging
import time
from collections import deque

import numpy as np
from sklearn.ensemble import IsolationForest

logger = logging.getLogger(__name__)


# The feature columns we feed to the anomaly detector
# Must be numeric — strings can't be used directly
ANOMALY_FEATURE_COLS = [
    "length",           # domain length
    "entropy",          # randomness
    "subdomains",       # depth of subdomain nesting
    "consonant_ratio",  # fraction of consonants
    "numeric_ratio",    # fraction of digits
    "unique_ratio",     # fraction of unique chars
    "longest_label",    # longest label segment
    "has_hex",          # hex pattern flag (0 or 1)
]


class AnomalyDetector:
    
    def __init__(self,
                 warmup=300,
                 buffer_size=2000,
                 contamination=0.05,
                 retrain_interval=500):
       
        self.warmup            = warmup
        self.contamination     = contamination
        self.retrain_interval  = retrain_interval

        # Rolling buffer of recent feature vectors
        # deque(maxlen=N) automatically drops oldest entries when full
        # We train on this buffer — it represents "recent normal traffic"
        self._buffer = deque(maxlen=buffer_size)

        # The Isolation Forest model (None until training completes)
        self._model = None

        # Counters
        self._packets_seen   = 0   # total packets processed
        self._since_retrain  = 0   # packets since last model retrain
        self._anomalies_seen = 0   # total anomalies flagged

        # Flag: is the detector trained and ready?
        self._trained = False

        # Track when training happened
        self._last_train_time = None

    @property
    def is_ready(self):
           return self._trained

    @property
    def warmup_progress(self):
        if self._trained:
            return 1.0
        return min(self._packets_seen / self.warmup, 1.0)

    def score(self, features):
        self._packets_seen += 1

        # Extract the numeric feature vector from the features dict
        # features.get(col, 0) returns 0 if the key doesn't exist
        vec = [features.get(col, 0) for col in ANOMALY_FEATURE_COLS]

        # Skip packets with no meaningful data (empty queries, response packets)
        # An all-zero vector doesn't help the model learn
        if sum(vec) == 0:
            return False, 0.0

        # Add this packet's features to the rolling buffer
        self._buffer.append(vec)
        self._since_retrain += 1

        # --- Check if we should train or retrain ---
        should_train = (
            not self._trained and
            len(self._buffer) >= self.warmup
        )
        should_retrain = (
            self._trained and
            self._since_retrain >= self.retrain_interval
        )

        if should_train or should_retrain:
            self._train()

        # --- Score the packet if model is ready ---
        if not self._trained:
            # Still in warmup — return no anomaly
            return False, 0.0

        return self._predict(vec)

    def _train(self):
        try:
            # Convert the buffer deque to a numpy array
            # np.array() creates a 2D matrix: rows=packets, cols=features
            X = np.array(list(self._buffer))

            # IsolationForest constructor parameters:
            #   n_estimators=100  : number of isolation trees (more = more accurate)
            #   contamination=0.05: expected fraction of anomalies
            #   random_state=42   : reproducible results
            #   n_jobs=-1         : use all CPU cores (faster training)
            self._model = IsolationForest(
                n_estimators=100,
                contamination=self.contamination,
                random_state=42,
                n_jobs=-1,
            )

            # fit() trains the model on the buffer data
            # No labels needed (unsupervised learning)
            self._model.fit(X)

            self._trained        = True
            self._since_retrain  = 0
            self._last_train_time = time.time()

            logger.info(
                f"AnomalyDetector trained on {len(X)} samples. "
                f"Packets seen: {self._packets_seen}"
            )

        except Exception as e:
            logger.error(f"AnomalyDetector training failed: {e}")

    def _predict(self, vec):
    
        try:
            # Reshape vec to a 2D array [[f1, f2, ...]] (model needs 2D)
            X = np.array([vec])

            # predict() returns 1 (normal) or -1 (anomaly)
            label = self._model.predict(X)[0]

            # decision_function() returns a raw anomaly score
            # More negative = more anomalous
            raw_score = self._model.decision_function(X)[0]

            # Convert raw score to a 0.0–1.0 range
            # Raw scores are typically in range [-0.5, 0.5]
            # We map this to [0, 1] where 1 = very anomalous
            normalised_score = max(0.0, min(1.0, 0.5 - raw_score))

            is_anomaly = (label == -1)   # -1 = anomaly in Isolation Forest

            if is_anomaly:
                self._anomalies_seen += 1

            return is_anomaly, round(normalised_score, 3)

        except Exception as e:
            logger.error(f"AnomalyDetector prediction failed: {e}")
            return False, 0.0

    def get_stats(self):
        """Returns current detector statistics for display in the GUI."""
        return {
            "trained":          self._trained,
            "warmup_progress":  round(self.warmup_progress * 100, 1),
            "packets_seen":     self._packets_seen,
            "buffer_size":      len(self._buffer),
            "anomalies_flagged":self._anomalies_seen,
            "last_trained":     self._last_train_time,
            "contamination":    self.contamination,
        }

    def reset(self):
        """Resets the detector to an untrained state (call when restarting monitoring)."""
        self._buffer.clear()
        self._model          = None
        self._trained        = False
        self._packets_seen   = 0
        self._since_retrain  = 0
        self._anomalies_seen = 0
        self._last_train_time = None
        logger.info("AnomalyDetector reset.")
