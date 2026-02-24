"""
app/utils/deep_model_bundle.py
─────────────────────────────────────────────────────────────
Module-level class for the Stage 2 Deep Model.
Moving this to a dedicated module allows joblib to pickle/unpickle
the model correctly across different scopes (training vs api).
"""

from __future__ import annotations
import numpy as np

class DeepModelBundle:
    """
    Bundles imputer + XGBClassifier + IsotonicRegression into a single
    pickleable object that ModelService can load and call predict_proba(X) on.

    Inference chain: X → imputer.transform → xgb.predict_proba → iso.transform
    """

    def __init__(self, imputer, xgb, iso_regressor) -> None:
        self.imputer       = imputer
        self.xgb           = xgb
        self.iso_regressor = iso_regressor

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Apply imputer, then XGB, then isotonic calibration."""
        imp_X  = self.imputer.transform(X)
        # XGBoost predict_proba returns [p_safe, p_phishing]
        raw_p  = self.xgb.predict_proba(imp_X)[:, 1]
        
        # Isotonic regression clips or interpolates the raw probability
        cal_p  = self.iso_regressor.transform(raw_p)
        
        # Expand back to [p_safe, p_phishing]
        result       = np.zeros((len(X), 2))
        result[:, 1] = cal_p
        result[:, 0] = 1.0 - cal_p
        return result

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Return binary labels based on 0.5 threshold on calibrated proba."""
        return (self.predict_proba(X)[:, 1] >= 0.5).astype(int)
