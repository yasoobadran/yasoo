import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import RandomizedSearchCV, StratifiedKFold, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


DATASET_PATH = Path("Dataset/dataset_phishing.csv")
MODEL_PATH = Path("phishing_model.pkl")
FEATURES_PATH = Path("feature_columns.pkl")
REPORT_PATH = Path("training_report.txt")
RANDOM_STATE = 42


def build_pipeline():
    """Create a preprocessing + model pipeline."""
    preprocess = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
        ]
    )

    model = RandomForestClassifier(
        class_weight="balanced",
        n_jobs=-1,
        random_state=RANDOM_STATE,
    )

    return Pipeline(
        steps=[
            ("preprocess", preprocess),
            ("model", model),
        ]
    )


def load_dataset():
    df = pd.read_csv(DATASET_PATH)
    y = df["status"].astype(str).str.lower().map({"legitimate": 0, "phishing": 1}).astype(int)
    feature_columns = [col for col in df.columns if col not in ["url", "status"]]
    X = df[feature_columns].copy().replace({None: np.nan})
    return X, y, feature_columns, df.shape[0]


def main():
    X, y, feature_columns, row_count = load_dataset()
    print(f"Loaded dataset with {row_count} rows and {len(feature_columns)} features.")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        stratify=y,
        random_state=RANDOM_STATE,
    )

    pipeline = build_pipeline()

    param_distributions = {
        "model__n_estimators": [200, 300, 400, 500],
        "model__max_depth": [None, 20, 30, 40],
        "model__min_samples_split": [2, 4, 6, 10],
        "model__min_samples_leaf": [1, 2, 4],
        "model__max_features": ["sqrt", "log2", 0.5],
    }

    cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=RANDOM_STATE)

    search = RandomizedSearchCV(
        estimator=pipeline,
        param_distributions=param_distributions,
        n_iter=15,
        scoring="f1",
        n_jobs=-1,
        cv=cv,
        verbose=1,
        random_state=RANDOM_STATE,
        refit=True,
    )

    print("Running hyper-parameter search...")
    search.fit(X_train, y_train)
    best_model = search.best_estimator_

    print(f"Best params: {search.best_params_}")

    print("\nEvaluating on hold-out set...")
    y_pred = best_model.predict(X_test)
    y_proba = best_model.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    roc_auc = roc_auc_score(y_test, y_proba)
    f1 = f1_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred)

    class_report = classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"])

    print(f"\nAccuracy: {acc:.4f}")
    print(f"ROC-AUC: {roc_auc:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall: {recall:.4f}")
    print(f"F1-score: {f1:.4f}")
    print("\nConfusion Matrix:")
    print(cm)
    print("\nClassification Report:")
    print(class_report)

    print("\nPersisting artifacts...")
    joblib.dump(best_model, MODEL_PATH)
    joblib.dump(list(feature_columns), FEATURES_PATH)

    report_payload = {
        "sklearn": sklearn.__version__,
        "rows": row_count,
        "features": len(feature_columns),
        "accuracy": round(acc, 4),
        "roc_auc": round(roc_auc, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "best_params": search.best_params_,
    }

    REPORT_PATH.write_text(json.dumps(report_payload, indent=2))
    print("Training completed successfully!")


if __name__ == "__main__":
    main()
