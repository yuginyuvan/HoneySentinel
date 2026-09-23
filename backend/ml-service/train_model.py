import os
import json

import pandas as pd
import joblib

from sklearn.model_selection import (
    train_test_split,
    StratifiedKFold,
    cross_val_score
)

from sklearn.pipeline import Pipeline, FeatureUnion

from sklearn.feature_extraction.text import TfidfVectorizer

from sklearn.linear_model import LogisticRegression

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)


# ============================================================
# CONFIGURATION
# ============================================================

DATASET_PATH = "training_data.csv"

MODEL_DIR = "models"

MODEL_PATH = os.path.join(
    MODEL_DIR,
    "command_classifier.pkl"
)

METRICS_PATH = os.path.join(
    MODEL_DIR,
    "model_metrics.json"
)


# ============================================================
# LOAD DATASET
# ============================================================

def load_dataset():

    print("=" * 70)
    print("HoneySentinel ML Threat Classifier")
    print("=" * 70)

    print("\n[1] Loading dataset...")

    df = pd.read_csv(DATASET_PATH)

    print(
        f"Original dataset size: {len(df)}"
    )

    # Remove invalid rows
    df = df.dropna(
        subset=["command", "label"]
    )

    # Convert to strings
    df["command"] = df["command"].astype(str)
    df["label"] = df["label"].astype(str)

    # Remove exact duplicate command + label pairs
    df = df.drop_duplicates(
        subset=["command", "label"]
    )

    print(
        f"Dataset size after cleaning: {len(df)}"
    )

    return df


# ============================================================
# DATASET INFORMATION
# ============================================================

def show_dataset_info(df):

    print("\n" + "=" * 70)
    print("DATASET INFORMATION")
    print("=" * 70)

    print(
        f"\nTotal samples : {len(df)}"
    )

    print(
        f"Number classes: {df['label'].nunique()}"
    )

    print("\nClass distribution:")
    print("-" * 40)

    print(
        df["label"].value_counts()
    )

    print("-" * 40)


# ============================================================
# BUILD MODEL
# ============================================================

def build_model():

    print("\n[2] Building ML pipeline...")

    # --------------------------------------------------------
    # WORD FEATURES
    # --------------------------------------------------------

    word_features = TfidfVectorizer(

        analyzer="word",

        lowercase=True,

        ngram_range=(1, 2),

        sublinear_tf=True,

        min_df=1,

        max_features=5000
    )


    # --------------------------------------------------------
    # CHARACTER FEATURES
    # --------------------------------------------------------

    char_features = TfidfVectorizer(

        analyzer="char",

        lowercase=True,

        ngram_range=(2, 6),

        sublinear_tf=True,

        min_df=1,

        max_features=10000
    )


    # --------------------------------------------------------
    # COMBINE WORD + CHARACTER FEATURES
    # --------------------------------------------------------

    features = FeatureUnion([

        (
            "word_tfidf",
            word_features
        ),

        (
            "char_tfidf",
            char_features
        )

    ])


    # --------------------------------------------------------
    # LOGISTIC REGRESSION
    # --------------------------------------------------------

    classifier = LogisticRegression(

        C=5.0,

        max_iter=3000,

        class_weight="balanced",

        solver="lbfgs",

        random_state=42
    )


    # --------------------------------------------------------
    # COMPLETE PIPELINE
    # --------------------------------------------------------

    model = Pipeline([

        (
            "features",
            features
        ),

        (
            "classifier",
            classifier
        )

    ])


    return model


# ============================================================
# EVALUATION
# ============================================================

def evaluate_model(
    model,
    X_test,
    y_test
):

    print("\n[5] Evaluating model...")

    predictions = model.predict(
        X_test
    )


    # --------------------------------------------------------
    # METRICS
    # --------------------------------------------------------

    accuracy = accuracy_score(
        y_test,
        predictions
    )

    macro_precision = precision_score(
        y_test,
        predictions,
        average="macro",
        zero_division=0
    )

    macro_recall = recall_score(
        y_test,
        predictions,
        average="macro",
        zero_division=0
    )

    macro_f1 = f1_score(
        y_test,
        predictions,
        average="macro",
        zero_division=0
    )

    weighted_f1 = f1_score(
        y_test,
        predictions,
        average="weighted",
        zero_division=0
    )


    # --------------------------------------------------------
    # DISPLAY
    # --------------------------------------------------------

    print("\n" + "=" * 70)
    print("MODEL EVALUATION")
    print("=" * 70)

    print(
        f"\nAccuracy       : {accuracy * 100:.2f}%"
    )

    print(
        f"Macro Precision: {macro_precision * 100:.2f}%"
    )

    print(
        f"Macro Recall   : {macro_recall * 100:.2f}%"
    )

    print(
        f"Macro F1       : {macro_f1 * 100:.2f}%"
    )

    print(
        f"Weighted F1    : {weighted_f1 * 100:.2f}%"
    )


    # --------------------------------------------------------
    # CLASSIFICATION REPORT
    # --------------------------------------------------------

    print("\n" + "=" * 70)
    print("CLASSIFICATION REPORT")
    print("=" * 70)

    print(
        classification_report(
            y_test,
            predictions,
            zero_division=0
        )
    )


    # --------------------------------------------------------
    # CONFUSION MATRIX
    # --------------------------------------------------------

    print("=" * 70)
    print("CONFUSION MATRIX")
    print("=" * 70)

    labels = sorted(
        y_test.unique()
    )

    cm = confusion_matrix(
        y_test,
        predictions,
        labels=labels
    )

    print("\nLabels:")
    print(labels)

    print("\nMatrix:")

    for row in cm:
        print(row)


    # --------------------------------------------------------
    # MISCLASSIFIED COMMANDS
    # --------------------------------------------------------

    print("\n" + "=" * 70)
    print("MISCLASSIFIED COMMANDS")
    print("=" * 70)

    errors = []

    for command, actual, predicted in zip(
        X_test,
        y_test,
        predictions
    ):

        if actual != predicted:

            errors.append(
                (
                    command,
                    actual,
                    predicted
                )
            )


    print(
        f"\nTotal misclassified: {len(errors)}"
    )

    for i, (
        command,
        actual,
        predicted
    ) in enumerate(errors, start=1):

        print(f"\n[{i}] Command:")
        print(f"    {command}")

        print(
            f"    Actual    : {actual}"
        )

        print(
            f"    Predicted : {predicted}"
        )

        print("-" * 70)


    return {

        "accuracy": float(accuracy),

        "macro_precision": float(
            macro_precision
        ),

        "macro_recall": float(
            macro_recall
        ),

        "macro_f1": float(
            macro_f1
        ),

        "weighted_f1": float(
            weighted_f1
        ),

        "test_samples": len(y_test),

        "misclassified": len(errors)

    }


# ============================================================
# CROSS VALIDATION
# ============================================================

def cross_validate_model(
    model,
    X,
    y
):

    print("\n" + "=" * 70)
    print("5-FOLD CROSS VALIDATION")
    print("=" * 70)

    print(
        "\nRunning 5-fold stratified cross-validation..."
    )

    cv = StratifiedKFold(

        n_splits=5,

        shuffle=True,

        random_state=42
    )


    scores = cross_val_score(

        model,

        X,

        y,

        cv=cv,

        scoring="f1_macro",

        n_jobs=-1
    )


    print("\nFold Macro-F1 scores:")

    for i, score in enumerate(
        scores,
        start=1
    ):

        print(
            f"Fold {i}: {score * 100:.2f}%"
        )


    mean_score = scores.mean()

    std_score = scores.std()


    print(
        f"\nMean CV Macro-F1: "
        f"{mean_score * 100:.2f}%"
    )

    print(
        f"CV Std Deviation: "
        f"{std_score * 100:.2f}%"
    )


    return {

        "fold_scores": [
            float(score)
            for score in scores
        ],

        "mean_macro_f1": float(
            mean_score
        ),

        "std_macro_f1": float(
            std_score
        )

    }


# ============================================================
# MAIN
# ============================================================

def main():

    # --------------------------------------------------------
    # LOAD
    # --------------------------------------------------------

    df = load_dataset()


    # --------------------------------------------------------
    # DATASET INFO
    # --------------------------------------------------------

    show_dataset_info(df)


    # --------------------------------------------------------
    # FEATURES / LABELS
    # --------------------------------------------------------

    X = df["command"]

    y = df["label"]


    # --------------------------------------------------------
    # TRAIN / TEST SPLIT
    # --------------------------------------------------------

    print("\n[3] Splitting dataset...")

    X_train, X_test, y_train, y_test = train_test_split(

        X,

        y,

        test_size=0.20,

        random_state=42,

        stratify=y
    )


    print(
        f"Training samples: {len(X_train)}"
    )

    print(
        f"Testing samples : {len(X_test)}"
    )


    # --------------------------------------------------------
    # BUILD MODEL
    # --------------------------------------------------------

    model = build_model()


    # --------------------------------------------------------
    # TRAIN
    # --------------------------------------------------------

    print(
        "\n[4] Training Logistic Regression model..."
    )

    model.fit(

        X_train,

        y_train
    )

    print(
        "Training completed successfully."
    )


    # --------------------------------------------------------
    # TEST EVALUATION
    # --------------------------------------------------------

    test_metrics = evaluate_model(

        model,

        X_test,

        y_test
    )


    # --------------------------------------------------------
    # CROSS VALIDATION
    # --------------------------------------------------------

    cv_metrics = cross_validate_model(

        model,

        X,

        y
    )


    # --------------------------------------------------------
    # SAVE MODEL
    # --------------------------------------------------------

    print(
        "\n[6] Saving trained model..."
    )

    os.makedirs(

        MODEL_DIR,

        exist_ok=True
    )


    joblib.dump(

        model,

        MODEL_PATH
    )


    print(
        "\nModel saved to:"
    )

    print(
        os.path.abspath(
            MODEL_PATH
        )
    )


    # --------------------------------------------------------
    # SAVE METRICS
    # --------------------------------------------------------

    metrics = {

        "dataset_size": len(df),

        "number_of_classes":
            int(df["label"].nunique()),

        "test_accuracy":
            test_metrics["accuracy"],

        "test_macro_precision":
            test_metrics["macro_precision"],

        "test_macro_recall":
            test_metrics["macro_recall"],

        "test_macro_f1":
            test_metrics["macro_f1"],

        "test_weighted_f1":
            test_metrics["weighted_f1"],

        "test_samples":
            test_metrics["test_samples"],

        "misclassified":
            test_metrics["misclassified"],

        "cv_macro_f1":
            cv_metrics["mean_macro_f1"],

        "cv_std":
            cv_metrics["std_macro_f1"],

        "cv_fold_scores":
            cv_metrics["fold_scores"],

        "model":
            "LogisticRegression",

        "features":
            "Word TF-IDF + Character TF-IDF"

    }


    with open(
        METRICS_PATH,
        "w"
    ) as f:

        json.dump(
            metrics,
            f,
            indent=4
        )


    print(
        "\nMetrics saved to:"
    )

    print(
        os.path.abspath(
            METRICS_PATH
        )
    )


    # --------------------------------------------------------
    # FINAL SUMMARY
    # --------------------------------------------------------

    print("\n" + "=" * 70)
    print("TRAINING COMPLETE")
    print("=" * 70)

    print(
        f"\nDataset size     : {len(df)}"
    )

    print(
        f"Classes          : "
        f"{df['label'].nunique()}"
    )

    print(
        f"Test Accuracy    : "
        f"{test_metrics['accuracy'] * 100:.2f}%"
    )

    print(
        f"Test Macro-F1    : "
        f"{test_metrics['macro_f1'] * 100:.2f}%"
    )

    print(
        f"CV Macro-F1      : "
        f"{cv_metrics['mean_macro_f1'] * 100:.2f}%"
    )

    print(
        f"Misclassified    : "
        f"{test_metrics['misclassified']}"
    )

    print("\nModel:")
    print(
        os.path.abspath(
            MODEL_PATH
        )
    )

    print("\nMetrics:")
    print(
        os.path.abspath(
            METRICS_PATH
        )
    )

    print("\n" + "=" * 70)


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()