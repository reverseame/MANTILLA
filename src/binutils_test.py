import json
import os
from nltk import ngrams
from sklearn.model_selection import StratifiedShuffleSplit
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction import DictVectorizer
from sklearn.neighbors import KNeighborsClassifier
import numpy as np
from collections import Counter
from sklearn.model_selection import StratifiedKFold

import matplotlib.pyplot as plt
from sklearn.metrics import classification_report
from sklearn.metrics import confusion_matrix
import itertools
import pandas as pd

from MANTILLA import train_knn_model, classify_file


def get_feature_dict(func, compiler_label):
    """Extract feature dictionary from a function's data."""
    return {
        'cc': func['cc'],
        'cost': func['cost'],
        'size': func['size'],
        'stackframe': func['stackframe'],
        'nbbs': func['nbbs'],
        'ninst': func['ninst'],
        'edges': func['edges'],
        'ebbs': func['ebbs'],
        'noreturn': 1 if func.get('noreturn', False) else 0,
        'outdegree': func['outdegree'],
        'nlocals': func['nlocals'],
        'nargs': func['nargs'],
        'entropy': func.get('entropy', -1),
        'fnc_callgraph': len(func['fnc_callgraph']),
        'label': compiler_label,
    }


def get_features_test(files):
    X = []
    y = []
    same_feature_array = 0
    for file in files:
        with open(file, "r") as f:
            data = json.load(f)
            name_file = file.split(".json")[0]
            arch = name_file.split("-")[-2]
            lib = name_file.split("-")[-1]
            compiler = arch

            if "-x86-" in name_file or "i686" in name_file:
                compiler = "x86"
            if "x86_64" in name_file:
                compiler = "x86-64"

            compiler_label = compiler + "_" + lib + "_gcc"

            for i in data:

                if i != 'file':

                        features = get_feature_dict(data[i], compiler_label)

                        if features in X:
                            same_feature_array += 1
                        X.append(features)
                        # y.append(compiler_label)

    return X  # ,y


def main():
    model, X_train, y_train = train_knn_model("features_model.csv", 5, "minkowski")

    ok = 0
    fail = 0

    X_test_files = os.listdir("./dataset_json_binutils")
    X_test_files = list(map(lambda x: os.path.join("./dataset_json_binutils", x), X_test_files))

    for i in X_test_files:

        df2 = pd.DataFrame(get_features_test([i]))
        y_test = df2["label"].values
        X_test = df2.drop(columns="label").values
        label_predict = []
        if len(X_test) != 0:

            results = classify_file(model, X_test, X_train, y_train, 0.5)
            all_predictions = [pred for pred in results["predictions"]]

            if all_predictions:
                most_common_prediction, count = Counter(all_predictions).most_common(1)[0]

                if most_common_prediction == y_test[0]:
                    ok += 1
                    print("OK: {} Pred:{} Real: {} file: {} label: {}".format(ok, most_common_prediction,
                                                                                    y_test[0], i, len(all_predictions)))
                else:
                    fail += 1
                    print(
                        "FAIL: {} Pred:{} Real: {} file: {} label:{}".format(fail, most_common_prediction, y_test[0],
                                                                              i, len(all_predictions)))
    print("Correct: {}".format(ok))
    print("Errors: {}".format(fail))
    print("Percentage: {}".format(ok / (fail + ok)))
    print("TOTAL: {}".format(ok + fail))
    print("TOTAL FILES: {}".format(len(X_test_files)))


if __name__ == '__main__':
    main()
