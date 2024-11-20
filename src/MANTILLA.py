import argparse
import pandas as pd
from sklearn.neighbors import KNeighborsClassifier
from collections import Counter
import os
import json
import sys
from feature_extraction import analyze_binary

def get_feature_dict(func):
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
    }

def get_features_test(files):
    """Extract features from test JSON files."""
    features = []
    duplicate_count = 0
    for file in files:
        with open(file, "r") as f:
            data = json.load(f)

        for func_name, func_data in data.items():
            if func_name != 'file':
                feature = get_feature_dict(func_data)
                features.append(feature)
    return features


def parse_arguments():
    """Parse and validate command-line arguments."""
    parser = argparse.ArgumentParser(
        description="This tool identifies the runtime library in statically linked Linux binaries."
    )
    parser.add_argument("-b", "--binary", type=str, help="Specify the binary to analyze")
    parser.add_argument("-j", "--json", type=str, help="Specify the features of a binary in JSON format")
    parser.add_argument("-m", "--metric", type=str, default="euclidean", help="Specify the distance metric")
    parser.add_argument("-t", "--threshold", type=float, default=1.0, help="Specify the distance threshold")
    parser.add_argument("-k", "--neighbors", type=int, default=5, help="Specify the number of k-neighbors")
    parser.add_argument("-f", "--file_model", type=str, default="features_model.csv", help="Specify the features model CSV file")
    parser.add_argument("-d", "--directory", type=str, help="Specify a directory with test files")

    args = parser.parse_args()
    if not args.binary and not args.json and not args.directory:
        parser.print_help()
        sys.exit(1)
    return args


def prepare_test_files(args):
    """Determine the list of test files based on the input arguments."""
    if args.directory:
        return [os.path.join(args.directory, f) for f in os.listdir(args.directory)]
    if args.json:
        return [args.json]
    if args.binary:
        output_file = analyze_binary(args.binary, [], [])

        return [output_file]
    return []


def train_knn_model(features_file, n_neighbors, metric):
    """Load features and train the KNN model."""
    df = pd.read_csv(features_file).drop_duplicates()
    X = df.drop(columns="label").values
    y = df["label"].values
    model = KNeighborsClassifier(n_neighbors=n_neighbors, metric=metric)
    model.fit(X, y)
    return model, X, y


def classify_file(model, test_features, X, y, threshold=1):

    results = {"predictions": []}
    df_test = pd.DataFrame(test_features)
    X_test = df_test.values

    if X_test.size == 0:
        return results

    kneighbors_distance, kneighbors_index_labels = model.kneighbors(X_test)

    predicted_labels = [
        y[kneighbors_index_labels[d][index]]
        for d in range(len(kneighbors_distance))
        for index in range(len(kneighbors_distance[d]))
        if kneighbors_distance[d][index] <= threshold
    ]

    results["predictions"] = predicted_labels
    return results



def main():
    args = parse_arguments()
    test_files = prepare_test_files(args)

    model, X, y = train_knn_model(args.file_model, args.neighbors, args.metric)

    for test_file in test_files:
        test_features = get_features_test([test_file])
        results = classify_file(model, test_features, X, y, args.threshold)
        print(f"File: {test_file}")

        all_predictions = [pred for pred in results["predictions"]]

        if all_predictions:
            print(len(all_predictions))
            most_common_prediction, count = Counter(all_predictions).most_common(1)[0]
            print(f"Most common prediction: {most_common_prediction} (Count: {count})")
        else:
            print("No predictions were made")


if __name__ == "__main__":
    main()
