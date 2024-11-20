# MANTILLA
An open source tool to identify runtime libraries on statically linked Linux binaries.

![MANTILLA](img/MANTILLA.jpg "A system for runtiMe librAries ideNtification in sTatIcally-Linked Linux binAries")

The original logo image can be seen [here](https://commons.wikimedia.org/wiki/File:Objectes_de_la_Sala_Sec%C3%A0_i_Muntanya_(26914857930).jpg) and is licensed under the terms of the CC-BY-SA-2.0

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

This system is part of an investigation that is currently under review. We will release the system once the review process is complete.

## Installation

We recommend to install MANTILLA's dependencies with [pip](https://pypi.org/project/pip/) in a virtual environment to not mess up with your current configuration:

```Shell
$ sudo apt update
$ sudo apt install python3-pip python3-venv
```

Create and activate your virtual environment:

```Shell
$ python3 -m venv .
$ source venv/bin/activate
(venv) $ git clone https://github.com/reverseame/MANTILLA.git
```

Now, you can install dependencies in [requirements.txt](requirements.txt):

```Shell
(venv) $ python3 -m pip install -r requirements.txt
```

## Usage

```
usage: MANTILLA.py [-h] [-b BINARY] [-j JSON] [-m METRIC] [-t THRESHOLD]
                   [-k NEIGHBORS] [-f FILE_MODEL] [-d DIRECTORY]

This tool identifies the runtime library in statically linked Linux binaries.

optional arguments:
  -h, --help            show this help message and exit
  -b BINARY, --binary BINARY
                        Specify the binary to analyze
  -j JSON, --json JSON  Specify the features of a binary in JSON format
  -m METRIC, --metric METRIC
                        Specify the distance metric
  -t THRESHOLD, --threshold THRESHOLD
                        Specify the distance threshold
  -k NEIGHBORS, --neighbors NEIGHBORS
                        Specify the number of k-neighbors
  -f FILE_MODEL, --file_model FILE_MODEL
                        Specify the features model CSV file
  -d DIRECTORY, --directory DIRECTORY
                        Specify a directory with test files
```

To extract features from a binary:

```
Usage: python3 feature_extraction.py -s <source_code_path> -b <binary_file>

Options:
  -h, --help            show this help message and exit
  -s SOURCE_CODE_PATH, --source=SOURCE_CODE_PATH
                        Source code directory
  -b BINARY_FILE_PATH, --binary=BINARY_FILE_PATH
                        Binary file path
  -p PDB, --pdb=PDB     PDB file path

```

The datasets used to train and test the model are available at [zenodo](https://zenodo.org/records/7991325)
## License
Licensed under the [GNU GPLv3](LICENSE) license.
