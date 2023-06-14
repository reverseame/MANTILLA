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
$ source bin/activate
(venv) $ git clone https://github.com/reverseame/MANTILLA.git
```

Now, you can install dependencies in [requirements.txt](requirements.txt):

```Shell
(venv) $ python3 -m pip install -r requirements.txt
```

## Usage

```
usage: MANTILLA.py [-h] [-b] [-d] [-k]

This tool allows you to identify the runtime library on statically linked Linux Binaries

optional arguments:
  -h, --help            show this help message and exit
  -b, --binary          specify the binary to analyze
  -d <distance>         specify the distance metric
  -t <threshold>        specify the distance threshold
  -k <neighbors>        specify the number of k-neighbors
```
## License
Licensed under the [GNU GPLv3](LICENSE) license.
