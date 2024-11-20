import os
import re
import json
import magic
import subprocess
import collections
import math
import binascii
import tlsh
import ssdeep
import r2pipe
from optparse import OptionParser


class FileUtils:
    @staticmethod
    def get_all_files(folder_path):
        return [os.path.join(root, file) for root, dirs, files in os.walk(folder_path) for file in files]

    @staticmethod
    def filter_code_files(all_files_list):
        pattern_files = r'.*\.(c|cpp)$'
        pattern_text = r'\bC\+{0,2}\s*source\b'
        return [file for file in all_files_list if re.match(pattern_files, file) and re.search(pattern_text, magic.from_file(file))]


class SourceCodeAnalyzer:
    @staticmethod
    def extract_functions(source_code_list):
        functions = []
        for file in source_code_list:
            try:
                cflow_output = subprocess.check_output(
                    f'cflow --all --all -i_ {file} 2>/dev/null',
                    shell=True
                ).decode().split("\n")
                functions.extend([
                    match.group()
                    for line in cflow_output
                    if (match := re.search(r'\w+\s*(?=\()', line.strip()))
                ])
            except subprocess.CalledProcessError:
                continue
        return functions


class EntropyCalculator:
    # Snipped from https://stackoverflow.com/questions/15450192/fastest-way-to-compute-entropy-in-python
    @staticmethod
    def calculate_entropy(data):
        probabilities = [n_x / len(data) for x, n_x in collections.Counter(data).items()]
        e_x = [-p_x * math.log(p_x, 2) for p_x in probabilities]
        return sum(e_x)


class BinaryAnalyzer:
    def __init__(self, binary_file, pdb=None):
        self.file = binary_file
        self.r2_handler = r2pipe.open(binary_file, flags=['-2'])
        if pdb:
            self.r2_handler.cmd(f"idp {pdb}")
        self.r2_handler.cmd('aaa')
        self.string_references = self._extract_string_references()

    def __del__(self):
        self.r2_handler.quit()

    def get_functions(self):
        func_list = json.loads(self.r2_handler.cmd('aflj'))
        imports = self.get_imports()
        return [
            {'name': func['name'], 'offset': func['offset']}
            for func in func_list
            if 'sym.imp.' not in func['name'] and not any(func['name'] in imported_func for imported_func in imports)
        ]

    def get_imports(self):
        imports = json.loads(self.r2_handler.cmd('iij'))
        return [imp['name'] for imp in imports]

    def extract_function_features(self, function_name, offset):

        func_data = json.loads(self.r2_handler.cmd(f"s {offset}; afij"))[0]

        features = {
            'name': function_name,
            'offset': func_data['offset'],
            'cc': func_data['cc'],
            'cost': func_data['cost'],
            'size': func_data['size'],
            'stackframe': func_data['stackframe'],
            'nbbs': func_data['nbbs'],
            'ninst': func_data['ninstrs'],
            'edges': func_data['edges'],
            'ebbs': func_data['ebbs'],
            'noreturn': func_data['noreturn'],
            'indegree': func_data['indegree'],
            'outdegree': func_data['outdegree'],
            'nlocals': func_data['nlocals'] if 'nlocals' in func_data else 0,
            'nargs': func_data['nargs'] if 'nargs' in func_data else 0,
            'opcodes': self._extract_opcodes(offset),
            'bytes': self._get_fnc_bytes(function_name, offset),
            'tlsh_hash_bytes': self._get_tlsh_hash(function_name, offset),
            'ssdeep': self._get_ssdeep_hash(function_name, offset),
            'entropy': self._calculate_entropy(func_data, offset),
            'fnc_callgraph': self._extract_callgraph_imports(offset),
            'str': list(set(self.string_references.get(function_name, [])))
        }
        return features


    def _get_tlsh_hash(self, function_name, offset):
        try:
            for item in json.loads(self.r2_handler.cmd(f"zaf @{offset}; zj")):
                if item['addr'] == offset:
                    return tlsh.hash(item['bytes'].encode())
            return None
        except:
            return None

    def _get_ssdeep_hash(self, function_name, offset):
        try:
            for item in json.loads(self.r2_handler.cmd(f"zaf @{offset}; zj")):
                if item['addr'] == offset:
                    return ssdeep.hash(item['bytes'])
            return None
        except:
            return None

    def _get_fnc_bytes(self, function_name, offset):
        try:
            for item in json.loads(self.r2_handler.cmd(f"zaf @{offset}; zj")):
                if item['addr'] == offset:
                    return item['bytes']
            return None
        except:
            return None


    def _extract_opcodes(self, offset_func):
        try:
            ops = json.loads(self.r2_handler.cmd(f"s {offset_func}; pdfj"))
            return [op['opcode'].split(' ')[0] for op in ops['ops'] if 'opcode' in op]
        except:
            return []

    def _extract_callgraph_imports(self, offset):
        try:
            graph = json.loads(self.r2_handler.cmd(f'agcj {offset}'))
            return graph[0]['imports'] if graph else []
        except:
            return []

    def _extract_string_references(self):
        str_list = json.loads(self.r2_handler.cmd("izj"))
        references = {}
        for string in str_list:
            refs = json.loads(self.r2_handler.cmd(f"axtj @{string['vaddr']}"))
            for ref in refs:
                if 'fcn_name' in ref:
                    references.setdefault(ref['fcn_name'], []).append(string['string'])
        return references

    def _calculate_entropy(self, function_name, offset):
        for item in json.loads(self.r2_handler.cmd(f"zaf @{offset}; zj")):
            if item['addr'] == offset:
                data = binascii.unhexlify(item['bytes'])
                return EntropyCalculator.calculate_entropy(data)
        return -1


class FunctionFilter:
    @staticmethod
    def clean_function_names(function_names):
        pattern = r'_[1-9]{1,2}$'
        prefixes = r'^(sym\.imp\.|sym\.|pdb\._|dbg\._|dbg\.)'
        clean_names = []

        for func in function_names:
            clean_name = re.sub(prefixes, '', func['name'])
            clean_name = re.sub(pattern, '', clean_name)
            clean_names.append({'name': clean_name, 'offset': func['offset']})

        return clean_names

    @staticmethod
    def remove_fnc_c_plus(clean_names, code_functions):
        return [
            item for item in clean_names
            if not any(code in item['name'] for code in code_functions if code != 'main')
        ]


    @staticmethod

    def remove_glibc(clean_names):
        # Define the glibc files to check
        glibc_files = ["glibc_32.txt", "glibc_functions.txt", "uclibc_functions.txt", "musl_functions.txt"]

        # Load all glibc names into a set
        glibc_names = set()
        for file in glibc_files:
            if os.path.exists(file):
                with open(file, "r") as f:
                    glibc_names.update(f.read().splitlines())

        # Filter clean_names, keeping only those whose 'name' is not in glibc_names
        return [item for item in clean_names if item['name'] not in glibc_names]

    @staticmethod
    def remove_known_fnc(clean_names):
        # File containing known function names
        known_functions_file = "./List_total_functions_uniq_clean.txt"

        # Load known function names into a set
        known_fnc_list = set()
        if os.path.exists(known_functions_file):
            with open(known_functions_file, "r") as f:
                known_fnc_list.update(f.read().splitlines())

        # Criteria for removal
        suffixes_to_remove = [
            "_ia32", ".cold", "ifunc", "_ssse3", "_sse2", ".0", "_sse42",
            "sse2_bsf", "_sse4", "_internal", "_sse2_rep", "_ssse3_back",
            "_avx2", "_rtm", "_erms", "_unaligned", "no_vzeroupper",
            "_avx", "sse2_no_bsf", "evex", "evex_movbe", "avx2_movbe",
            "_nocancel", "_neon", "_noneon", "_vfp", "_from_arm", "_test",
            "__gnu_", "unwind", "_Unwind", "next_unwind", "___Unwind"
        ]
        prefixes_to_remove = ["_IO", "_dl_tunable", "__GI_"]
        exact_matches_to_remove = [".plt"]

        # Filter clean_names
        return [
            item for item in clean_names
            if item['name'] not in known_fnc_list and
               not any(item['name'].endswith(suffix) for suffix in suffixes_to_remove) and
               not any(item['name'].startswith(prefix) for prefix in prefixes_to_remove) and
               item['name'] not in exact_matches_to_remove
        ]

def analyze_binary(binary_file_path, pdb, code_functions):
    # Perform binary analysis
    analyzer = BinaryAnalyzer(binary_file_path, pdb)
    binary_functions = analyzer.get_functions()

    # Clean and filter functions
    clean_functions = filter_functions(binary_functions, code_functions)

    # Collect function features
    function_features = build_function_features(analyzer, clean_functions)

    # Save function features to a JSON file
    output_file = save_function_features(binary_file_path, function_features)

    return output_file

def filter_functions(binary_functions, code_functions):
    clean_functions = FunctionFilter.clean_function_names(binary_functions)
    clean_functions = FunctionFilter.remove_fnc_c_plus(clean_functions, set(code_functions))
    clean_functions = FunctionFilter.remove_glibc(clean_functions)
    clean_functions = FunctionFilter.remove_known_fnc(clean_functions)
    return clean_functions


def build_function_features(analyzer, clean_functions):
    function_features = {
        "file": {"file_name": analyzer.file}
    }
    function_features.update({
        func['name']: analyzer.extract_function_features(func['name'], func['offset'])
        for func in clean_functions
    })
    return function_features


def save_function_features(binary_file_path, function_features):
    output_file = os.path.basename(binary_file_path) + ".json"
    tmp_folder = "./tmp"
    os.makedirs(tmp_folder, exist_ok=True)  # Ensure the folder exists
    path_json_file = os.path.join(tmp_folder, output_file)
    with open(path_json_file, 'w') as f:
        json.dump(function_features, f, indent=4)
    return path_json_file



def main():
    parser = OptionParser('Usage: python3 main.py -s <source_code_path> -b <binary_file>')
    parser.add_option('-s', '--source', dest='source_code_path', type='string', help='Source code directory')
    parser.add_option('-b', '--binary', dest='binary_file_path', type='string', help='Binary file path')
    parser.add_option('-p', '--pdb', dest='pdb', type='string', help='PDB file path')

    options, _ = parser.parse_args()

    if not options.binary_file_path:
        print(parser.usage)
        return

    if not os.path.isfile(options.binary_file_path):
        print('[X] Binary file not found')
        return

    if options.source_code_path:
        if not os.path.isdir(options.source_code_path):
            print('[X] Source code directory not found')
            return
        # File processing
        file_list = FileUtils.get_all_files(options.source_code_path)
        print(f'[+] Number of C/C++ source files found in {options.source_code_path}: {len(file_list)}')
        source_files = FileUtils.filter_code_files(file_list)
        code_functions = SourceCodeAnalyzer.extract_functions(source_files)
    else:
        code_functions = []

    output_file = analyze_binary(options.binary_file_path,options.pdb, code_functions)
    print(f"Analysis saved to {output_file}")


if __name__ == '__main__':
    main()
