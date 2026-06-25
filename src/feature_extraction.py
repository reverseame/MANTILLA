import os
import re
import sys
import bisect
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

# Directory holding this script and its companion filter lists. Used to resolve
# the filter files regardless of the current working directory.
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))


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
        # r2_handler may be missing if r2pipe.open failed in __init__.
        handler = getattr(self, 'r2_handler', None)
        if handler is not None:
            handler.quit()

    @staticmethod
    def _func_offset(func):
        # radare2 >= 6.x renamed the aflj/afij function address field from
        # 'offset' to 'addr'. Accept either so extraction works on both.
        return func['offset'] if 'offset' in func else func['addr']

    def get_functions(self):
        func_list = json.loads(self.r2_handler.cmd('aflj'))
        imports = set(self.get_imports())
        return [
            {'name': func['name'], 'offset': self._func_offset(func)}
            for func in func_list
            if 'sym.imp.' not in func['name'] and func['name'] not in imports
        ]

    def get_imports(self):
        imports = json.loads(self.r2_handler.cmd('iij'))
        return [imp['name'] for imp in imports]

    def extract_function_features(self, function_name, offset):

        func_data = json.loads(self.r2_handler.cmd(f"s {offset}; afij"))[0]

        # Fetch the function bytes once and derive bytes/tlsh/ssdeep/entropy from
        # them, instead of running "zaf @offset; zj" four separate times.
        fnc_bytes = self._get_fnc_bytes(offset)

        features = {
            'name': function_name,
            'offset': self._func_offset(func_data),
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
            'bytes': fnc_bytes,
            'tlsh_hash_bytes': self._tlsh_from_bytes(fnc_bytes),
            'ssdeep': self._ssdeep_from_bytes(fnc_bytes),
            'entropy': self._entropy_from_bytes(fnc_bytes),
            'fnc_callgraph': self._extract_callgraph_imports(offset),
            'str': list(set(self.string_references.get(function_name, [])))
        }
        return features


    def _get_fnc_bytes(self, offset):
        """Return the hex-encoded bytes of the function at ``offset``.

        This is the single ``zaf @offset; zj`` call whose result feeds the
        bytes, TLSH, ssdeep and entropy features.
        """
        try:
            for item in json.loads(self.r2_handler.cmd(f"zaf @{offset}; zj")):
                if item['addr'] == offset:
                    return item['bytes']
            return None
        except Exception:
            return None

    def _tlsh_from_bytes(self, fnc_bytes):
        if not fnc_bytes:
            return None
        try:
            return tlsh.hash(fnc_bytes.encode())
        except Exception:
            return None

    def _ssdeep_from_bytes(self, fnc_bytes):
        if not fnc_bytes:
            return None
        try:
            return ssdeep.hash(fnc_bytes)
        except Exception:
            return None

    def _entropy_from_bytes(self, fnc_bytes):
        # -1 is a sentinel for "bytes unavailable", not a real entropy value.
        # Root cause was a radare2 bug: zaf produced no zignature at all for
        # certain fully-analyzed ARM (A32, not Thumb) functions, so no bytes
        # could be recovered. It hit ~10-20% of ARM functions and 0% of
        # x86/x86-64/mips, so the sentinel correlates with the ARM architecture
        # -- an extraction artifact, not signal. Fixed upstream in radare2 6.x
        # (radareorg/radare2#26140), so the -1 values only exist in the
        # features_model.csv generated with an older radare2; current radare2
        # no longer produces them.
        # Measured harmless on the existing model: the affected rows collapse to
        # ~15 unique vectors under drop_duplicates() at training time, and
        # 5-fold CV accuracy is identical whether -1 is kept or imputed to the
        # median. Kept as -1 for compatibility with that CSV. Beware before
        # standardizing features: that would give this artifact real weight.
        if not fnc_bytes:
            return -1
        try:
            return EntropyCalculator.calculate_entropy(binascii.unhexlify(fnc_bytes))
        except Exception:
            return -1


    def _extract_opcodes(self, offset_func):
        try:
            ops = json.loads(self.r2_handler.cmd(f"s {offset_func}; pdfj"))
            return [op['opcode'].split(' ')[0] for op in ops['ops'] if 'opcode' in op]
        except Exception:
            return []

    def _extract_callgraph_imports(self, offset):
        try:
            graph = json.loads(self.r2_handler.cmd(f'agcj {offset}'))
            return graph[0]['imports'] if graph else []
        except Exception:
            return []

    def _safe_json(self, cmd, default):
        # Some radare2 commands/versions return an empty (non-JSON) string;
        # string-reference extraction is best-effort metadata, so degrade
        # gracefully instead of crashing the whole analysis.
        try:
            return json.loads(self.r2_handler.cmd(cmd))
        except (ValueError, TypeError):
            return default

    def _extract_string_references(self):
        """Map each function name to the strings it references.

        Instead of issuing one ``axt`` per string (O(number of strings) r2
        commands), this fetches the string list, the function list and the
        whole cross-reference list once each, and resolves the owning function
        of every string reference locally via binary search over the function
        ranges.
        """
        strings = {s['vaddr']: s['string'] for s in self._safe_json("izj", [])}
        if not strings:
            return {}

        functions = self._safe_json("aflj", [])
        functions.sort(key=self._func_offset)
        starts = [self._func_offset(f) for f in functions]

        def function_at(address):
            idx = bisect.bisect_right(starts, address) - 1
            if idx < 0:
                return None
            func = functions[idx]
            if address < self._func_offset(func) + func.get('size', 0):
                return func['name']
            return None

        references = {}
        for xref in self._safe_json("axlj", []):
            target, source = xref.get('addr'), xref.get('from')
            if source is None or target not in strings:
                continue
            name = function_at(source)
            if name:
                references.setdefault(name, []).append(strings[target])
        return references



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
        # Drop functions whose name matches a source-code function exactly,
        # keeping 'main'. Matching by substring (the previous behavior) wrongly
        # removed unrelated functions, e.g. 'address_of' for a source 'add'.
        code_functions = set(code_functions) - {'main'}
        return [item for item in clean_names if item['name'] not in code_functions]


    @staticmethod
    def remove_glibc(clean_names):
        # Define the glibc files to check (resolved relative to this script)
        glibc_files = ["glibc_32.txt", "glibc_functions.txt", "uclibc_functions.txt", "musl_functions.txt"]

        # Load all glibc names into a set
        glibc_names = set()
        for file in glibc_files:
            path = os.path.join(_BASE_DIR, file)
            if os.path.exists(path):
                with open(path, "r") as f:
                    glibc_names.update(f.read().splitlines())
            else:
                print(f"[!] WARNING: libc filter list not found: {path} -- "
                      "standard libc functions will NOT be filtered out, degrading results.",
                      file=sys.stderr)

        # Filter clean_names, keeping only those whose 'name' is not in glibc_names
        return [item for item in clean_names if item['name'] not in glibc_names]

    @staticmethod
    def remove_known_fnc(clean_names):
        # File containing known function names (resolved relative to this script)
        known_functions_file = os.path.join(_BASE_DIR, "List_total_functions_uniq_clean.txt")

        # Load known function names into a set
        known_fnc_list = set()
        if os.path.exists(known_functions_file):
            with open(known_functions_file, "r") as f:
                known_fnc_list.update(f.read().splitlines())
        else:
            print(f"[!] WARNING: known-functions list not found: {known_functions_file} -- "
                  "known functions will NOT be filtered out, degrading results.",
                  file=sys.stderr)

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
