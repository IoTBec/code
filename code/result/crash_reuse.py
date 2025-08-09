import json
import os
import copy
from pathlib import Path
from typing import Union, List
from rapidfuzz import fuzz
import logging

# --- Configuration ---
VENDOR = "D-Link"
SERIES = "DIR"
TARGET_PRODUCT = "DIR-619L"

# Path to the target JSON (page data)
target_file = f'./{VENDOR}/{SERIES}/{TARGET_PRODUCT}/{TARGET_PRODUCT}_page.json'

# List each database JSON with its full series/product path
database_paths = [
    f'./Tenda/AC/AC18/AC18.json',
    f'./Tenda/FH/FH1202/FH1202.json',
    f'./TOTOLINK/AR/A3700R/A3700R.json'
    f'./D-Link/DIR/DIR-816/DIR-816.json'
    f'./TP-Link/WR/WR841ND/WR841ND.json'
    # add more paths as needed
]

RESULT_DIR = "result"  # subdirectory under target folder
os.makedirs(f'./{VENDOR}/{SERIES}/{TARGET_PRODUCT}/{RESULT_DIR}', exist_ok=True)

logging.basicConfig(
    filename=f'./{VENDOR}/{SERIES}/{TARGET_PRODUCT}/{RESULT_DIR}/crash_reuse.log',
    filemode='w',         # 'w' 覆盖，'a' 追加
    encoding='gbk',       # 日志文件使用 GBK 编码
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

BASE_WEIGHTS = {
    'vendor': 0,
    'product': 0,
    'URI': 50,
    'form_parameter': 40,
    'form_format': 10,
    'button': 10,
    'navigation': 40
}
THRESHOLD = 75

# --- Helper Functions ---
def log_print(*args, **kwargs):
    message = ' '.join(str(a) for a in args)
    print(message, **kwargs)            # 控制台打印
    logging.info(message)               # 写入日志
    
def load_json(filepath: Union[str, Path]):
    """
    Load JSON from file, return None on error.
    """
    filepath = str(filepath)
    if not os.path.exists(filepath):
        log_print(f"Error: File not found -> {filepath}")
        return None
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        log_print(f"Error loading JSON {filepath}: {e}")
        return None


def calculate_weighted_similarity(item1: dict, item2: dict, weights: dict) -> float:
    """
    Compute weighted fuzzy similarity using rapidfuzz.
    """
    total_score = 0
    total_weight = 0
    for field, weight in weights.items():
        v1 = str(item1.get(field) or "")
        v2 = str(item2.get(field) or "")
        score = fuzz.ratio(v1, v2)
        total_score += score * weight
        total_weight += weight
    return total_score / total_weight if total_weight else 0

# --- Full-match Functionality ---
def match_cves_full(target_data: list, database_data: list, weights: dict, threshold: float) -> dict:
    """
    Return dict mapping URI to list of full db entries that match by weighted similarity.
    """
    per_item_matches = {}
    for target in target_data:
        uri = target.get('URI', '').strip()
        if not uri:
            per_item_matches[uri] = []
            continue
        matches = []
        for db in database_data:
            if calculate_weighted_similarity(target, db, weights) >= threshold:
                matches.append(db.copy())
        per_item_matches[uri] = matches
    return per_item_matches

# --- Simple-match & Analysis ---
def match_cves(target_data: list, database_data: list, weights: dict, threshold: float):
    """
    Return matched CVE IDs and per-item simple matches for summary.
    """
    matched_db_cves = set()
    per_item_matches = {}
    for target in target_data:
        key = target.get('URI')
        if not key:
            continue
        matches = []
        for db in database_data:
            score = calculate_weighted_similarity(target, db, weights)
            if score >= threshold:
                cve = db.get('CVE ID')
                uri = db.get('URI')
                if cve and uri:
                    matches.append({'CVE ID': cve, 'URI': uri})
                    matched_db_cves.add(cve)
        per_item_matches[key] = matches
    return matched_db_cves, per_item_matches


def analyze_reuse(database_data: list, matched_db_cves: set):
    all_db_cves = {db.get('CVE ID') for db in database_data if db.get('CVE ID')}
    unique_cve_count = len(matched_db_cves)
    total_db_cve_count = len(all_db_cves)
    proportion = unique_cve_count / total_db_cve_count * 100 if total_db_cve_count else 0
    return unique_cve_count, total_db_cve_count, proportion


def summarize(matches_set, per_match):
    unique_cve_count, db_total, proportion = analyze_reuse(database, matches_set)
    matched_targets = sum(1 for v in per_match.values() if v)
    total_hits = sum(len(v) for v in per_match.values())
    return {
        'unique_cve_count': unique_cve_count,
        'total_db_cve_count': db_total,
        'reused_proportion': proportion,
        'matched_targets': matched_targets,
        'total_hits': total_hits
    }

# --- Diff Computation ---
def compute_diffs(baseline: dict, group: dict) -> List[dict]:
    """
    Compare baseline and group matches, output only added/removed entries per URI.
    """
    diffs = []
    for uri, base_list in baseline.items():
        grp_list = group.get(uri, [])
        base_set = {json.dumps(item, sort_keys=True, ensure_ascii=False) for item in base_list}
        grp_set  = {json.dumps(item, sort_keys=True, ensure_ascii=False) for item in grp_list}
        added   = grp_set - base_set
        removed = base_set - grp_set
        if added or removed:
            diff_entry = {'URI': uri}
            if added:
                diff_entry['新增'] = [json.loads(s) for s in added]
            if removed:
                diff_entry['删除'] = [json.loads(s) for s in removed]
            diffs.append(diff_entry)
    return diffs

# --- Experiment Runner ---
def run_experiments(
    target_path: Union[str, Path],
    database_path: Union[str, Path],
    base_weights: dict,
    threshold: float
):
    global database
    target = load_json(target_path)
    database = load_json(database_path)
    if target is None or database is None:
        return {}

    summary = {}
    details = {}

    # Baseline
    matched_base, per_matches_base = match_cves(target, database, base_weights, threshold)
    summary['baseline'] = summarize(matched_base, per_matches_base)
    details['baseline'] = per_matches_base

    # Ablation groups
    groups = {
        'no_URI': ['URI'],
        'no_form': ['form_parameter', 'form_format'],
        'no_button_navigation': ['button', 'navigation']
    }
    for name, fields in groups.items():
        weights = base_weights.copy()
        for f in fields:
            weights[f] = 0
        matched_grp, per_matches_grp = match_cves(target, database, weights, threshold)
        summary[name] = summarize(matched_grp, per_matches_grp)
        diffs = compute_diffs(per_matches_base, per_matches_grp)
        details[name] = diffs

    return {'summary': summary, 'detailed_matches': details}

# --- Merge Databases ---
def merge_databases(db_paths: List[Union[str, Path]], merged_path: Union[str, Path]):
    merged = []
    for p in db_paths:
        data = load_json(p)
        if data is None:
            continue
        if isinstance(data, list):
            merged.extend(data)
        else:
            log_print(f"Warning: {p} is not a list, skipping.")
    with open(merged_path, 'w', encoding='utf-8') as f:
        json.dump(merged, f, indent=2, ensure_ascii=False)
    log_print(f"✅ Merged database saved to {merged_path}")

# --- Save Full Match Results ---
def save_all_match_results(
    target_path: Union[str, Path],
    database_path: Union[str, Path],
    base_weights: dict,
    threshold: float,
    result_dir: Union[str, Path]
) -> None:
    target_path = Path(target_path)
    database_path = Path(database_path)
    data = load_json(target_path)
    db   = load_json(database_path)

    result_path = target_path.parent / result_dir
    for f in result_path.glob('*.json'):
        try:
            f.unlink()
        except Exception as e:
            logging.error(f"删除旧 JSON 失败：{f}，原因：{e}")
    result_path.mkdir(parents=True, exist_ok=True)

    if data is None or db is None:
        return

    product = target_path.stem.split('_')[0]
    ablation_groups = {
        'no_URI': ['URI'],
        'no_form': ['form_parameter', 'form_format'],
        'no_button_navigation': ['button', 'navigation'],
    }
    weight_groups = {'baseline': BASE_WEIGHTS}
    for name, fields in ablation_groups.items():
        w = BASE_WEIGHTS.copy()
        for f in fields:
            w[f] = 0
        weight_groups[name] = w

    for group_name, weights in weight_groups.items():
        per_matches = match_cves_full(data, db, weights, threshold)
        data_copy = copy.deepcopy(data)
        for entry in data_copy:
            uri = entry.get('URI', "").strip()
            entry['match_result'] = per_matches.get(uri, [])

        out_file = result_path / (
            f"{product}.json" if group_name=='baseline' else f"{product}_{group_name}.json"
        )
        with open(out_file, 'w', encoding='utf-8') as fout:
            json.dump(data_copy, fout, indent=2, ensure_ascii=False)
        log_print(f"✅ Saved {group_name} results to {out_file}")


def add_content_field(json_file_path, output_file_path):
    # 读取 JSON 文件
    with open(json_file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # 处理单个字典或列表中的字典
    def process_entry(entry):
        if isinstance(entry, dict) and "form_parameter" in entry:
            # 构造新的有序字典插入 content 在 button 前
            new_entry = {}
            for key, value in entry.items():
                if key == "button":
                    new_entry["content"] = entry["form_parameter"]
                new_entry[key] = value
            return new_entry
        return entry

    if isinstance(data, list):
        data = [process_entry(item) for item in data]
    elif isinstance(data, dict):
        data = process_entry(data)

    # 写回 JSON 文件
    with open(output_file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=4)


# --- Main Entry ---
if __name__ == '__main__':
    try:
        script_dir = Path(__file__).parent
    except NameError:
        script_dir = Path.cwd()
    add_content_field(target_file, target_file)
    merged_db_file = script_dir / 'database.json'
    merge_databases(database_paths, merged_db_file)

    results = run_experiments(target_file, merged_db_file, BASE_WEIGHTS, THRESHOLD)
    log_print(json.dumps(results, ensure_ascii=False, indent=2))

    save_all_match_results(target_file, merged_db_file, BASE_WEIGHTS, THRESHOLD, RESULT_DIR)

