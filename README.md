# IoTBec

## IoTBec Workflow

![image-20250809164749643](https://raw.githubusercontent.com/abcdefg-png/images2/main/image-20250809164749643.png)

[Code](#Code)

- [Ground Truth Database](#Ground Truth Database)
- [Test product](#Test product)

[Signature](#Signature)

- [Vulnerability Signature](#Vulnerability Signature)
- [Interface Signature](#Interface Signature)
- [Vulnerability Interface Signature](#Vulnerability Interface Signature)

[Match](#Match)

## Code

```bash
python spider/spider_get_vendor_cve.py # crawl the corresponding vendor's CVEs and save them to the results/{Vendor}
```

### Ground Truth Database

```bash
python spider/cve_filter_by_product.py # filter the CVEs of base product and save as result/{Vendor}/{Series}/{product}/{product}_{Vendor}_cve.csv

python cve_summary_by_llm.py # Using the Vulnerability Analyzer LLM to generate json-format Vulnerability Signatures，save as result/{Vendor}/{Series}/{product}/{product}_CVE.json

# Generate Interface Signature and save as result/{Vendor}/{Series}/{product}/{product}_page.json

python result/merge_page_and_CVE_for_db.py # {product}_page.json ∪ {product}_CVE.json
```

### Test product

```bash
# Generate Interface Signature and save as result/{Vendor}/{Series}/{product}/{product}_page.json

python result/crash_reuse.py

# 生成result/{Vendor}/{Series}/{product}/result/*.json
python result/generate_poc_by_llm.py

# result/{Vendor}/{Series}/{product}/result/{product}.json
python result/exec_poc.py
```

## Signature

### Vulnerability Signature

![image-20250809164909979](https://raw.githubusercontent.com/abcdefg-png/images2/main/image-20250809164909979.png)

```json
// demo
[
  {
    "CVE ID": "CVE-2024-33180",
    "vendor": "Tenda",
    "product": "AC18",
    "vul_type": "Overflow",
    "URI": "/goform/saveParentControlInfo",
    "parameter or argument": "deviceId",
  }
]
```

### Interface Signature

![image-20250809164936560](https://raw.githubusercontent.com/abcdefg-png/images2/main/image-20250809164936560.png)

```json
// demo
[
  {
    "vendor": "Tenda",
    "product": "AC18",
    "URI": "/goform/saveParentControlInfo",
    "form_parameter": "['deviceId', 'enable', 'time', 'url_enable', 'urls', 'day', 'limit_type']",
    "form_format": "key-value",
    "button": "Save",
    "navigation": "Parental Control->Parental Control"
  }
]
```

### Vulnerability Interface Signature

```json
// demo
[
  {
    "CVE ID": "CVE-2024-33180",
    "vendor": "Tenda",
    "product": "AC18",
    "URI": "/goform/saveParentControlInfo",
    "form_parameter": "['deviceId', 'enable', 'time', 'url_enable', 'urls', 'day', 'limit_type']",
    "form_format": "key-value",
    "button": "Save",
    "navigation": "Parental Control->Parental Control",
    "vul_type": "Overflow",
    "parameter or argument": "deviceId",
  }
]
```

### Match

```json
// demo
[
  {
    "vendor": "Tenda",
    "product": "AC5",
    "URI": "/goform/saveParentControlInfo",
    "form_parameter": "['deviceId', 'deviceName', 'enable', 'time', 'url_enable', 'urls', 'day', 'limit_type']",
    "form_format": "key-value",
    "button": "Save",
    "navigation": "Parental Control->Parental Control",
    "match_result": [
      {
        "CVE ID": "CVE-2024-33180",
        "vendor": "Tenda",
        "product": "AC18",
        "URI": "/goform/saveParentControlInfo",
        "form_parameter": "['deviceId', 'enable', 'time', 'url_enable', 'urls', 'day', 'limit_type']",
        "form_format": "key-value",
        "button": "Save",
        "navigation": "Parental Control->Parental Control",
        "vul_type": "Overflow",
        "function name": "",
        "parameter or argument": "deviceId",
      }
    ]
  }
]
```

### 
