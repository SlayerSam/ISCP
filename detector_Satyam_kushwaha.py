import sys, csv, json, re, os, ipaddress

PAT_PHONE = re.compile(r'(?<!\d)([6-9]\d{9})(?!\d)')
PAT_AADHAR = re.compile(r'(?<!\d)(\d{4}\s?\d{4}\s?\d{4})(?!\d)')
PAT_PASSPORT = re.compile(r'\b([A-Z][0-9]{7})\b', re.I)
PAT_UPI = re.compile(r'\b([a-z0-9][a-z0-9._-]{1,30})@([a-z][a-z0-9]{1,15})\b', re.I)
PAT_EMAIL = re.compile(r'\b([a-z0-9._%+-]{1,64})@([a-z0-9.-]{1,253}\.[a-z]{2,})\b', re.I)
PAT_IP = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


def mask_phone(x):
    return x[:2] + "XXXXXX" + x[-2:] if len(x) == 10 else "[REDACTED]"

def mask_aadhar(x):
    d = re.sub(r'\D', '', x)
    return "XXXX XXXX " + d[-4:] if len(d) == 12 else "[REDACTED]"

def mask_passport(x):
    return x[0] + "XXXXX" + x[-2:] if PAT_PASSPORT.fullmatch(x) else "[REDACTED]"

def mask_upi(local, dom):
    return local[:2] + "XXX@" + dom

def mask_email(local, dom):
    return local[:2] + "XXX@" + dom

def mask_ip(x):
    try:
        ipaddress.IPv4Address(x)
        seg = x.split(".")
        return ".".join(seg[:2] + ["xx", "xx"])   
    except:
        return "[REDACTED]"


def clean_value(k, v):
    if not isinstance(v, str):
        return v, False
    found, raw = False, v

    def sub_phone(m): 
        nonlocal found; found=True
        return mask_phone(m.group(1))
    v = PAT_PHONE.sub(sub_phone, v)

    def sub_aad(m): 
        nonlocal found; found=True
        return mask_aadhar(m.group(1))
    v = PAT_AADHAR.sub(sub_aad, v)

    def sub_pass(m): 
        nonlocal found; found=True
        return mask_passport(m.group(1))
    v = PAT_PASSPORT.sub(sub_pass, v)

    def sub_upi(m): 
        nonlocal found; found=True
        return mask_upi(m.group(1), m.group(2))
    v = PAT_UPI.sub(sub_upi, v)

    def sub_mail(m): 
        nonlocal found; found=True
        return mask_email(m.group(1), m.group(2))
    v = PAT_EMAIL.sub(sub_mail, v)

    def sub_ip(m): 
        nonlocal found; found=True
        return mask_ip(m.group(0))
    v = PAT_IP.sub(sub_ip, v)

    return v, found


def to_json(s):
    try:
        return json.loads(s)
    except:
        return {}


def handle_record(d):
    red, anypii = {}, False
    for k, v in d.items():
        newv, f = clean_value(k, v)
        red[k] = newv
        if f: anypii = True
    return red, anypii


def main():
    if len(sys.argv) < 2:
        print("Usage: python script.py <input.csv>")
        sys.exit(1)

    infile = sys.argv[1]
    outfile = os.path.splitext(infile)[0] + "_redacted.csv"

    with open(infile, "r", encoding="utf-8") as fin, open(outfile, "w", encoding="utf-8", newline="") as fout:
        rdr = csv.DictReader(fin)
        wr = csv.DictWriter(fout, fieldnames=["record_id", "redacted_data_json", "is_pii"])
        wr.writeheader()
        for row in rdr:
            rid = row.get("record_id") or row.get("id") or ""
            raw = row.get("data_json") or "{}"
            obj = to_json(raw)
            red, pii = handle_record(obj)
            wr.writerow({
                "record_id": rid,
                "redacted_data_json": json.dumps(red, ensure_ascii=False),
                "is_pii": str(pii)
            })

    print("Output written to", outfile)


if __name__ == "__main__":
    main()
