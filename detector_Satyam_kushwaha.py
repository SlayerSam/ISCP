import sys, csv, json, re, ast, os, ipaddress

RE_TEN_DIGIT_PHONE = re.compile(r'(?<!\d)([6-9]\d{9})(?!\d)')  
RE_AADHAR = re.compile(r'(?<!\d)(\d{4}\s?\d{4}\s?\d{4})(?!\d)')
RE_PASSPORT = re.compile(r'(?i)\b([A-Z][0-9]{7})\b') 
RE_UPI = re.compile(r'\b([a-z0-9][a-z0-9._-]{1,30})@([a-z][a-z0-9]{1,15})\b', re.I)
RE_EMAIL = re.compile(r'\b([a-z0-9._%+-]{1,64})@([a-z0-9.-]{1,253}\.[a-z]{2,})\b', re.I)
RE_IPV4 = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
RE_NAME_WORD = re.compile(r'^[A-Za-z]+(?:\s+[A-Za-z]+)+$')  

def mask_phone(s):
    return s[:2] + 'XXXXXX' + s[-2:] if len(s) == 10 else '[REDACTED_PII]'

def mask_aadhar(s):
    digits = re.sub(r'\D', '', s)
    if len(digits) == 12:
        return 'XXXX XXXX ' + digits[-4:]
    return '[REDACTED_PII]'

def mask_passport(s):
    if re.fullmatch(RE_PASSPORT, s):
        return s[0] + 'XXXXX' + s[-2:]
    return '[REDACTED_PII]'

def mask_upi(local, domain):
    keep = min(2, len(local))
    return local[:keep] + 'XXX@' + domain

def mask_email(local, domain):
    keep = min(2, len(local))
    return local[:keep] + 'XXX@' + domain

def mask_name(fullname):
    parts = [p for p in fullname.split() if p]
    masked_parts = []
    for p in parts:
        if len(p) <= 2:
            masked_parts.append(p[0] + 'X'*(len(p)-1))
        else:
            masked_parts.append(p[0] + 'X'*(len(p)-1))
    return ' '.join(masked_parts)

def mask_ipv4(ip):
    try:
        ipaddress.IPv4Address(ip)
        octets = ip.split('.')
        return '.'.join(octets[:2] + ['x','x'])
    except Exception:
        return '[REDACTED_PII]'

def redact_value(key, val):
    found = False
    if isinstance(val, str):
        original = val

        def _phone_sub(m):
            nonlocal found
            found = True
            return mask_phone(m.group(1))
        val = RE_TEN_DIGIT_PHONE.sub(_phone_sub, val)

        def _aad_sub(m):
            nonlocal found
            found = True
            return mask_aadhar(m.group(1))
        val = RE_AADHAR.sub(_aad_sub, val)

        def _pp_sub(m):
            nonlocal found
            found = True
            return mask_passport(m.group(1))
        val = RE_PASSPORT.sub(_pp_sub, val)

        def _upi_sub(m):
            nonlocal found
            found = True
            return mask_upi(m.group(1), m.group(2))
        val = RE_UPI.sub(_upi_sub, val)

        def _email_sub(m):
            nonlocal found
            found = True  
            return mask_email(m.group(1), m.group(2))
        val = RE_EMAIL.sub(_email_sub, val)

        def _ip_sub(m):
            nonlocal found
            found = True
            return mask_ipv4(m.group(0))
        val = RE_IPV4.sub(_ip_sub, val)

        if key.lower() == 'name' and RE_NAME_WORD.match(original.strip()):
            found = True
            val = mask_name(original.strip())

        if key.lower() in {'address', 'address_proof'}:
            if original.strip():
                found = True
                val = '[REDACTED_PII]'

        if key.lower() in {'device_id'} and original.strip():
            found = True
            if len(original) > 4:
                val = original[:-4] + 'XXXX'
            else:
                val = '[REDACTED_PII]'

    return val, found

def parse_json_str(s):
    try:
        return json.loads(s)
    except Exception:
        try:
            return ast.literal_eval(s)
        except Exception:
            try:
                fixed = s.replace("'", '"')
                return json.loads(fixed)
            except Exception:
                return {}

def is_full_name(value):
    return isinstance(value, str) and RE_NAME_WORD.match(value.strip()) is not None

def detect_combinatorial_flags(obj):
    name_present = (
        ('name' in obj and is_full_name(str(obj.get('name')))) or
        (obj.get('first_name') and obj.get('last_name'))
    )
    email_val = str(obj.get('email', '') or '')
    email_present = bool(RE_EMAIL.search(email_val))
    address_val = str(obj.get('address', '') or '')
    pin_code_val = str(obj.get('pin_code', '') or '')
    city_val = str(obj.get('city', '') or '')
    state_val = str(obj.get('state', '') or '')
    physical_address_present = (
        (len(address_val.strip()) > 0) or
        ((city_val.strip() or state_val.strip()) and pin_code_val.strip())
    )
    device_or_ip_present = bool(obj.get('device_id')) or bool(RE_IPV4.search(str(obj.get('ip_address', '') or '')))
    return {
        'name_present': name_present,
        'email_present': email_present,
        'physical_address_present': physical_address_present,
        'device_or_ip_present': device_or_ip_present,
    }

def detect_standalone_pii(obj):
    text_blobs = []
    for k, v in obj.items():
        if v is None: 
            continue
        if isinstance(v, str):
            text_blobs.append(v)
        elif isinstance(v, (int, float)):
            text_blobs.append(str(v))
    blob = ' | '.join(text_blobs)
    if RE_TEN_DIGIT_PHONE.search(blob):
        return True
    if RE_AADHAR.search(blob):
        return True
    if RE_PASSPORT.search(blob):
        return True
    if RE_UPI.search(blob):
        return True
    return False

def process_record(obj):
    redacted = {}
    pii_found_any = False
    for k, v in obj.items():
        rv, found = redact_value(k, v)
        redacted[k] = rv
        pii_found_any = pii_found_any or found
    standalone = detect_standalone_pii(obj)
    flags = detect_combinatorial_flags(obj)
    combo_count = sum(1 for x in flags.values() if x)
    combinatorial = combo_count >= 2
    is_pii = standalone or combinatorial
    if not standalone and combo_count < 2:
        is_pii = False
    return redacted, is_pii

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 detector_Satyam_Kushwaha.py <input_csv_path>")
        sys.exit(1)
    in_path = sys.argv[1]
    out_path = os.path.join(os.path.dirname(in_path) or ".", "redacted_output_Satyam_Kushwaha.csv")
    with open(in_path, 'r', encoding='utf-8') as f_in, open(out_path, 'w', encoding='utf-8', newline='') as f_out:
        reader = csv.DictReader(f_in)
        fieldnames = ['record_id', 'redacted_data_json', 'is_pii']
        writer = csv.DictWriter(f_out, fieldnames=fieldnames)
        writer.writeheader()
        for row in reader:
            record_id = row.get('record_id') or row.get('id') or ''
            data_json_raw = row.get('Data_json') or row.get('data_json') or '{}'
            obj = parse_json_str(data_json_raw)
            redacted_obj, is_pii = process_record(obj)
            writer.writerow({
                'record_id': record_id,
                'redacted_data_json': json.dumps(redacted_obj, ensure_ascii=False),
                'is_pii': str(bool(is_pii))
            })
    print(out_path)

if __name__ == "__main__":
    main()
