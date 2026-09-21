import os
import sys
import csv
import json
import subprocess

def identify_microarch():
    """Detect local system CPU Family and Model, returning the mapfile key string."""
    try:
        output = subprocess.check_output("lscpu", text=True)
        family, model = None, None
        for line in output.splitlines():
            if "CPU family:" in line:
                family = line.split(":")[-1].strip()
            elif "Model:" in line:
                model = int(line.split(":")[-1].strip())
        if family and model is not None:
            return f"GenuineIntel-{family}-{model:02X}"
    except Exception as e:
        print(f"[-] Error executing lscpu detection: {e}")
        sys.exit(1)
    return None

def find_json(repo_path, cpu_id):
    """Scan mapfile.csv to pull file paths linked to the target CPU signature."""
    mapfile_path = os.path.join(repo_path, "mapfile.csv")
    if not os.path.exists(mapfile_path):
        print(f"[-] Error: mapfile.csv not found at {repo_path}")
        sys.exit(1)
    
    paths = []
    with open(mapfile_path, "r") as f:
        reader = csv.reader(f)
        next(reader)  # Skip CSV header
        for row in reader:
            if row and row[0].strip() == cpu_id:
                file_path = row[2]
                if "/metrics/" in file_path.lower():
                    continue
                paths.append(os.path.join(repo_path, file_path.lstrip('/')))
    return paths

def lookup_events(json_paths):
    """Injest uniform JSON structures into an optimized uppercase matching dictionary."""
    database = {}
    for path in json_paths:
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r") as f:
                data = json.load(f)
                events_list = data.get("Events", [])
                
                for event in events_list:
                    raw_name = event.get("EventName")
                    if raw_name:
                        name_upper = raw_name.upper()
                        # Map base attributes
                        ev_data = {
                            "EventCode": event.get("EventCode"),
                            "UMask": event.get("UMask"),
                            "Counter": event.get("Counter", "")
                        }
                        # ~ database[name_upper] = ev_data
                        database[raw_name] = ev_data
                        
                        # ~ # Strip core tags (_PS, _P, _M) for simplified target matching
                        # ~ for suffix in ["_PS", "_P", "_M"]:
                            # ~ if name_upper.endswith(suffix):
                                # ~ normalized = name_upper[:-len(suffix)]
                                # ~ if normalized not in database:
                                    # ~ database[normalized] = ev_data
        except Exception:
            continue
            
    # Inject reliable fallback hardware defaults for fixed architectural registers if omitted
    # ~ if "INST_RETIRED.ANY" not in database:
        # ~ database["INST_RETIRED.ANY"] = {"EventCode": "0x00", "UMask": "0x01", "Counter": "Fixed"}
    # ~ if "CPU_CLK_UNHALTED.THREAD" not in database:
        # ~ database["CPU_CLK_UNHALTED.THREAD"] = {"EventCode": "0x00", "UMask": "0x02", "Counter": "Fixed"}
        
    return database


def build_output_csv(target_events, event_db, output_filename="event_encodings.csv"):
    """Generates the clean final CSV file with all requested hardware properties."""
    headers = ["index", "event_name", "event_number", "umask", "mode", "sample_period", "type", "role", "status"]
    
    print(f"[*] Compiling encoding layouts into '{output_filename}'...")
    
    with open(output_filename, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(headers)  # Write header labels
        
        for idx, name in enumerate(target_events):
            name_clean = name.strip()
            if not name_clean:
                continue
                
            # Default properties fallback configuration
            event_number = "0x00"
            umask = "0x00"
            mode = "counting"
            sample_period = "0"
            counter_type = "raw"
            role = "member"
            
            # Context-specific logic rules for the Group Encodings layout:
            if idx == 0:
                mode = "sampling"
                sample_period = "1000"
                role = "leader"
                
            # Query the cross-referenced internal database
            # ~ repo_match = event_db.get(name_clean.upper())
            repo_match = event_db.get(name_clean)
            status = "FOUND" #default, change to NOT_FOUND if not found
            if repo_match:
                event_number = repo_match["EventCode"]
                umask = repo_match["UMask"]
                
                # Auto-detect if event belongs to native fixed counters
                counter_str = str(repo_match["Counter"]).lower()
                if "fixed" in counter_str:
                    counter_type = "fixed"
            else:
                # Soft fallback default exceptions for the two fundamental items
                # ~ if "INST_RETIRED.ANY" in name_clean.upper():
                    # ~ event_number, umask, counter_type = "0x00", "0x01", "fixed"
                # ~ elif "CPU_CLK_UNHALTED.THREAD" in name_clean.upper():
                    # ~ event_number, umask, counter_type = "0x00", "0x02", "fixed"
                # ~ else:
                print(f" Warning: Event '{name_clean}' not found in architecture maps. Using defaults.")
                status = "NOT_FOUND"
            
            # Edge-case formatting overrides to keep hexadecimal strings uniform (lowercase zero-padded strings)
            if event_number.startswith("0x") and len(event_number) == 3:
                event_number = f"0x0{event_number[2].upper()}"
            if umask.startswith("0x") and len(umask) == 3:
                umask = f"0x0{umask[2].upper()}"
                
            writer.writerow([idx, name_clean, event_number.upper(), umask.upper(), mode, sample_period, counter_type, role, status])
            
    print(f"[+] Successfully exported {len(target_events)} validated profile items.")

if __name__ == "__main__":
    REPO_DIR = "./perfmon"
    OUTPUT_CSV = "event_encodings.csv"
    
    # List of input events
    input_event_list = [
        "INST_RETIRED.ANY", "BR_MISP_RETIRED.ALL_BRANCHES", "BR_MISP_RETIRED.CONDITIONAL",
        "BR_MISP_RETIRED.NEAR_CALL", "BR_MISP_RETIRED.NEAR_TAKEN", "BR_INST_RETIRED.ALL_BRANCHES",
        "BR_INST_RETIRED.COND_NTAKEN", "BR_INST_RETIRED.CONDITIONAL", "BR_INST_RETIRED.FAR_BRANCH",
        "BR_INST_RETIRED.NEAR_CALL", "BR_INST_RETIRED.NEAR_RETURN", "BR_INST_RETIRED.NEAR_TAKEN",
        "BR_INST_RETIRED.NOT_TAKEN", "BR_MISP_EXEC.ALL_BRANCHES", "BR_MISP_EXEC.INDIRECT",
        "MEM_LOAD_RETIRED.FB_HIT", "MEM_LOAD_RETIRED.L1_MISS", "MEM_LOAD_RETIRED.L1_HIT",
        "MEM_LOAD_RETIRED.L2_HIT", "MEM_LOAD_RETIRED.L2_MISS", "MEM_LOAD_RETIRED.L3_HIT",
        "MEM_LOAD_RETIRED.L3_MISS", "MEM_INST_RETIRED.ALL_LOADS", "MEM_INST_RETIRED.ALL_STORES",
        "MEM_INST_RETIRED.ANY", "MEM_INST_RETIRED.STLB_MISS_LOADS", "MEM_INST_RETIRED.STLB_MISS_STORES",
        "DTLB_LOAD_MISSES.MISS_CAUSES_A_WALK", "DTLB_LOAD_MISSES.STLB_HIT", "DTLB_LOAD_MISSES.WALK_COMPLETED",
        "DTLB_STORE_MISSES.STLB_HIT", "DTLB_STORE_MISSES.WALK_COMPLETED", "ITLB_MISSES.MISS_CAUSES_A_WALK",
        "ITLB_MISSES.STLB_HIT", "ITLB_MISSES.WALK_COMPLETED", "L2_RQSTS.CODE_RD_HIT",
        "L2_RQSTS.CODE_RD_MISS", "ICACHE_64B.IFTAG_HIT", "ICACHE_64B.IFTAG_MISS",
        "CPU_CLK_UNHALTED.THREAD"
    ]
    
    # 1. Resolve host signature
    target_cpu = identify_microarch()
    print(f"[+] Auto-detected CPU Signature: {target_cpu}")
    
    # 2. Extract JSON mapping folders
    matched_files = find_json(REPO_DIR, target_cpu)
    print(f"[+] Mapping files: {[os.path.basename(p) for p in matched_files]}")
    
    # 3. Read repository coordinates
    event_database = lookup_events(matched_files)
    
    #print the db generated for debug
    # ~ print(json.dumps(event_database, indent=4))
    
    # 4. Generate output file
    build_output_csv(input_event_list, event_database, OUTPUT_CSV)
