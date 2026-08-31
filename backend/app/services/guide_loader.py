import os
import random
import logging
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from app.db.models import Alert, Incident
from app.config import settings

logger = logging.getLogger(__name__)

# Expected Microsoft GUIDE benchmark columns
GUIDE_COLUMNS = [
    "OrgId", "IncidentId", "AlertId", "Timestamp", "DetectorId",
    "AlertTitle", "Category", "MitreTechniques", "Severity",
    "IncidentGrade", "ActionGrouped", "DeviceId", "AccountUpn",
    "IpAddress", "Sha256", "Url"
]

def clean_and_impute_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """
    Cleans high-null columns (>40% nulls) and prepares the dataset.
    """
    total_rows = len(df)
    for col in df.columns:
        null_count = df[col].isnull().sum()
        null_pct = null_count / total_rows if total_rows > 0 else 0
        if null_pct > 0.40:
            logger.info(f"Column '{col}' has {null_pct:.1%} nulls (>40%). Applying graceful imputation.")
            if df[col].dtype == 'object' or pd.api.types.is_string_dtype(df[col]):
                df[col] = df[col].fillna("N/A")
            else:
                df[col] = df[col].fillna(0)
        else:
            if df[col].dtype == 'object' or pd.api.types.is_string_dtype(df[col]):
                df[col] = df[col].fillna("Unknown")
            else:
                df[col] = df[col].fillna(0)
    return df

def generate_synthetic_guide_dataset(num_alerts: int = 125) -> pd.DataFrame:
    """
    Generates a 120+ row high-fidelity dataset strictly conforming to the Microsoft GUIDE schema.
    Includes multi-alert incident stories with ground-truth grades.
    """
    base_time = datetime.utcnow() - timedelta(hours=36)
    
    incident_templates = [
        {
            "id": "INC-1001",
            "name": "Multi-Stage Ransomware & Shadow Copy Deletion",
            "grade": "TruePositive",
            "category": "Ransomware",
            "devices": ["DEV-FIN-01", "DEV-FIN-02", "DEV-SRV-BACKUP"],
            "accounts": ["corp\\alice.smith", "corp\\finance_svc", "corp\\backup_admin"],
            "ips": ["192.168.10.45", "192.168.10.46", "185.220.101.42"],
            "sha256": "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
            "url": "http://malicious-doc-share.ru/invoice.docm",
            "alerts": [
                ("Malicious Office Macro Executed", "InitialAccess", "T1566.001", "High", "Blocked", 0),
                ("PowerShell Obfuscated Script Execution", "Execution", "T1059.001", "High", "Detected", 15),
                ("Volume Shadow Copies Deleted via vssadmin", "Impact", "T1490", "Critical", "Detected", 35),
                ("High Volume of File Renaming to .locked", "Impact", "T1486", "Critical", "Detected", 50),
                ("Outbound C2 Communication to Suspect IP", "CommandAndControl", "T1071.001", "High", "Blocked", 65),
                ("Lateral SMB File Copy to Backup Server", "LateralMovement", "T1021.002", "Critical", "Detected", 80)
            ]
        },
        {
            "id": "INC-1002",
            "name": "Mimikatz Credential Dumping & Domain Controller Lateral Movement",
            "grade": "TruePositive",
            "category": "CredentialAccess",
            "devices": ["DEV-ENG-08", "DEV-DC-01"],
            "accounts": ["corp\\dev_lead", "corp\\domain_admin"],
            "ips": ["192.168.20.108", "10.0.0.1"],
            "sha256": "8c42b0c3679c2ef3bf3589b3f6e1f0e21074e2d3b4f9f743ab98d89a26315efb",
            "url": "N/A",
            "alerts": [
                ("LSASS Process Memory Access / MiniDump", "CredentialAccess", "T1003.001", "Critical", "Detected", 10),
                ("Pass-the-Hash NTLM Relay Detected", "LateralMovement", "T1550.002", "High", "Detected", 25),
                ("Remote PowerShell Session to Domain Controller", "Execution", "T1021.006", "High", "Detected", 45),
                ("Suspicious Group Policy Object Modification", "Persistence", "T1484.001", "Critical", "Detected", 90),
                ("Golden Ticket Kerberos Activity", "PrivilegeEscalation", "T1558.001", "Critical", "Detected", 120)
            ]
        },
        {
            "id": "INC-1003",
            "name": "Cloud Identity Compromise & Token Exfiltration",
            "grade": "TruePositive",
            "category": "CloudCompromise",
            "devices": ["DEV-MKT-03"],
            "accounts": ["corp\\sarah.connor@acme.com"],
            "ips": ["194.26.29.112", "192.168.30.15"],
            "sha256": "N/A",
            "url": "https://graph.microsoft.com/v1.0/me/messages",
            "alerts": [
                ("Impossible Travel Anomaly (Tokyo to London in 10m)", "InitialAccess", "T1078.004", "High", "Detected", 5),
                ("MFA Fatigue Push Notification Spam Accepted", "CredentialAccess", "T1621", "High", "Detected", 12),
                ("Suspicious OAuth Application Registered", "Persistence", "T1528", "Medium", "Allowed", 30),
                ("Mass Mailbox Data Export via Graph API", "Exfiltration", "T1530", "High", "Detected", 55)
            ]
        },
        {
            "id": "INC-1004",
            "name": "Routine IT Admin Vulnerability Scan",
            "grade": "BenignPositive",
            "category": "Discovery",
            "devices": ["DEV-MGMT-01", "DEV-MGMT-02"],
            "accounts": ["corp\\net_admin", "corp\\sec_ops"],
            "ips": ["10.0.0.254", "10.0.0.253"],
            "sha256": "N/A",
            "url": "N/A",
            "alerts": [
                ("High Volume TCP Port Scan Detected (Nmap)", "Discovery", "T1046", "Low", "Allowed", 0),
                ("Automated SSH Banner Grabbing", "Discovery", "T1046", "Low", "Allowed", 10),
                ("SNMP Community String Enumeration", "Discovery", "T1046", "Informational", "Allowed", 20),
                ("Simulated SMB Auth Checks (Nessus Scanner)", "Discovery", "T1110.001", "Low", "Allowed", 30)
            ]
        },
        {
            "id": "INC-1005",
            "name": "Web Application Firewall Scanner False Positive",
            "grade": "FalsePositive",
            "category": "WebAttack",
            "devices": ["SRV-WEB-01", "SRV-WEB-02"],
            "accounts": ["svc_web_iis"],
            "ips": ["203.0.113.19", "203.0.113.88"],
            "sha256": "N/A",
            "url": "https://portal.acme.com/api/search?q=SQL+UNION+SELECT",
            "alerts": [
                ("SQL Injection Syntax in Query Parameter", "InitialAccess", "T1190", "Medium", "Blocked", 0),
                ("Cross-Site Scripting Pattern Detected", "InitialAccess", "T1059.007", "Low", "Blocked", 5),
                ("Directory Traversal Attempt (../etc/passwd)", "InitialAccess", "T1190", "Low", "Blocked", 15)
            ]
        },
        {
            "id": "INC-1006",
            "name": "Monday Morning Password Reset Lockouts",
            "grade": "FalsePositive",
            "category": "AccountActivity",
            "devices": ["DEV-CORP-W10-01", "DEV-CORP-W10-02", "DEV-CORP-W10-03"],
            "accounts": ["corp\\bob.d", "corp\\carol.w", "corp\\dave.m"],
            "ips": ["192.168.40.11", "192.168.40.12", "192.168.40.13"],
            "sha256": "N/A",
            "url": "N/A",
            "alerts": [
                ("Multiple Failed Domain Logon Attempts", "CredentialAccess", "T1110.001", "Low", "Detected", 0),
                ("Account Locked Out Due to Bad Passwords", "AccountActivity", "T1110.001", "Informational", "Detected", 2),
                ("Kerberos Pre-Authentication Failure Spike", "CredentialAccess", "T1110.001", "Low", "Detected", 5)
            ]
        },
        {
            "id": "INC-1007",
            "name": "Supply Chain DLL Hijack & Data Exfiltration",
            "grade": "TruePositive",
            "category": "SupplyChain",
            "devices": ["DEV-OPS-04", "BUILD-SRV-01"],
            "accounts": ["corp\\deploy_bot", "corp\\jenkins_svc"],
            "ips": ["192.168.50.20", "45.33.32.156"],
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "url": "https://update-packages.globalcdn-delivery.net/payload.bin",
            "alerts": [
                ("Suspicious DLL Loaded by Signed Executable", "DefenseEvasion", "T1574.002", "Critical", "Detected", 0),
                ("Hidden Scheduled Task Registered in Registry", "Persistence", "T1053.005", "High", "Detected", 20),
                ("Archive File Created in Temp Directory", "Collection", "T1560.001", "Medium", "Detected", 40),
                ("Encrypted TLS Traffic to Uncategorized IP", "Exfiltration", "T1048.003", "Critical", "Detected", 60)
            ]
        }
    ]

    records = []
    alert_counter = 10001
    
    for tpl in incident_templates:
        inc_id = tpl["id"]
        grade = tpl["grade"]
        dev_list = tpl["devices"]
        acc_list = tpl["accounts"]
        ip_list = tpl["ips"]
        sha = tpl["sha256"]
        url = tpl["url"]
        
        for (title, cat, mitre, sev, action, offset_min) in tpl["alerts"]:
            alert_time = base_time + timedelta(minutes=offset_min + random.randint(0, 5))
            records.append({
                "OrgId": "ORG-CORP-01",
                "IncidentId": inc_id,
                "AlertId": f"ALT-{alert_counter}",
                "Timestamp": alert_time.strftime("%Y-%m-%d %H:%M:%S"),
                "DetectorId": f"DET-{random.randint(100, 999)}",
                "AlertTitle": title,
                "Category": cat,
                "MitreTechniques": mitre,
                "Severity": sev,
                "IncidentGrade": grade,
                "ActionGrouped": action,
                "DeviceId": random.choice(dev_list),
                "AccountUpn": random.choice(acc_list),
                "IpAddress": random.choice(ip_list),
                "Sha256": sha,
                "Url": url
            })
            alert_counter += 1

    noise_titles = [
        ("Antivirus Signature Update Completed", "System", "N/A", "Informational", "Allowed"),
        ("Certificate Near Expiration (Internal Root CA)", "System", "N/A", "Low", "Allowed"),
        ("Minor DNS Resolution Timeout", "Network", "N/A", "Informational", "Allowed"),
        ("USB Device Connected to Workstation", "Policy", "T1052.001", "Low", "Detected"),
        ("PowerShell Execution Policy Check", "Discovery", "T1059.001", "Informational", "Detected"),
        ("Outdated Chrome Browser Version Detected", "Vulnerability", "N/A", "Low", "Allowed"),
        ("High RAM Utilization Warning", "System", "N/A", "Informational", "Allowed"),
        ("Windows Event Log Service Cleared (Scheduled Test)", "DefenseEvasion", "T1070.001", "Medium", "Detected")
    ]

    while len(records) < num_alerts:
        title, cat, mitre, sev, action = random.choice(noise_titles)
        noise_time = base_time + timedelta(minutes=random.randint(0, 1800))
        noise_inc_id = f"INC-NOISE-{random.randint(200, 250)}"
        records.append({
            "OrgId": "ORG-CORP-01",
            "IncidentId": noise_inc_id,
            "AlertId": f"ALT-{alert_counter}",
            "Timestamp": noise_time.strftime("%Y-%m-%d %H:%M:%S"),
            "DetectorId": f"DET-{random.randint(100, 999)}",
            "AlertTitle": title,
            "Category": cat,
            "MitreTechniques": mitre,
            "Severity": sev,
            "IncidentGrade": "BenignPositive" if sev == "Low" else "FalsePositive",
            "ActionGrouped": action,
            "DeviceId": f"DEV-WORKSTATION-{random.randint(1, 40):02d}",
            "AccountUpn": f"corp\\user_{random.randint(1, 40):02d}",
            "IpAddress": f"192.168.100.{random.randint(10, 240)}",
            "Sha256": "N/A",
            "Url": "N/A"
        })
        alert_counter += 1

    df = pd.DataFrame(records)
    return df

def ingest_guide_dataset(filepath: str, db: Session) -> dict:
    if os.path.exists(filepath):
        logger.info(f"Loading Microsoft GUIDE dataset from {filepath}")
        df = pd.read_csv(filepath)
        df = clean_and_impute_dataframe(df)
    else:
        logger.warning(f"GUIDE dataset not found at {filepath}. Generating high-fidelity synthetic benchmark (125 alerts).")
        df = generate_synthetic_guide_dataset(num_alerts=125)
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        df.to_csv(filepath, index=False)
        logger.info(f"Saved benchmark dataset to {filepath}")

    db.query(Alert).delete()
    db.commit()

    alerts_to_insert = []
    for _, row in df.iterrows():
        ts = pd.to_datetime(row["Timestamp"]) if pd.notnull(row["Timestamp"]) else datetime.utcnow()
        alert = Alert(
            AlertId=str(row.get("AlertId", f"ALT-{random.randint(10000, 99999)}")),
            IncidentId=str(row.get("IncidentId", "INC-UNASSIGNED")),
            OrgId=str(row.get("OrgId", "ORG-CORP-01")),
            Timestamp=ts,
            DetectorId=str(row.get("DetectorId", "DET-001")),
            AlertTitle=str(row.get("AlertTitle", "Generic Security Alert")),
            Category=str(row.get("Category", "SuspiciousActivity")),
            MitreTechniques=str(row.get("MitreTechniques", "N/A")),
            Severity=str(row.get("Severity", "Medium")),
            IncidentGrade=str(row.get("IncidentGrade", "TruePositive")),
            ActionGrouped=str(row.get("ActionGrouped", "Detected")),
            DeviceId=str(row.get("DeviceId", "DEV-UNKNOWN")),
            AccountUpn=str(row.get("AccountUpn", "corp\\unknown")),
            IpAddress=str(row.get("IpAddress", "0.0.0.0")),
            Sha256=str(row.get("Sha256", "N/A")),
            Url=str(row.get("Url", "N/A")),
            AnomalyScore=0.0,
            ClusterId=str(row.get("IncidentId", "INC-UNASSIGNED"))
        )
        alerts_to_insert.append(alert)

    db.bulk_save_objects(alerts_to_insert)
    db.commit()

    total_alerts = len(alerts_to_insert)
    unique_incidents = len(df["IncidentId"].unique()) if "IncidentId" in df.columns else 0
    
    logger.info(f"Successfully ingested {total_alerts} alerts across {unique_incidents} incident clusters.")
    return {
        "status": "success",
        "total_alerts": total_alerts,
        "unique_clusters": unique_incidents,
        "dataset_path": filepath
    }