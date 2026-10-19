import mailparser
import hashlib
import re
import tldextract

class ApexParser:
    def __init__(self, file_path):
        self.file_path = file_path
        self.parsed_mail = None
        self.extraction_results = {}

    def parse_email(self):
        try:
            # Parse the email file using mail-parser
            self.parsed_mail = mailparser.parse_from_file(self.file_path)
            
            # Extract basic metadata
            self.extraction_results["subject"] = self.parsed_mail.subject or "No Subject"
            self.extraction_results["from_address"] = self.parsed_mail.from_ or "Unknown Sender"
            self.extraction_results["to_address"] = self.parsed_mail.to or "Unknown Recipient"
            self.extraction_results["date"] = str(self.parsed_mail.date) or "Unknown Date"
            
            # Extract URLs from body
            body_content = self.parsed_mail.body or ""
            raw_urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', body_content)
            
            # Defang URLs for safe viewing and reporting
            defanged_urls = []
            for url in raw_urls:
                defanged = url.replace("http", "hxxp").replace(".", "[.]")
                defanged_urls.append({"original": url, "defanged": defanged})
            
            self.extraction_results["urls"] = defanged_urls

            # Extract Attachments and compute hashes
            attachments_info = []
            for att in self.parsed_mail.attachments:
                filename = att.get("filename", "unknown_file")
                payload = att.get("payload", "")
                
                # If payload is base64 encoded, decode to bytes for hashing
                import base64
                try:
                    file_bytes = base64.b64decode(payload)
                except Exception:
                    file_bytes = payload.encode('utf-8', errors='ignore')

                sha256_hash = hashlib.sha256(file_bytes).hexdigest()
                md5_hash = hashlib.md5(file_bytes).hexdigest()

                # Check for risky extensions
                is_executable = filename.lower().endswith(('.exe', '.scr', '.js', '.bat', '.cmd', '.pif'))
                has_macros = filename.lower().endswith(('.xlsm', '.docm', '.pptm'))

                attachments_info.append({
                    "filename": filename,
                    "sha256": sha256_hash,
                    "md5": md5_hash,
                    "is_executable": is_executable,
                    "has_macros": has_macros
                })

            self.extraction_results["attachments"] = attachments_info
            return self.extraction_results

        except Exception as e:
            print(f"\033[91m[!] Error parsing email structure: {str(e)}\033[0m")
            return None
