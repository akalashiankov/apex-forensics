#!/usr/bin/env python3
import argparse
import os
import sys
from datetime import datetime
from core.banner import print_banner
from core.parser import ApexParser
from core.scorer import ApexScorer
from reports.pdf_generator import ApexReportGenerator

def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="APEX - Automated Phishing Executive Examiner",
        usage="python3 apex.py -f <path_to_email> [options]"
    )
    
    parser.add_argument(
        "-f", "--file", 
        required=True, 
        help="Path to the target email file (.eml or .msg)"
    )
    
    parser.add_argument(
        "-o", "--output", 
        default="./reports_output", 
        help="Directory to save the generated PDF report (default: ./reports_output)"
    )

    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"\033[91m[!] Error: Target file '{args.file}' not found.\033[0m")
        sys.exit(1)

    print(f"\033[94m[*] Initializing forensic analysis on:\033[0m {args.file}")
    
    # 1. Parse Email
    apex_parser = ApexParser(args.file)
    results = apex_parser.parse_email()

    if not results:
        print(f"\033[91m[!] Analysis failed during parsing stage.\033[0m")
        sys.exit(1)

    # 2. Calculate Score & Severity
    scorer = ApexScorer(results)
    score = scorer.calculate_score()
    severity, description = scorer.get_severity_tier()

    print(f"\033[92m[+] Forensic Triage Complete:\033[0m")
    print(f"    - Subject       : {results['subject']}")
    print(f"    - Composite Risk: {score} / 100")
    print(f"    - Severity Tier : {severity}")

    # 3. Generate PDF Report
    os.makedirs(args.output, exist_ok=True)
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    pdf_filename = os.path.join(args.output, f"APEX_Report_{timestamp_str}.pdf")

    report_gen = ApexReportGenerator(pdf_filename, results, score, severity)
    report_gen.build_pdf()

    print(f"\033[92m[+] Executive PDF report generated successfully:\033[0m {pdf_filename}")
    print(f"\033[90m[*] Module execution completed.\033[0m\n")

if __name__ == "__main__":
    main()
