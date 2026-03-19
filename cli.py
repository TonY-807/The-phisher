import argparse
import analyzer
import email_analyzer
import database
import pdf_generator
import sys

def interactive_mode():
    print("Welcome to ThePhisher: Multi-Layer Detection System")
    print("1. Scan URL")
    print("2. Scan Email (.eml file)")
    print("3. View Logs")
    choice = input("Select an option (1-3): ")
    
    if choice == '1':
        url = input("Enter URL to scan: ")
        result = analyzer.calculate_risk_score(url)
        result['type'] = 'URL'
        result['input_data'] = result['url']
        database.add_scan(result['input_data'], 'URL', result['classification'], result['score'])
        
        print(f"\nVerdict: {result['classification']} (Score: {result['score']}%)")
        for detail in result['details']:
            print(f" - {detail['check']}: {detail['result']}")
            
        pdf_path = pdf_generator.generate_phishing_report(result)
        print(f"\nPDF Report generated at: {pdf_path}")
        
    elif choice == '2':
        path = input("Enter path to .eml file to scan: ")
        try:
            result = email_analyzer.analyze_email_file(path)
            database.add_scan(result['input_data'], 'Email', result['classification'], result['score'])
            print(f"\nVerdict: {result['classification']} (Score: {result['score']}%)")
            for detail in result['details']:
                print(f" - {detail['check']}: {detail['result']}")
                
            pdf_path = pdf_generator.generate_phishing_report(result)
            print(f"\nPDF Report generated at: {pdf_path}")
        except FileNotFoundError:
            print(f"File not found: {path}")
            
    elif choice == '3':
        history = database.get_history()
        print(f"\n{'ID':<5} | {'Type':<10} | {'Input':<40} | {'Classification':<15} | {'Score':<5} | {'Date'}")
        print("-" * 105)
        for h in history:
            print(f"{h.get('id', ''):<5} | {h.get('input_type', 'URL'):<10} | {h.get('input_data', h.get('url', ''))[:38]:<40} | {h['classification']:<15} | {h['score']:<5} | {h['scan_date']}")
    else:
        print("Invalid choice.")

def main():
    parser = argparse.ArgumentParser(description="Multi-Layer Phishing Detection and Logging System")
    parser.add_argument("--url", help="URL to scan")
    parser.add_argument("--email-file", help="Path to .eml file to scan")
    parser.add_argument("--logs", action="store_true", help="View scan logs")
    
    args = parser.parse_args()
    
    database.init_db()
    
    # If no arguments provided, run interactive mode
    if not any(vars(args).values()):
        interactive_mode()
        return

    if args.url:
        print(f"Scanning URL: {args.url}")
        result = analyzer.calculate_risk_score(args.url)
        result['type'] = 'URL'
        result['input_data'] = result['url']
        database.add_scan(result['input_data'], 'URL', result['classification'], result['score'])
        
        print(f"Verdict: {result['classification']} (Score: {result['score']})")
        pdf_path = pdf_generator.generate_phishing_report(result)
        print(f"Report generated: {pdf_path}")
        
    elif args.email_file:
        print(f"Scanning Email: {args.email_file}")
        try:
            result = email_analyzer.analyze_email_file(args.email_file)
            database.add_scan(result['input_data'], 'Email', result['classification'], result['score'])
            print(f"Verdict: {result['classification']} (Score: {result['score']})")
            pdf_path = pdf_generator.generate_phishing_report(result)
            print(f"Report generated: {pdf_path}")
        except FileNotFoundError:
            print(f"Error: File not found {args.email_file}", file=sys.stderr)
            
    elif args.logs:
        history = database.get_history()
        print(f"\n{'ID':<5} | {'Type':<10} | {'Input':<40} | {'Classification':<15} | {'Score':<5} | {'Date'}")
        print("-" * 105)
        for h in history:
            print(f"{h.get('id', ''):<5} | {h.get('input_type', 'URL'):<10} | {h.get('input_data', h.get('url', ''))[:38]:<40} | {h['classification']:<15} | {h['score']:<5} | {h['scan_date']}")

if __name__ == "__main__":
    main()
