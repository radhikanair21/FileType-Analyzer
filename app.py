#This is a console-based application 
import os
from datetime import datetime
from file_analyzer import FileTypeAnalyzer

def main():
    analyzer = FileTypeAnalyzer()
    
    while True:
        print("\nFileType Analyzer")
        print("1. Analyze File")
        print("2. Exit")
        choice = input("Enter your choice: ").strip()
        
        if choice == '2':
            print("Exiting...")
            break
        elif choice == '1':
            path = input("Enter file path: ").strip()
            if not os.path.isfile(path):
                print("File does not exist!")
                continue
            
            try:
                result = analyzer.analyze_file(path)
                print("\nAnalysis Results:")
                print(f"File Name      : {result['filename']}")
                print(f"Extension      : {result['extension']}")
                print(f"Detected Type  : {result['detected_type']}")
                print(f"Magic Signature: {result['signature']}")
                print(f"File Size      : {result['file_size']:,} bytes")
                print(f"SHA-256        : {result['sha256']}")
                
                if result['is_suspicious']:
                    print(f"Status         : Suspicious")
                    print(f"Detail         : {result['mismatch_reason']}")
                else:
                    print(f"Status          : Safe")
                    print(f"Detail          : Extension matches detected type")
                
                save = input("\nDo you want to save the report? (y/n): ").strip().lower()
                if save == 'y':
                    save_path = input("Enter report file name (with .txt): ").strip()
                    save_report(result, save_path)
                    print(f"Report saved to {save_path}")
            except Exception as e:
                print(f"Error: {e}")
        else:
            print("Invalid choice. Try again.")

def save_report(result, path):
    report = f"""
╔════════════════════ FILE ANALYZER REPORT ═════════════════════╗
║ Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}     
╠════════════════════ FILE INFORMATION ════════════════════════╣
║ Name: {result['filename']}                                    
║ Path: {result['filepath']}                                    
║ Size: {result['file_size']} bytes ({result['file_size']/1024:.2f} KB)
║ Extension: {result['extension']}                              
╠══════════════════ SIGNATURE ANALYSIS ════════════════════════╣
║ Detected Type: {result['detected_type']}                      
║ Magic Signature: {result['signature']}                        
╠════════════════════ HASH DETAILS ════════════════════════════╣
║ SHA-256: {result['sha256']}                                    
╠══════════════════ THREAT ASSESSMENT ═════════════════════════╣
║ Status: {"Suspicious" if result['is_suspicious'] else "Safe"}
║ Detail: {result['mismatch_reason'] if result['is_suspicious'] else "None"}
╚══════════════════════════════════════════════════════════════╝
"""
    with open(path, 'w', encoding='utf-8') as f:
        f.write(report)

if __name__ == "__main__":
    main()

