import os
import re


def parse_nmap_output(filename):
    with open(filename, 'r') as file:
        nmap_output = file.read()

    results = {}
    current_port = None
    script_id = None
    script_content = ""

    # Combined pattern to match lines starting with '|_' or '| ' (with exactly one space)
    combined_pattern = r'^\|_|^\| [^ ]'
    just_found_port = False

    for line in nmap_output.split('\n'):
        is_new_script = False

        # Check for a port line
        port_match = re.match(r'(\d+)/tcp\s+open\s+(\S+)', line)
        if port_match:
            # Save the previous script data before moving to a new port
            if current_port and script_id:
                results[current_port]['scripts'][script_id] = script_content + '\n'

            current_port = port_match.group(1)
            service = port_match.group(2)
            results[current_port] = {'service': service, 'scripts': {}, 'full_content': line + '\n'}
            script_id = None
            script_content = ""
            just_found_port = True
            continue

        # Handle script lines based on the combined pattern
        if current_port and re.match(combined_pattern, line):
            if re.match(r'^\|_([0-9a-zA-Z_-]+):', line) or (line.startswith('| ') and just_found_port):
                is_new_script = True

            if is_new_script:
                # Save the previous script data before starting a new script
                if script_id:
                    results[current_port]['scripts'][script_id] = script_content

                parts = line.split(':', 1)
                script_id = parts[0].strip('|_').strip()
                script_content = line + '\n'

                results[current_port]['scripts'][script_id] = ""
                results[current_port]['full_content'] += line + '\n'
                continue
            else:
                script_content += line + '\n'
        elif line.startswith('|') and current_port and script_id:
            script_content += line + '\n'

        just_found_port = False

        if results and not line.startswith('|') and current_port and script_id:
            results[current_port]['scripts'][script_id] = script_content
            break
        elif current_port:
            results[current_port]['full_content'] += line + '\n'

    return results


def generate_findings_files(findings: dict) -> None:
    os.makedirs('nmap', exist_ok=True)

    for port, info in findings.items():
        with open(f"nmap/{port}-{info['service'].upper()}", 'w') as f:
            f.write(info['full_content'])
            f.write('\n')
            f.write('-' * 100)
            f.write('\n')
            f.write('Things to check:\n')
            for r in _get_recommendations(info['service']):
                f.write('- ' + r + '\n')
            f.write('-' * 100)
            f.write('\n')


def _get_recommendations(service: str) -> list:
    if service == 'http' or service == 'https':
        return [
            'Manual browsing',
            'Check robots.txt',
            'Enumerate directories',
            'Check software version',
            'Check for SQL injection',
            'Check for XSS',
            'Check for LFI/RFI',
            'Check for XXE',
            'Check for SSTI',
            'Check for SSTI',
            'Check for open redirect',
            'Check for file upload',
            'Check for insecure cookies',
            'Check for insecure headers',
            'Check for insecure CORS',
        ]
    elif service == 'ssh':
        return [
            'Manual login',
            'Check for weak credentials',
            'Check for SSH key',
            'Check for SSH agent forwarding',
        ]
    elif service == 'ftp':
        return [
            'Manual login',
            'Check for anonymous login',
            'Check for weak credentials',
            'Check for FTP bounce attack',
        ]
    elif service == 'smtp':
        return [
            'Manual login',
            'Check for weak credentials',
            'Check for open relay',
            'Check for SMTP user enumeration',
            'Check for SMTP command injection',
            'Check for SMTP STARTTLS',
            'Check for SMTP user enumeration',
        ]
    elif service == 'pop3':
        return [
            'Manual login',
            'Check for weak credentials',
            'Check for POP3 STARTTLS',
            'Check for POP3 user enumeration',
        ]
    elif service == 'imap':
        return [
            'Manual login',
            'Check for weak credentials',
            'Check for IMAP STARTTLS',
            'Check for IMAP user enumeration',
        ]
    elif service == 'mysql':
        return [
            'Manual login',
            'Check for weak credentials',
            'Check for SQL injection',
            'Check for MySQL command execution',
            'Check for MySQL user enumeration',
        ]
    elif service == 'smb':
        return [
            'Manual login',
            'Check for SMB null session',
            'Check for SMB user enumeration',
            'Check for SMB shares',
            'Check for SMB vulnerabilities',
        ]

    return ["No recommendations found."]

if __name__ == '__main__':
    # Usage
    filename = 'nmap_result.txt'  # Replace with your filename
    print(os.getcwd())
    results = parse_nmap_output(filename)
    generate_findings_files(results)
    # for port, info in results.items():
    #     print(f"Port: {port}")
    #     # print(f"    Full content:\n{info['full_content']}")
    #     print(f"Service: {info['service']}")
    #     for script, result in info['scripts'].items():
    #         print(f"Script: {script}")
    #         print(f"Result:\n{result}")
