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
