import os
import subprocess

from cmd2 import CommandSet, with_default_category, with_argparser, Cmd2ArgumentParser
# from ..utils.nmap_parser import parse_nmap_output

from utils.colors import Colors


@with_default_category('Reconnaissance Commands')
class ReconCommandSet(CommandSet):
    TOP_PORTS_ARG = '--top-ports 1000'

    scan_parser = Cmd2ArgumentParser()
    scan_parser.add_argument('target', help='The target to scan.', nargs='?')
    scan_parser.add_argument('ports', help='The ports to scan.', nargs='?', default=TOP_PORTS_ARG)

    auto_scan_parser = Cmd2ArgumentParser()
    auto_scan_parser.add_argument('target', help='The target to scan.', nargs='?')

    @with_argparser(auto_scan_parser)
    def do_auto_scan(self, opts) -> None:
        """
        Perform an automatic scan. This will perform an initial scan, an enumeration scan, and a full scan.
        """
        if not self._cmd.target and not opts.target:
            print(f"{Colors.FAIL}Please set the target.{Colors.ENDC}")
            return

        if opts.target:
            self._cmd.do_set(f"target {opts.target}")  # noqa

        setattr(opts, 'ports', None)

        self.do_initial_scan(opts)  # noqa
        self.extract_open_ports()
        setattr(opts, 'ports', self._cmd.target_open_ports)
        self.do_enum_scan(opts)  # noqa
        # findings = parse_nmap_output(self._cmd.nmap_enum_scan_output)
        # self.generate_findings_files(findings)
        self.do_full_scan(opts)  # noqa

    def generate_findings_files(self, findings: dict) -> None:
        os.makedirs('nmap', exist_ok=True)

        for port, info in findings.items():
            with open(f"nmap/{port}-{info['service'].upper()}", 'w') as f:
                f.write(info['full_content'])
                f.write('\n\n')
                f.write('-' * 100)
                f.write('\n\n')
                f.write('Things to check:\n')
                for r in self._get_recommendations(info['service']):
                    f.write('- ' + r + '\n')

    def _get_recommendations(self, service: str) -> list:
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

    def extract_open_ports(self) -> None:
        command = (
                """awk '/Ports:/ {for(i=1;i<=NF;i++) if($i~/\/open\/tcp/){split($i,a,"/"); 
                ports=(ports=="") ? a[1] : ports","a[1]}} END {printf "%s", ports}' """ +
                self._cmd.nmap_initial_scan_output  # noqa
        )
        open_ports = subprocess.run(command, shell=True, check=True).stdout.decode().strip()
        self._cmd.do_set(f"target_open_ports {open_ports}")  # noqa

    def scan(self, opts, scan_options, output_file, method_name, run_in_background=False):
        if not self._cmd.target and not opts.target:
            print(f"{Colors.FAIL}Please set the target.{Colors.ENDC}")
            return

        if opts.target:
            self._cmd.do_set(f"target {opts.target}")  # noqa

        ports = f"-p {opts.ports or self._cmd.nmap_port_range} " if opts.ports != self.TOP_PORTS_ARG else ''

        command = (
            f"nmap "
            f"{scan_options} "
            f"{ports}"
            f"-oG {output_file} "
            f"{self._cmd.target}"
            f"{'' if self._cmd.verbose_mode else ' > /dev/null'}"
            f"{'' if self._cmd.debug_mode else ' 2> /dev/null'}"
            f"{' &' if run_in_background else ''}"
        )

        print(f"Performing {method_name}...")
        self.nmap_scan(command)

    @with_argparser(scan_parser)
    def do_initial_scan(self, opts) -> None:
        self.scan(opts, self._cmd.nmap_initial_scan_options, self._cmd.nmap_initial_scan_output, 'initial Nmap scan')

    @with_argparser(scan_parser)
    def do_enum_scan(self, opts) -> None:
        self.scan(opts, self._cmd.nmap_enum_scan_options, self._cmd.nmap_enum_scan_output, 'Nmap enumeration scan')

    @with_argparser(scan_parser)
    def do_full_scan(self, opts) -> None:
        self.scan(opts, self._cmd.nmap_full_scan_options, self._cmd.nmap_full_scan_output, 'full Nmap scan in background...', True)

    def nmap_scan(self, command: str) -> None:
        """
        Perform a Nmap scan.
        """
        print(command)
        self._cmd.do_shell(command)  # noqa
