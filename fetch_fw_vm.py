from extras.scripts import Script, StringVar, BooleanVar, ChoiceVar
from django.forms.widgets import PasswordInput
import winrm
import paramiko
from concurrent.futures import ThreadPoolExecutor, as_completed

class CheckFirewallStatus(Script):
    windows_domain = StringVar(description="Windows Domain (e.g. domain.com)")
    windows_username = StringVar(description="Windows Username")
    windows_password = StringVar(description="Windows Password", widget=PasswordInput)
    linux_username = StringVar(description="Linux Username (optional)", required=False)
    linux_password = StringVar(description="Linux Password (optional)", widget=PasswordInput, required=False)
    domain_suffixes = StringVar(description="Domain suffixes for Windows (semicolon-separated, e.g. contoso.com;domain.com)")
    test_single_vm = BooleanVar(description="Test only one VM?", required=False)
    single_vm_target = StringVar(description="IP or FQDN of the VM to test (optional)", required=False)
    max_threads = ChoiceVar(
        description="Number of parallel threads (higher = faster, but more load on NetBox and network)",
        choices=[(str(i), f"{i} threads") for i in range(1, 11)],
        default="5"
    )

    class Meta:
        name = "Check Firewall Status"
        description = (
            "Checks if firewall is active on Windows (Domain profile) or Linux (firewalld/ufw) and updates NetBox custom field 'active_firewall'.\n"
            "Windows is checked first; Linux only if Windows fails and credentials provided."
        )
        field_order = [
            "windows_domain", "windows_username", "windows_password",
            "domain_suffixes", "linux_username", "linux_password",
            "test_single_vm", "single_vm_target", "max_threads"
        ]

    def run(self, data, commit):
        win_domain = data["windows_domain"]
        win_user = data["windows_username"]
        win_pass = data["windows_password"]
        linux_user = data.get("linux_username")
        linux_pass = data.get("linux_password")
        domains = [d.strip() for d in data["domain_suffixes"].split(";") if d.strip()]
        test_single = data.get("test_single_vm", False)
        single_target = data.get("single_vm_target", "").strip()
        threads = int(data.get("max_threads", "5"))

        success_results = []
        failure_results = []

        # Single VM mode
        if test_single and single_target:
            self.log_info(f"[{single_target}] Testing single VM")
            status, error_msg = self.try_windows_then_linux(single_target, win_domain, win_user, win_pass, linux_user, linux_pass)
            if status is None:
                self.log_failure(f"[{single_target}] {error_msg}")
                failure_results.append({"hostname": single_target, "error": error_msg})
            else:
                self.log_info(f"[{single_target}] Firewall Active: {status}")
                if commit:
                    self.update_netbox_vm(single_target, status)
                success_results.append({"hostname": single_target, "firewall": status})
            return "\n".join(self.generate_csv(success_results, failure_results))

        # Normal mode: process all VMs in parallel
        vms = self.get_vms()
        self.log_info(f"Found {len(vms)} virtual machines to process using {threads} threads.")
        futures = []
        with ThreadPoolExecutor(max_workers=threads) as executor:
            for vm in vms:
                futures.append(executor.submit(self.process_vm, vm, win_domain, win_user, win_pass, linux_user, linux_pass, domains, commit))
            for future in as_completed(futures):
                result = future.result()
                if result["status"] == "success":
                    success_results.append(result)
                    self.log_info(result["message"])
                else:
                    failure_results.append(result)
                    self.log_failure(result["message"])

        return "\n".join(self.generate_csv(success_results, failure_results))

    def generate_csv(self, success_results, failure_results):
        csv_lines = ["Hostname;Firewall Active;Error"]
        for s in success_results:
            csv_lines.append(f"{s['hostname']};{s['firewall']};")
        for f in failure_results:
            csv_lines.append(f"{f['hostname']};;{f['error']}")
        return csv_lines

    def try_windows_then_linux(self, target, win_domain, win_user, win_pass, linux_user, linux_pass):
        self.log_info(f"[{target}] Attempting Windows firewall check")
        status, error_msg = self.check_windows_firewall(target, win_domain, win_user, win_pass)
        if status is not None:
            return status, ""
        self.log_failure(f"[{target}] Windows check failed: {error_msg}")
        if linux_user and linux_pass:
            self.log_info(f"[{target}] Attempting Linux firewall check")
            status, error_msg = self.check_linux_firewall(target, linux_user, linux_pass)
            if status is not None:
                return status, ""
            self.log_failure(f"[{target}] Linux check failed: {error_msg}")
        return None, error_msg

    def process_vm(self, vm, win_domain, win_user, win_pass, linux_user, linux_pass, domains, commit):
        hostname = vm.name
        ip = str(vm.primary_ip.address.ip) if vm.primary_ip else None
        self.log_info(f"[{hostname}] Processing VM")
        status = None
        error_msg = ""

        # Try Windows first
        if ip:
            self.log_info(f"[{hostname}] Trying Windows via IP: {ip}")
            status, error_msg = self.check_windows_firewall(ip, win_domain, win_user, win_pass)

        # Try FQDN if IP fails
        if status is None and not ip:
            for domain in domains:
                fqdn = f"{hostname}.{domain}"
                self.log_info(f"[{hostname}] Trying Windows via FQDN: {fqdn}")
                status, error_msg = self.check_windows_firewall(fqdn, win_domain, win_user, win_pass)
                if status is not None:
                    break

        # Try Linux if Windows fails
        if status is None and linux_user and linux_pass:
            if ip:
                self.log_info(f"[{hostname}] Trying Linux via IP: {ip}")
                status, error_msg = self.check_linux_firewall(ip, linux_user, linux_pass)
            if status is None and not ip:
                for domain in domains:
                    fqdn = f"{hostname}.{domain}"
                    self.log_info(f"[{hostname}] Trying Linux via FQDN: {fqdn}")
                    status, error_msg = self.check_linux_firewall(fqdn, linux_user, linux_pass)
                    if status is not None:
                        break

        if status is None:
            return {"status": "fail", "hostname": hostname, "error": error_msg, "message": f"[{hostname}] FAILURE: {error_msg}"}

        try:
            if commit:
                self.update_netbox_vm(vm, status)
            return {
                "status": "success",
                "hostname": hostname,
                "firewall": status,
                "error": "",
                "message": f"[{hostname}] SUCCESS: Firewall Active = {status}"
            }
        except Exception as e:
            return {"status": "fail", "hostname": hostname, "error": f"Update error: {str(e)}", "message": f"[{hostname}] Error updating VM: {str(e)}"}

    def check_windows_firewall(self, target, domain, username, password):
        try:
            full_user = f"{username}@{domain}"
            session = winrm.Session(target, auth=(full_user, password), transport='ntlm')
            ps_script = "(Get-NetFirewallProfile -Profile Domain).Enabled"
            result = session.run_ps(ps_script)
            status = result.std_out.decode().strip()
            return True if status.lower() == "true" else False, ""
        except Exception as e:
            return None, f"WinRM connection failed: {str(e)}"

    def check_linux_firewall(self, target, username, password):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(target, username=username, password=password, timeout=5)
            stdin, stdout, stderr = ssh.exec_command("systemctl is-active firewalld || ufw status | grep -i active")
            output = stdout.read().decode().strip().lower()
            ssh.close()
            if "active" in output:
                return True, ""
            return False, ""
        except Exception as e:
            return None, f"SSH connection failed: {str(e)}"

    def update_netbox_vm(self, vm, status):
        vm.custom_field_data["active_firewall"] = status
        vm.save()

    def get_vms(self):
        from virtualization.models import VirtualMachine
        return VirtualMachine.objects.all()
