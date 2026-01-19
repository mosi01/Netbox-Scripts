from extras.scripts import Script, StringVar, BooleanVar, ChoiceVar
from django.forms.widgets import PasswordInput
import winrm
from concurrent.futures import ThreadPoolExecutor, as_completed

class CheckWindowsAntivirusStatus(Script):
    windows_domain = StringVar(description="Windows Domain (e.g. contoso.com)")
    windows_username = StringVar(description="Windows Username")
    windows_password = StringVar(description="Windows Password", widget=PasswordInput)
    domain_suffixes = StringVar(description="Domain suffixes for Windows (semicolon-separated, e.g. contoso.com;domain.com)")
    test_single_vm = BooleanVar(description="Test only one VM?", required=False)
    single_vm_target = StringVar(description="IP or FQDN of the VM to test (optional)", required=False)
    max_threads = ChoiceVar(
        description="Number of parallel threads (higher = faster, but more load on NetBox and network)",
        choices=[(str(i), f"{i} threads") for i in range(1, 11)],
        default="5"
    )

    class Meta:
        name = "Check Windows Antivirus Status"
        description = (
            "Checks if Microsoft Defender services are running on Windows VMs and updates NetBox custom field 'active_antivirus'.\n"
            "Services checked: WinDefend, WdNisSvc, Sense. (Windows 2008-2012: MsMpSvc, NisSrv)"
        )
        field_order = [
            "windows_domain", "windows_username", "windows_password",
            "domain_suffixes", "test_single_vm", "single_vm_target", "max_threads"
        ]

    def run(self, data, commit):
        win_domain = data["windows_domain"]
        win_user = data["windows_username"]
        win_pass = data["windows_password"]
        domains = [d.strip() for d in data["domain_suffixes"].split(";") if d.strip()]
        test_single = data.get("test_single_vm", False)
        single_target = data.get("single_vm_target", "").strip()
        threads = int(data.get("max_threads", "5"))

        success_results = []
        failure_results = []

        # Single VM mode
        if test_single and single_target:
            self.log_info(f"[{single_target}] Testing single VM")
            status, details, error_msg = self.check_antivirus_services(single_target, win_domain, win_user, win_pass)
            if status is None:
                self.log_failure(f"[{single_target}] {error_msg}")
                failure_results.append({"hostname": single_target, "error": error_msg})
            else:
                self.log_info(f"[{single_target}] Antivirus Active: {status} \n{details}")
                if commit:
                    vm_obj = self.get_vm_by_name(single_target)
                    if vm_obj:
                        self.update_netbox_vm(vm_obj, status)
                    else:
                        self.log_failure(f"[{single_target}] Could not find VM in NetBox for update")
                success_results.append({"hostname": single_target, "antivirus": status, "details": details})
            return "\n".join(self.generate_csv(success_results, failure_results))

        # Normal mode: process all VMs in parallel
        vms = self.get_vms()
        self.log_info(f"Found {len(vms)} virtual machines to process using {threads} threads.")
        futures = []
        with ThreadPoolExecutor(max_workers=threads) as executor:
            for vm in vms:
                futures.append(executor.submit(self.process_vm, vm, win_domain, win_user, win_pass, domains, commit))
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
        csv_lines = ["Hostname;Antivirus Active;Details;Error"]
        for s in success_results:
            csv_lines.append(f"{s['hostname']};{s['antivirus']};{s['details']};")
        for f in failure_results:
            csv_lines.append(f"{f['hostname']};;;{f['error']}")
        return csv_lines

    def check_antivirus_services(self, target, domain, username, password):
        try:
            full_user = f"{username}@{domain}"
            session = winrm.Session(target, auth=(full_user, password), transport='ntlm')

            # PowerShell script to check Defender and fallback to legacy services
            ps_script = """
            $modernServices = @('WinDefend','WdNisSvc','Sense')
            $legacyServices = @('MsMpSvc','NisSrv')
            $modernRunning = 0
            $legacyRunning = 0
            $details = @()

            foreach ($svc in $modernServices) {
                try {
                    $status = (Get-Service -Name $svc -ErrorAction SilentlyContinue).Status
                    if ($status) {
                        $details += "$svc=$status"
                        if ($status -eq 'Running') { $modernRunning++ }
                    } else {
                        $details += "$svc=NotInstalled"
                    }
                } catch {
                    $details += "$svc=NotInstalled"
                }
            }

            if ($modernRunning -eq 3) {
                Write-Output "Antivirus=True"
                Write-Output ($details -join ', ')
                exit
            }

            foreach ($svc in $legacyServices) {
                try {
                    $status = (Get-Service -Name $svc -ErrorAction SilentlyContinue).Status
                    if ($status) {
                        $details += "$svc=$status"
                        if ($status -eq 'Running') { $legacyRunning++ }
                    } else {
                        $details += "$svc=NotInstalled"
                    }
                } catch {
                    $details += "$svc=NotInstalled"
                }
            }

            if ($legacyRunning -eq 2) {
                Write-Output "Antivirus=True"
            } else {
                Write-Output "Antivirus=False"
            }
            Write-Output ($details -join ', ')
            """

            result = session.run_ps(ps_script)
            output = result.std_out.decode().strip().split("\n")
            antivirus_status = False
            details = []
            for line in output:
                if line.startswith("Antivirus="):
                    antivirus_status = line.split("=")[1].strip().lower() == "true"
                else:
                    details.append(line)
            return antivirus_status, ", ".join(details), ""
        except Exception as e:
            return None, "", f"WinRM connection failed: {str(e)}"

    def process_vm(self, vm, win_domain, win_user, win_pass, domains, commit):
        hostname = vm.name
        ip = str(vm.primary_ip.address.ip) if vm.primary_ip else None
        self.log_info(f"[{hostname}] Processing VM")
        status = None
        details = ""
        error_msg = ""

        # Try IP first
        if ip:
            self.log_info(f"[{hostname}] Trying Windows via IP: {ip}")
            status, details, error_msg = self.check_antivirus_services(ip, win_domain, win_user, win_pass)

        # Try FQDN if IP fails
        if status is None and not ip:
            for domain in domains:
                fqdn = f"{hostname}.{domain}"
                self.log_info(f"[{hostname}] Trying Windows via FQDN: {fqdn}")
                status, details, error_msg = self.check_antivirus_services(fqdn, win_domain, win_user, win_pass)
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
                "antivirus": status,
                "details": details,
                "error": "",
                "message": f"[{hostname}] SUCCESS: Antivirus Active = {status} \n{details}"
            }
        except Exception as e:
            return {"status": "fail", "hostname": hostname, "error": f"Update error: {str(e)}", "message": f"[{hostname}] Error updating VM: {str(e)}"}

    def update_netbox_vm(self, vm, status):
        vm.custom_field_data["active_antivirus"] = status
        vm.save()

    def get_vms(self):
        from virtualization.models import VirtualMachine
        return VirtualMachine.objects.all()

    def get_vm_by_name(self, name):
        from virtualization.models import VirtualMachine
        try:
            return VirtualMachine.objects.get(name=name)
        except VirtualMachine.DoesNotExist:
            return None
