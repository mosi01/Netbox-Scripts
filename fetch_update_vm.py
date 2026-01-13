
from extras.scripts import Script, StringVar
from django.forms.widgets import PasswordInput
import paramiko
import winrm

class FetchAndUpdateVMResources(Script):
    linux_username = StringVar(description="Linux Username")
    linux_password = StringVar(description="Linux Password", widget=PasswordInput)
    windows_domain = StringVar(description="Windows Domain (e.g. contoso.com)")
    windows_username = StringVar(description="Windows Username")
    windows_password = StringVar(description="Windows Password", widget=PasswordInput)
    domain_suffixes = StringVar(description="Domain suffixes for Windows (semicolon-separated, e.g. contoso.com;domain.com)")

    class Meta:
        name = "Fetch and Update VM Resources"
        description = "Fetch vCPU, Memory, and Disk info for VMs and update NetBox records."
        field_order = [
            "linux_username", "linux_password",
            "windows_domain", "windows_username", "windows_password",
            "domain_suffixes"
        ]

    def run(self, data, commit):
        linux_user = data["linux_username"]
        linux_pass = data["linux_password"]
        win_domain = data["windows_domain"]
        win_user = data["windows_username"]
        win_pass = data["windows_password"]
        domains = [d.strip() for d in data["domain_suffixes"].split(";") if d.strip()]

        vms = self.get_vms()
        self.log_info(f"Found {len(vms)} virtual machines to process.")

        success_count = 0
        failure_count = 0

        for vm in vms:
            ip = vm.primary_ip.address if vm.primary_ip else None
            hostname = vm.name
            fqdn = None
            vm_data = None

            self.log_info(f"Processing VM: {hostname}")

            # Try Linux first
            if ip:
                self.log_info(f"Trying SSH on {ip} with Linux credentials...")
                vm_data = self.fetch_linux_data(ip, linux_user, linux_pass)
            else:
                for domain in domains:
                    fqdn = f"{hostname}.{domain}"
                    self.log_info(f"Trying SSH on {fqdn} with Linux credentials...")
                    vm_data = self.fetch_linux_data(fqdn, linux_user, linux_pass)
                    if vm_data:
                        break

            # If Linux failed, try Windows
            if not vm_data:
                if ip:
                    self.log_info(f"Trying WinRM on {ip} with Windows credentials ({win_user}@{win_domain})...")
                    vm_data = self.fetch_windows_data(ip, win_domain, win_user, win_pass)
                else:
                    for domain in domains:
                        fqdn = f"{hostname}.{domain}"
                        self.log_info(f"Trying WinRM on {fqdn} with Windows credentials ({win_user}@{win_domain})...")
                        vm_data = self.fetch_windows_data(fqdn, win_domain, win_user, win_pass)
                        if vm_data:
                            break

            if not vm_data:
                self.log_failure(f"Could not reach VM: {hostname}")
                failure_count += 1
                continue

            try:
                vcpus = self.extract_cpu_count(vm_data)
                memory_mb = self.extract_memory(vm_data)
                disk_gb = self.extract_disk_size(vm_data)

                changes = []
                if vm.vcpus != vcpus:
                    vm.vcpus = vcpus
                    changes.append(f"vCPUs={vcpus}")
                if vm.memory != memory_mb:
                    vm.memory = memory_mb
                    changes.append(f"Memory={memory_mb}MB")
                if vm.disk != disk_gb:
                    vm.disk = disk_gb
                    changes.append(f"Disk={disk_gb}GB")

                if changes:
                    if commit:
                        vm.save()
                        self.log_success(f"Updated VM '{hostname}': " + ", ".join(changes))
                    else:
                        self.log_info(f"Dry run: Would update VM '{hostname}' with: " + ", ".join(changes))
                else:
                    self.log_info(f"No changes needed for VM '{hostname}'")

                success_count += 1
            except Exception as e:
                self.log_failure(f"Error updating VM '{hostname}': {e}")
                failure_count += 1

        # Summary
        self.log_info("---------------------------------------------------")
        self.log_info(f"Summary: {success_count} VMs succeeded, {failure_count} VMs failed.")
        self.log_info("---------------------------------------------------")

    def get_vms(self):
        from virtualization.models import VirtualMachine
        return VirtualMachine.objects.all()

    def fetch_linux_data(self, target, username, password):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(target, username=username, password=password, timeout=5)
            stdin, stdout, stderr = ssh.exec_command("lscpu | grep '^CPU(s):'; free -m; lsblk -b -o NAME,SIZE,TYPE,MOUNTPOINT")
            output = stdout.read().decode().strip().split("\n")
            ssh.close()
            return {"OS": "Linux", "Raw": output}
        except Exception as e:
            self.log_info(f"SSH connection failed for {target}: {e}")
            return None

    def fetch_windows_data(self, target, domain, username, password):
        try:
            full_user = f"{username}@{domain}"
            session = winrm.Session(target, auth=(full_user, password))
            cpu_info = session.run_cmd("wmic cpu get NumberOfLogicalProcessors").std_out.decode().strip().split("\n")[1:]
            mem_info = session.run_cmd("wmic OS get TotalVisibleMemorySize").std_out.decode().strip().split("\n")[1:]
            disk_info_raw = session.run_cmd("wmic logicaldisk get size,freespace,caption").std_out.decode().strip().split("\n")[1:]
            return {"OS": "Windows", "CPU": cpu_info, "Memory": mem_info, "Disks": disk_info_raw}
        except Exception as e:
            self.log_info(f"WinRM connection failed for {target}: {e}")
            return None

    def extract_cpu_count(self, vm_data):
        if vm_data["OS"] == "Linux":
            for line in vm_data["Raw"]:
                if "CPU(s)" in line:
                    return int(line.split(":")[1].strip())
        elif vm_data["OS"] == "Windows":
            return int(vm_data["CPU"][0].strip())
        return 0

    def extract_memory(self, vm_data):
        if vm_data["OS"] == "Linux":
            for line in vm_data["Raw"]:
                if "Mem:" in line or "total" in line:
                    parts = line.split()
                    return int(parts[1])
        elif vm_data["OS"] == "Windows":
            return int(vm_data["Memory"][0].strip()) // 1024
        return 0

    def extract_disk_size(self, vm_data):
        total_size_gb = 0
        if vm_data["OS"] == "Linux":
            for line in vm_data["Raw"]:
                if "disk" in line or "part" in line:
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        total_size_gb += int(parts[1]) / (1024**3)
        elif vm_data["OS"] == "Windows":
            for line in vm_data["Disks"]:
                parts = line.split()
                if len(parts) >= 3 and parts[2].isdigit():
                    total_size_gb += int(parts[2]) / (1024**3)
        return round(total_size_gb, 2)
