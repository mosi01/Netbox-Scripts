from extras.scripts import Script, StringVar
from django.forms.widgets import PasswordInput
import paramiko
import winrm
import json

class FetchAndUpdateVMResources(Script):
    ad_username = StringVar(description="Service Account Username")
    ad_password = StringVar(description="Service Account Password", widget=PasswordInput)
    domain_suffixes = StringVar(description="Domain suffixes (semicolon-separated, e.g. example.com;corp.local)")

    class Meta:
        name = "Fetch and Update VM Resources"
        description = "Fetch vCPU, Memory, and Disk info for VMs and update NetBox records."
        field_order = ["ad_username", "ad_password", "domain_suffixes"]

    def run(self, data, commit):
        username = data["ad_username"]
        password = data["ad_password"]
        domains = [d.strip() for d in data["domain_suffixes"].split(";") if d.strip()]

        vms = self.get_vms()
        self.log_info(f"Found {len(vms)} virtual machines to process.")

        for vm in vms:
            ip = vm.primary_ip.address if vm.primary_ip else None
            hostname = vm.name
            fqdn = None
            vm_data = None

            self.log_info(f"Processing VM: {hostname}")

            if ip:
                vm_data = self.fetch_vm_data(ip, username, password)
            else:
                for domain in domains:
                    fqdn = f"{hostname}.{domain}"
                    vm_data = self.fetch_vm_data(fqdn, username, password)
                    if vm_data:
                        break

            if not vm_data:
                self.log_failure(f"Could not reach VM: {hostname}")
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
            except Exception as e:
                self.log_failure(f"Error updating VM '{hostname}': {e}")

    def get_vms(self):
        from virtualization.models import VirtualMachine
        return VirtualMachine.objects.all()

    def fetch_vm_data(self, target, username, password):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(target, username=username, password=password, timeout=5)
            stdin, stdout, stderr = ssh.exec_command("lscpu | grep '^CPU(s):'; free -m; lsblk -b -o NAME,SIZE,TYPE,MOUNTPOINT")
            output = stdout.read().decode().strip().split("\n")
            ssh.close()
            return {"OS": "Linux", "Raw": output}
        except:
            pass
        try:
            session = winrm.Session(target, auth=(username, password))
            cpu_info = session.run_cmd("wmic cpu get NumberOfLogicalProcessors").std_out.decode().strip().split("\n")[1:]
            mem_info = session.run_cmd("wmic OS get TotalVisibleMemorySize").std_out.decode().strip().split("\n")[1:]
            disk_info_raw = session.run_cmd("wmic logicaldisk get size,freespace,caption").std_out.decode().strip().split("\n")[1:]
            return {"OS": "Windows", "CPU": cpu_info, "Memory": mem_info, "Disks": disk_info_raw}
        except:
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
