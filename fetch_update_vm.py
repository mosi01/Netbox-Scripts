from extras.scripts import Script, StringVar, BooleanVar
from django.forms.widgets import PasswordInput
import paramiko
import winrm

class FetchAndUpdateVMResources(Script):
    linux_username = StringVar(description="Linux Username")
    linux_password = StringVar(description="Linux Password", widget=PasswordInput)
    windows_domain = StringVar(description="Windows Domain (e.g. se.lindab.com)")
    windows_username = StringVar(description="Windows Username")
    windows_password = StringVar(description="Windows Password", widget=PasswordInput)
    domain_suffixes = StringVar(description="Domain suffixes for Windows (semicolon-separated, e.g. contoso.com;domain.com)")
    test_single_vm = BooleanVar(description="Test only one VM?")
    single_vm_target = StringVar(description="IP or FQDN of the VM to test (required if checkbox is checked)")

    class Meta:
        name = "Fetch and Update VM Resources"
        description = "Fetch vCPU, Memory, and Disk info for VMs and update NetBox records."
        field_order = [
            "linux_username", "linux_password",
            "windows_domain", "windows_username", "windows_password",
            "domain_suffixes", "test_single_vm", "single_vm_target"
        ]

    def run(self, data, commit):
        linux_user = data["linux_username"]
        linux_pass = data["linux_password"]
        win_domain = data["windows_domain"]
        win_user = data["windows_username"]
        win_pass = data["windows_password"]
        domains = [d.strip() for d in data["domain_suffixes"].split(";") if d.strip()]
        test_single = data["test_single_vm"]
        single_target = data["single_vm_target"].strip() if data["single_vm_target"] else None

        success_count = 0
        failure_count = 0
        failed_vms = []

        # If single VM test is enabled
        if test_single:
            if not single_target:
                self.log_failure("Single VM target is required when checkbox is checked.")
                return
            self.log_info(f"Testing single VM: {single_target}")
            vm_data = None

            # Try Linux first
            self.log_info(f"Trying SSH on {single_target} with Linux credentials...")
            vm_data = self.fetch_linux_data(single_target, linux_user, linux_pass)

            # If Linux failed, try Windows with NTLM
            if not vm_data:
                self.log_info(f"Trying WinRM (NTLM) on {single_target} with Windows credentials ({win_user}@{win_domain})...")
                vm_data = self.fetch_windows_data(single_target, win_domain, win_user, win_pass)

            if not vm_data:
                self.log_failure(f"Could not reach VM: {single_target}")
                return

            try:
                vcpus = self.extract_cpu_count(vm_data)
                memory_mb = self.extract_memory(vm_data)
                disks = self.extract_disks(vm_data)

                self.log_info(f"Fetched data: vCPUs={vcpus}, Memory={memory_mb}MB")
                self.log_info("Disks found:")
                for name, size in disks.items():
                    disk_label = self.format_disk_name(single_target, name)
                    self.log_info(f"- {disk_label}: {size}GB")
            except Exception as e:
                self.log_failure(f"Error processing VM '{single_target}': {e}")
            return

        # Normal mode: process all VMs
        vms = self.get_vms()
        self.log_info(f"Found {len(vms)} virtual machines to process.")

        from virtualization.models import VirtualDisk

        for vm in vms:
            ip = str(vm.primary_ip.address.ip) if vm.primary_ip else None
            hostname = vm.name
            fqdn = None
            vm_data = None

            self.log_info(f"Processing VM: {hostname}")

            # Try Linux first
            if ip:
                self.log_info(f"Trying SSH on {ip} with Linux credentials...")
                vm_data = self.fetch_linux_data(ip, linux_user, linux_pass)
            if not vm_data and not ip:
                for domain in domains:
                    fqdn = f"{hostname}.{domain}"
                    self.log_info(f"Trying SSH on {fqdn} with Linux credentials...")
                    vm_data = self.fetch_linux_data(fqdn, linux_user, linux_pass)
                    if vm_data:
                        break

            # If Linux failed, try Windows with NTLM
            if not vm_data and ip:
                self.log_info(f"Trying WinRM (NTLM) on {ip} with Windows credentials ({win_user}@{win_domain})...")
                vm_data = self.fetch_windows_data(ip, win_domain, win_user, win_pass)
            if not vm_data and not ip:
                for domain in domains:
                    fqdn = f"{hostname}.{domain}"
                    self.log_info(f"Trying WinRM (NTLM) on {fqdn} with Windows credentials ({win_user}@{win_domain})...")
                    vm_data = self.fetch_windows_data(fqdn, win_domain, win_user, win_pass)
                    if vm_data:
                        break

            if not vm_data:
                self.log_failure(f"Could not reach VM: {hostname}")
                failure_count += 1
                failed_vms.append(hostname)
                continue

            try:
                vcpus = self.extract_cpu_count(vm_data)
                memory_mb = self.extract_memory(vm_data)
                disks = self.extract_disks(vm_data)

                self.log_info(f"Fetched data: vCPUs={vcpus}, Memory={memory_mb}MB")
                self.log_info("Disks found:")
                for name, size in disks.items():
                    disk_label = self.format_disk_name(hostname, name)
                    self.log_info(f"- {disk_label}: {size}GB")

                # Update VM and disks in NetBox
                changes = []
                if vm.vcpus != vcpus:
                    vm.vcpus = vcpus
                    changes.append(f"vCPUs={vcpus}")
                if vm.memory != memory_mb:
                    vm.memory = memory_mb
                    changes.append(f"Memory={memory_mb}MB")

                if commit:
                    vm.save()

                    # Handle disks: add/update/remove
                    existing_disks = {d.name: d for d in VirtualDisk.objects.filter(virtual_machine=vm)}
                    new_disk_names = []

                    for name, size in disks.items():
                        disk_label = self.format_disk_name(hostname, name)
                        new_disk_names.append(disk_label)
                        if disk_label in existing_disks:
                            disk_obj = existing_disks[disk_label]
                            if disk_obj.size != int(size):
                                disk_obj.size = int(size)
                                disk_obj.save()
                                self.log_info(f"Updated disk '{disk_label}' size to {size}GB")
                        else:
                            VirtualDisk.objects.create(virtual_machine=vm, name=disk_label, size=int(size))
                            self.log_info(f"Created disk '{disk_label}' with size {size}GB")

                    # Remove disks that no longer exist
                    for old_disk_name in existing_disks.keys():
                        if old_disk_name not in new_disk_names:
                            existing_disks[old_disk_name].delete()
                            self.log_info(f"Deleted disk '{old_disk_name}' (no longer present on VM)")

                    self.log_success(f"Updated VM '{hostname}': " + ", ".join(changes))
                else:
                    self.log_info(f"Dry run: Would update VM '{hostname}' and disks: " + ", ".join([f"{self.format_disk_name(hostname, n)}={s}GB" for n, s in disks.items()]))

                success_count += 1
            except Exception as e:
                self.log_failure(f"Error updating VM '{hostname}': {e}")
                failure_count += 1
                failed_vms.append(hostname)

        # Summary
        self.log_info("---------------------------------------------------")
        self.log_info(f"Summary: {success_count} VMs succeeded, {failure_count} VMs failed.")
        if failed_vms:
            self.log_info("Failed VMs: " + ", ".join(failed_vms))
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
            session = winrm.Session(target, auth=(full_user, password), transport='ntlm')
            cpu_info = session.run_cmd("wmic cpu get NumberOfLogicalProcessors").std_out.decode().strip().split("\n")[1:]
            mem_info = session.run_cmd("wmic OS get TotalVisibleMemorySize").std_out.decode().strip().split("\n")[1:]
            disk_info_raw = session.run_cmd("wmic logicaldisk get size,caption").std_out.decode().strip().split("\n")[1:]
            return {"OS": "Windows", "CPU": cpu_info, "Memory": mem_info, "Disks": disk_info_raw}
        except Exception as e:
            self.log_info(f"WinRM (NTLM) connection failed for {target}: {e}")
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

    def extract_disks(self, vm_data):
        disks = {}
        if vm_data["OS"] == "Linux":
            for line in vm_data["Raw"]:
                parts = line.split()
                if len(parts) >= 3 and parts[2] == "disk":
                    name = parts[0]
                    size_gb = round(int(parts[1]) / (1024**3), 2)
                    disks[name] = size_gb
        elif vm_data["OS"] == "Windows":
            for line in vm_data["Disks"]:
                parts = line.split()
                if len(parts) >= 2 and parts[1].isdigit():
                    name = parts[0].replace(":", "")  # Remove colon from C:, D:
                    size_gb = round(int(parts[1]) / (1024**3), 2)
                    disks[name] = size_gb
        return disks

    def format_disk_name(self, hostname, disk_name):
        return f"VD-{hostname}-disk{disk_name}"
