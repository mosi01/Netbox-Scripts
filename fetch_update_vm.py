
from extras.scripts import Script, StringVar, BooleanVar, ChoiceVar
from django.forms.widgets import PasswordInput
import paramiko
import winrm
from concurrent.futures import ThreadPoolExecutor, as_completed

class FetchAndUpdateVMResources(Script):
    # Inputs
    linux_username = StringVar(description="Linux Username (optional)", required=False)
    linux_password = StringVar(description="Linux Password (optional)", widget=PasswordInput, required=False)
    windows_domain = StringVar(description="Windows Domain (e.g. se.lindab.com)")
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
        name = "Fetch and Update VM Resources"
        description = (
            "Fetch vCPU, Memory, and Disk info for VMs and update NetBox records.\n"
            "Optimised for speed with parallel processing.\n"
            "Windows is checked first; Linux only if Windows fails and credentials provided."
        )
        field_order = [
            "windows_domain", "windows_username", "windows_password",
            "domain_suffixes", "linux_username", "linux_password",
            "test_single_vm", "single_vm_target", "max_threads"
        ]

    def run(self, data, commit):
        linux_user = data.get("linux_username")
        linux_pass = data.get("linux_password")
        win_domain = data["windows_domain"]
        win_user = data["windows_username"]
        win_pass = data["windows_password"]
        domains = [d.strip() for d in data["domain_suffixes"].split(";") if d.strip()]
        test_single = data.get("test_single_vm", False)
        single_target = data.get("single_vm_target", "").strip()
        threads = int(data.get("max_threads", "5"))

        success_count = 0
        failure_count = 0
        failed_vms = []

        # Single VM mode
        if test_single and single_target:
            self.log_info(f"Testing single VM: {single_target}")
            vm_data = self.try_windows_then_linux(single_target, win_domain, win_user, win_pass, linux_user, linux_pass)
            if not vm_data:
                self.log_failure(f"Could not reach VM: {single_target}")
                return
            self.display_vm_data(single_target, vm_data)
            return

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
                    success_count += 1
                else:
                    failure_count += 1
                    failed_vms.append(result["hostname"])

        # Summary
        self.log_info("---------------------------------------------------")
        self.log_info(f"Summary: {success_count} VMs succeeded, {failure_count} VMs failed.")
        if failed_vms:
            self.log_info("Failed VMs: " + ", ".join(failed_vms))
        self.log_info("---------------------------------------------------")

    def process_vm(self, vm, win_domain, win_user, win_pass, linux_user, linux_pass, domains, commit):
        hostname = vm.name
        ip = str(vm.primary_ip.address.ip) if vm.primary_ip else None
        vm_data = None

        # Try Windows first
        if ip:
            vm_data = self.fetch_windows_data(ip, win_domain, win_user, win_pass)
        if not vm_data and not ip:
            for domain in domains:
                fqdn = f"{hostname}.{domain}"
                vm_data = self.fetch_windows_data(fqdn, win_domain, win_user, win_pass)
                if vm_data:
                    break

        # If Windows failed and Linux credentials provided, try Linux
        if not vm_data and linux_user and linux_pass:
            if ip:
                vm_data = self.fetch_linux_data(ip, linux_user, linux_pass)
            if not vm_data and not ip:
                for domain in domains:
                    fqdn = f"{hostname}.{domain}"
                    vm_data = self.fetch_linux_data(fqdn, linux_user, linux_pass)
                    if vm_data:
                        break

        if not vm_data:
            return {"status": "fail", "hostname": hostname}

        try:
            vcpus = self.extract_cpu_count(vm_data)
            memory_mb = self.extract_memory(vm_data)
            disks = self.extract_disks(vm_data)

            if commit:
                self.update_netbox_vm(vm, vcpus, memory_mb, disks)
            return {"status": "success", "hostname": hostname}
        except Exception:
            return {"status": "fail", "hostname": hostname}

    def update_netbox_vm(self, vm, vcpus, memory_mb, disks):
        from virtualization.models import VirtualDisk
        changes = []
        if vm.vcpus != vcpus:
            vm.vcpus = vcpus
            changes.append(f"vCPUs={vcpus}")
        if vm.memory != memory_mb:
            vm.memory = memory_mb
            changes.append(f"Memory={memory_mb}MB")
        vm.save()

        existing_disks = {d.name: d for d in VirtualDisk.objects.filter(virtual_machine=vm)}
        new_disk_names = []

        for name, size in disks.items():
            disk_label = self.format_disk_name(vm.name, name)
            new_disk_names.append(disk_label)
            if disk_label in existing_disks:
                disk_obj = existing_disks[disk_label]
                if disk_obj.size != int(size):
                    disk_obj.size = int(size)
                    disk_obj.save()
            else:
                VirtualDisk.objects.create(virtual_machine=vm, name=disk_label, size=int(size))

        for old_disk_name in existing_disks.keys():
            if old_disk_name not in new_disk_names:
                existing_disks[old_disk_name].delete()

    def display_vm_data(self, hostname, vm_data):
        vcpus = self.extract_cpu_count(vm_data)
        memory_mb = self.extract_memory(vm_data)
        disks = self.extract_disks(vm_data)
        self.log_info(f"Fetched data for {hostname}: vCPUs={vcpus}, Memory={memory_mb}MB")
        self.log_info("Disks:")
        for name, size in disks.items():
            self.log_info(f"- {self.format_disk_name(hostname, name)}: {size}GB")

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
        except:
            return None

    def fetch_windows_data(self, target, domain, username, password):
        try:
            full_user = f"{username}@{domain}"
            session = winrm.Session(target, auth=(full_user, password), transport='ntlm')
            cpu_info = session.run_cmd("wmic cpu get NumberOfLogicalProcessors").std_out.decode().strip().split("\n")[1:]
            mem_info = session.run_cmd("wmic OS get TotalVisibleMemorySize").std_out.decode().strip().split("\n")[1:]
            disk_info_raw = session.run_cmd("wmic logicaldisk get size,caption").std_out.decode().strip().split("\n")[1:]
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
                    name = parts[0].replace(":", "")
                    size_gb = round(int(parts[1]) / (1024**3), 2)
                    disks[name] = size_gb
        return disks

    def format_disk_name(self, hostname, disk_name):
        return f"VD-{hostname}-disk{disk_name}"
``
