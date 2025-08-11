from extras.scripts import Script
from virtualization.models import VirtualMachine, VMInterface
from ipam.models import IPAddress
import socket

class VerifyAndUpdateVMIPs(Script):
    class Meta:
        name = "Verify and Update VM IPs"
        description = "Resolves DNS and updates IPs for virtual machines"
        field_order = []

    def run(self, data, commit):
        updated_vms = []
        failed_vms = []

        for vm in VirtualMachine.objects.all():
            if not vm.primary_ip4:
                self.log_warning(f"{vm.name} has no primary IPv4 address.")
                continue

            dns_name = f"{vm.name}.se.lindab.com"
            try:
                resolved_ip = socket.gethostbyname(dns_name)
                current_ip = str(vm.primary_ip4.address.ip)

                if resolved_ip != current_ip:
                    # Find interface ending with -{vm.name}
                    iface = VMInterface.objects.filter(
                        virtual_machine=vm,
                        name__endswith=f"-{vm.name}"
                    ).first()

                    if iface:
                        ip_obj = IPAddress.objects.filter(assigned_object=iface).first()

                        if ip_obj:
                            self.log_info(f"{vm.name}: Updating IP from {ip_obj.address} to {resolved_ip}")
                            ip_obj.address = f"{resolved_ip}/32"
                            ip_obj.save()
                            updated_vms.append(vm.name)
                        else:
                            self.log_failure(f"{vm.name}: No IP found on interface {iface.name}")
                            failed_vms.append(vm.name)
                    else:
                        self.log_failure(f"{vm.name}: No interface found ending with -{vm.name}")
                        failed_vms.append(vm.name)
                else:
                    self.log_success(f"{vm.name}: IP matches ({resolved_ip})")
            except Exception as e:
                self.log_failure(f"{vm.name}: DNS lookup failed for {dns_name} - {e}")
                failed_vms.append(vm.name)

        self.log_info(f"✅ Updated VMs: {updated_vms}")
        self.log_info(f"❌ Failed VMs: {failed_vms}")
