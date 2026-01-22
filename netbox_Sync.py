from extras.scripts import Script, StringVar, BooleanVar
import pynetbox
from dcim.models import Site, Device
from ipam.models import IPAddress

class SyncFromProduction(Script):
    class Meta:
        name = "Sync from Production"
        description = "Pull data from production NetBox API and recreate in test environment using pynetbox."

    # Script variables for flexibility
    prod_url = StringVar(
        description="Production NetBox API URL",
        default="https://prod-netbox.example.com"
    )
    api_token = StringVar(
        description="Production NetBox API Token"
    )
    sync_sites = BooleanVar(description="Sync Sites", default=True)
    sync_devices = BooleanVar(description="Sync Devices", default=True)
    sync_ips = BooleanVar(description="Sync IP Addresses", default=False)

    def run(self, data, commit):
        self.log_info("Connecting to production NetBox API...")
        nb = pynetbox.api(data['prod_url'], token=data['api_token'])

        # Sync Sites
        if data['sync_sites']:
            self.log_info("Fetching sites from production...")
            sites = nb.dcim.sites.all()
            for site in sites:
                self.log_info(f"Syncing site: {site.name}")
                if commit:
                    Site.objects.update_or_create(
                        name=site.name,
                        defaults={
                            'slug': site.slug,
                            'status': site.status.value
                        }
                    )

        # Sync Devices
        if data['sync_devices']:
            self.log_info("Fetching devices from production...")
            devices = nb.dcim.devices.all()
            for device in devices:
                self.log_info(f"Syncing device: {device.name}")
                if commit:
                    try:
                        site_obj = Site.objects.get(name=device.site.name)
                        Device.objects.update_or_create(
                            name=device.name,
                            defaults={
                                'device_type_id': device.device_type.id,
                                'site': site_obj,
                                'status': device.status.value
                            }
                        )
                    except Site.DoesNotExist:
                        self.log_warning(f"Site {device.site.name} not found. Skipping device {device.name}.")

        # Sync IP Addresses
        if data['sync_ips']:
            self.log_info("Fetching IP addresses from production...")
            ips = nb.ipam.ip_addresses.all()
            for ip in ips:
                self.log_info(f"Syncing IP: {ip.address}")
                if commit:
                    IPAddress.objects.update_or_create(
                        address=ip.address,
                        defaults={
                            'status': ip.status.value,
                            'role': ip.role.value if ip.role else None
                        }
                    )

        self.log_success("Sync completed successfully!")
