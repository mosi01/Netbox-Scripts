from extras.scripts import Script, StringVar, BooleanVar, IntegerVar
import pynetbox
from django.db import transaction
from concurrent.futures import ThreadPoolExecutor, as_completed

# Import relevant NetBox models (expand as needed)
from dcim.models import Region, SiteGroup, Site, Location, Rack, Device, Manufacturer, DeviceType, ModuleType, Module, Interface, Cable
from tenancy.models import Tenant, TenantGroup, Contact, ContactGroup, ContactRole
from ipam.models import IPAddress, Prefix, VLAN, VRF, ASN, Aggregate
from virtualization.models import VirtualMachine, Cluster
from circuits.models import Circuit, Provider
from wireless.models import WirelessLAN, WirelessLANGroup
from extras.models import ConfigContext, Tag

class FullSyncFromProduction(Script):
    class Meta:
        name = "Full Sync from Production"
        description = "Pull ALL major data from production NetBox API and recreate in test environment. Optionally wipe dev environment first."

    # Script variables
    prod_url = StringVar(description="Production NetBox API URL", default="https://netbox.contoso.com")
    api_key = StringVar(description="API Key (first part)")
    api_token = StringVar(description="API Token (second part)")
    ca_cert_path = StringVar(description="Path to CA certificate (optional)", required=False)
    disable_ssl_verify = BooleanVar(description="Disable SSL verification (NOT recommended for production)", default=False)
    full_wipe = BooleanVar(description="Wipe all existing data before sync", default=False)
    thread_count = IntegerVar(description="Number of threads for parallel sync", default=5)

    def run(self, data, commit):
        full_token = f"nbt_{data['api_key']}.{data['api_token']}"
        self.log_info(f"Connecting to production NetBox API at {data['prod_url']}...")
        nb = pynetbox.api(data['prod_url'], token=full_token)

        # SSL handling
        if data['disable_ssl_verify']:
            self.log_warning("SSL verification is DISABLED. This is insecure!")
            nb.http_session.verify = False
        elif data.get('ca_cert_path'):
            self.log_info(f"Using custom CA certificate: {data['ca_cert_path']}")
            nb.http_session.verify = data['ca_cert_path']
        else:
            nb.http_session.verify = True

        # Optional full wipe
        if data['full_wipe'] and commit:
            self.log_warning("Performing FULL WIPE of dev environment...")
            with transaction.atomic():
                self._wipe_models([
                    Cable, Interface, Module, Device, Rack, Location, Site, Region,
                    Tenant, TenantGroup, Contact, ContactGroup, ContactRole,
                    IPAddress, Prefix, VLAN, VRF, ASN, Aggregate,
                    VirtualMachine, Cluster,
                    Circuit, Provider,
                    WirelessLAN, WirelessLANGroup,
                    ConfigContext, Tag
                ])
            self.log_success("Full wipe completed.")

        # Multi-threaded sync
        self.log_info(f"Starting sync with {data['thread_count']} threads...")
        endpoints = [
            ("Regions", nb.dcim.regions.all, self._sync_regions),
            ("Sites", nb.dcim.sites.all, self._sync_sites),
            ("Devices", nb.dcim.devices.all, self._sync_devices),
            ("IP Addresses", nb.ipam.ip_addresses.all, self._sync_ip_addresses),
            # Add more endpoints here...
        ]

        with ThreadPoolExecutor(max_workers=data['thread_count']) as executor:
            futures = {executor.submit(func, fetch(), commit): name for name, fetch, func in endpoints}
            for future in as_completed(futures):
                name = futures[future]
                try:
                    future.result()
                    self.log_success(f"{name} synced successfully.")
                except Exception as e:
                    self.log_failure(f"Failed to sync {name}: {e}")

        self.log_success("Full sync completed successfully!")

    def _wipe_models(self, models):
        for model in models:
            count = model.objects.count()
            model.objects.all().delete()
            self.log_info(f"Wiped {count} objects from {model.__name__}")

    # Sync functions for each object type
    def _sync_regions(self, regions, commit):
        for region in regions:
            if commit:
                Region.objects.update_or_create(name=region.name, defaults={'slug': region.slug})

    def _sync_sites(self, sites, commit):
        for site in sites:
            if commit:
                region_obj = Region.objects.filter(name=site.region.name).first() if site.region else None
                Site.objects.update_or_create(
                    name=site.name,
                    defaults={'slug': site.slug, 'region': region_obj, 'status': site.status.value}
                )

    def _sync_devices(self, devices, commit):
        for device in devices:
            if commit:
                site_obj = Site.objects.filter(name=device.site.name).first() if device.site else None
                Device.objects.update_or_create(
                    name=device.name,
                    defaults={
                        'device_type_id': device.device_type.id,
                        'site': site_obj,
                        'status': device.status.value
                    }
                )

    def _sync_ip_addresses(self, ips, commit):
        for ip in ips:
            if commit:
                IPAddress.objects.update_or_create(
                    address=ip.address,
                    defaults={
                        'status': ip.status.value,
                        'role': ip.role.value if ip.role else None
                    }
                )
