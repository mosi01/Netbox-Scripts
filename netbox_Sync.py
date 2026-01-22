from extras.scripts import Script, StringVar, BooleanVar, IntegerVar
import pynetbox
from django.db import transaction
from django.utils.text import slugify
from concurrent.futures import ThreadPoolExecutor, as_completed

# Import all relevant NetBox models
from dcim.models import (
    Region, SiteGroup, Site, Location, Rack, RackRole,
    Manufacturer, DeviceType, DeviceRole, Platform, Device,
    ModuleType, Module, Interface
)
from tenancy.models import Tenant, TenantGroup, Contact, ContactGroup, ContactRole
from ipam.models import IPAddress, Prefix, VLAN, VLANGroup, VRF
from virtualization.models import VirtualMachine, Cluster, ClusterType
from circuits.models import Circuit, CircuitType, Provider
from wireless.models import WirelessLAN, WirelessLANGroup
from extras.models import ConfigContext, Tag

class FullSyncFromProduction(Script):
    class Meta:
        name = "Full Sync from Production"
        description = "Sync all major NetBox objects from production to dev environment in correct dependency order with multi-threading."

    prod_url = StringVar(description="Production NetBox API URL", default="https://netbox.lindab.com")
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
            nb.http_session.verify = data['ca_cert_path']
        else:
            nb.http_session.verify = True

        # Full wipe
        if data['full_wipe'] and commit:
            self.log_warning("Performing FULL WIPE of dev environment...")
            with transaction.atomic():
                self._wipe_models([
                    Interface, Module, Device, DeviceType, ModuleType,
                    Rack, Location, Site, SiteGroup, Region,
                    RackRole, DeviceRole, Platform, Manufacturer,
                    IPAddress, Prefix, VLAN, VLANGroup, VRF,
                    VirtualMachine, Cluster, ClusterType,
                    Circuit, CircuitType, Provider,
                    WirelessLAN, WirelessLANGroup,
                    ConfigContext, Tag
                ])
            self.log_success("Full wipe completed.")

        self.log_info(f"Starting sync with {data['thread_count']} threads...")

        # Define sync groups (dependency-aware)
        sync_groups = [
            # Group 1: Independent objects
            [
                ("Manufacturers", nb.dcim.manufacturers.all(), self._sync_manufacturers),
                ("Device Roles", nb.dcim.device_roles.all(), self._sync_device_roles),
                ("Platforms", nb.dcim.platforms.all(), self._sync_platforms),
                ("Rack Roles", nb.dcim.rack_roles.all(), self._sync_rack_roles),
                ("Tags", nb.extras.tags.all(), self._sync_tags),
                ("Config Contexts", nb.extras.config_contexts.all(), self._sync_config_contexts),
            ],
            # Group 2: Device types and module types
            [
                ("Device Types", nb.dcim.device_types.all(), self._sync_device_types),
                ("Module Types", nb.dcim.module_types.all(), self._sync_module_types),
            ],
            # Group 3: Regions, Sites, Locations, Racks
            [
                ("Regions", nb.dcim.regions.all(), self._sync_regions),
                ("Site Groups", nb.dcim.site_groups.all(), self._sync_site_groups),
                ("Sites", nb.dcim.sites.all(), self._sync_sites),
                ("Locations", nb.dcim.locations.all(), self._sync_locations),
                ("Racks", nb.dcim.racks.all(), self._sync_racks),
            ],
            # Group 4: Devices, Modules, Interfaces
            [
                ("Devices", nb.dcim.devices.all(), self._sync_devices),
                ("Modules", nb.dcim.modules.all(), self._sync_modules),
                ("Interfaces", nb.dcim.interfaces.all(), self._sync_interfaces),
            ],
            # Group 5: IPAM
            [
                ("VRFs", nb.ipam.vrfs.all(), self._sync_vrfs),
                ("Prefixes", nb.ipam.prefixes.all(), self._sync_prefixes),
                ("VLAN Groups", nb.ipam.vlan_groups.all(), self._sync_vlan_groups),
                ("VLANs", nb.ipam.vlans.all(), self._sync_vlans),
                ("IP Addresses", nb.ipam.ip_addresses.all(), self._sync_ip_addresses),
            ],
            # Group 6: Virtualization
            [
                ("Cluster Types", nb.virtualization.cluster_types.all(), self._sync_cluster_types),
                ("Clusters", nb.virtualization.clusters.all(), self._sync_clusters),
                ("Virtual Machines", nb.virtualization.virtual_machines.all(), self._sync_virtual_machines),
            ],
            # Group 7: Circuits
            [
                ("Providers", nb.circuits.providers.all(), self._sync_providers),
                ("Circuit Types", nb.circuits.circuit_types.all(), self._sync_circuit_types),
                ("Circuits", nb.circuits.circuits.all(), self._sync_circuits),
            ],
            # Group 8: Wireless
            [
                ("Wireless LAN Groups", nb.wireless.wireless_lan_groups.all(), self._sync_wireless_lan_groups),
                ("Wireless LANs", nb.wireless.wireless_lans.all(), self._sync_wireless_lans),
            ]
        ]

        # Execute groups sequentially, but objects inside each group in parallel
        for group in sync_groups:
            with ThreadPoolExecutor(max_workers=data['thread_count']) as executor:
                futures = {executor.submit(func, fetch(), commit): name for name, fetch, func in group}
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
            try:
                model.objects.all().delete()
                self.log_info(f"Wiped {count} objects from {model.__name__}")
            except Exception as e:
                self.log_warning(f"Could not wipe {model.__name__}: {e}")

    def _slug(self, value):
        return slugify(value) if value else None

    # Sync functions (same as previous corrected version)
    def _sync_manufacturers(self, manufacturers, commit):
        for m in manufacturers:
            if commit:
                Manufacturer.objects.update_or_create(name=m.name, defaults={'slug': self._slug(getattr(m, "slug", None) or m.name)})

    def _sync_device_roles(self, roles, commit):
        for role in roles:
            if commit:
                DeviceRole.objects.update_or_create(name=role.name, defaults={'slug': self._slug(getattr(role, "slug", None) or role.name)})

    def _sync_platforms(self, platforms, commit):
        for p in platforms:
            if commit:
                Platform.objects.update_or_create(name=p.name, defaults={'slug': self._slug(getattr(p, "slug", None) or p.name)})

    def _sync_device_types(self, device_types, commit):
        for dt in device_types:
            if commit:
                manufacturer = Manufacturer.objects.filter(name=getattr(dt.manufacturer, "name", None)).first() if dt.manufacturer else None
                slug = self._slug(getattr(dt, "slug", None) or dt.model)
                if manufacturer:
                    DeviceType.objects.update_or_create(model=dt.model, defaults={'manufacturer': manufacturer, 'slug': slug})
                else:
                    self.log_warning(f"Skipping DeviceType {dt.model}: Manufacturer missing.")

    def _sync_module_types(self, module_types, commit):
        for mt in module_types:
            if commit:
                manufacturer = Manufacturer.objects.filter(name=getattr(mt.manufacturer, "name", None)).first() if mt.manufacturer else None
                slug = self._slug(getattr(mt, "slug", None) or mt.model)
                if manufacturer:
                    ModuleType.objects.update_or_create(model=mt.model, defaults={'manufacturer': manufacturer, 'slug': slug})
                else:
                    self.log_warning(f"Skipping ModuleType {mt.model}: Manufacturer missing.")

    def _sync_regions(self, regions, commit):
        for region in regions:
            if commit:
                Region.objects.update_or_create(name=region.name, defaults={'slug': self._slug(getattr(region, "slug", None) or region.name)})

    def _sync_site_groups(self, site_groups, commit):
        for sg in site_groups:
            if commit:
                SiteGroup.objects.update_or_create(name=sg.name, defaults={'slug': self._slug(getattr(sg, "slug", None) or sg.name)})

    def _sync_sites(self, sites, commit):
        for site in sites:
            if commit:
                region_obj = Region.objects.filter(name=getattr(site.region, "name", None)).first() if site.region else None
                Site.objects.update_or_create(name=site.name, defaults={'slug': self._slug(getattr(site, "slug", None) or site.name), 'region': region_obj})

    def _sync_locations(self, locations, commit):
        for loc in locations:
            if commit:
                site_obj = Site.objects.filter(name=getattr(loc.site, "name", None)).first() if loc.site else None
                if site_obj:
                    Location.objects.update_or_create(name=loc.name, defaults={'site': site_obj, 'slug': self._slug(getattr(loc, "slug", None) or loc.name)})
                else:
                    self.log_warning(f"Skipping Location {loc.name}: Site missing.")

    def _sync_rack_roles(self, roles, commit):
        for role in roles:
            if commit:
                RackRole.objects.update_or_create(name=role.name, defaults={'slug': self._slug(getattr(role, "slug", None) or role.name)})

    def _sync_racks(self, racks, commit):
        for rack in racks:
            if commit:
                site_obj = Site.objects.filter(name=getattr(rack.site, "name", None)).first() if rack.site else None
                slug = self._slug(getattr(rack, "slug", None) or rack.name)
                if site_obj:
                    Rack.objects.update_or_create(name=rack.name, defaults={'site': site_obj, 'slug': slug})
                else:
                    self.log_warning(f"Skipping Rack {rack.name}: Site missing.")

    def _sync_devices(self, devices, commit):
        for device in devices:
            if commit:
                site_obj = Site.objects.filter(name=getattr(device.site, "name", None)).first() if device.site else None
                dtype_obj = DeviceType.objects.filter(model=getattr(device.device_type, "model", None)).first() if device.device_type else None
                role_obj = DeviceRole.objects.filter(name=getattr(device.device_role, "name", None)).first() if getattr(device, "device_role", None) else None
                if site_obj and dtype_obj and role_obj:
                    Device.objects.update_or_create(name=device.name, defaults={'site': site_obj, 'device_type': dtype_obj, 'role': role_obj})
                else:
                    self.log_warning(f"Skipping Device {device.name}: Missing site, type, or role.")

    def _sync_modules(self, modules, commit):
        for module in modules:
            if commit:
                device_obj = Device.objects.filter(name=getattr(module.device, "name", None)).first() if module.device else None
                mtype_obj = ModuleType.objects.filter(model=getattr(module.module_type, "model", None)).first() if module.module_type else None
                if device_obj and mtype_obj:
                    Module.objects.update_or_create(name=module.name, defaults={'device': device_obj, 'module_type': mtype_obj})
                else:
                    self.log_warning(f"Skipping Module {module.name}: Missing device or module type.")

    def _sync_interfaces(self, interfaces, commit):
        for iface in interfaces:
            if commit:
                device_obj = Device.objects.filter(name=getattr(iface.device, "name", None)).first() if iface.device else None
                if device_obj:
                    Interface.objects.update_or_create(name=iface.name, defaults={'device': device_obj})
                else:
                    self.log_warning(f"Skipping Interface {iface.name}: Device missing.")

    def _sync_vrfs(self, vrfs, commit):
        for vrf in vrfs:
            if commit:
                VRF.objects.update_or_create(name=vrf.name)

    def _sync_prefixes(self, prefixes, commit):
        for prefix in prefixes:
            if commit:
                Prefix.objects.update_or_create(prefix=prefix.prefix)

    def _sync_vlan_groups(self, groups, commit):
        for group in groups:
            if commit:
                VLANGroup.objects.update_or_create(name=group.name)

    def _sync_vlans(self, vlans, commit):
        for vlan in vlans:
            if commit:
                VLAN.objects.update_or_create(vid=vlan.vid, defaults={'name': vlan.name})

    def _sync_ip_addresses(self, ips, commit):
        for ip in ips:
            if commit:
                IPAddress.objects.update_or_create(address=ip.address)

    def _sync_cluster_types(self, types, commit):
        for ct in types:
            if commit:
                ClusterType.objects.update_or_create(name=ct.name, defaults={'slug': self._slug(getattr(ct, "slug", None) or ct.name)})

    def _sync_clusters(self, clusters, commit):
        for cluster in clusters:
            if commit:
                ctype_obj = ClusterType.objects.filter(name=getattr(cluster.type, "name", None)).first() if cluster.type else None
                if ctype_obj:
                    Cluster.objects.update_or_create(name=cluster.name, defaults={'type': ctype_obj})
                else:
                    self.log_warning(f"Skipping Cluster {cluster.name}: ClusterType missing.")

    def _sync_virtual_machines(self, vms, commit):
        for vm in vms:
            if commit:
                VirtualMachine.objects.update_or_create(name=vm.name)

    def _sync_providers(self, providers, commit):
        for provider in providers:
            if commit:
                Provider.objects.update_or_create(name=provider.name, defaults={'slug': self._slug(getattr(provider, "slug", None) or provider.name)})

    def _sync_circuit_types(self, types, commit):
        for ct in types:
            if commit:
                CircuitType.objects.update_or_create(name=ct.name, defaults={'slug': self._slug(getattr(ct, "slug", None) or ct.name)})

    def _sync_circuits(self, circuits, commit):
        for circuit in circuits:
            if commit:
                provider_obj = Provider.objects.filter(name=getattr(circuit.provider, "name", None)).first() if circuit.provider else None
                ctype_obj = CircuitType.objects.filter(name=getattr(circuit.type, "name", None)).first() if circuit.type else None
                if provider_obj and ctype_obj:
                    Circuit.objects.update_or_create(cid=circuit.cid, defaults={'provider': provider_obj, 'type': ctype_obj})
                else:
                    self.log_warning(f"Skipping Circuit {circuit.cid}: Missing provider or type.")

    def _sync_wireless_lan_groups(self, groups, commit):
        for group in groups:
            if commit:
                WirelessLANGroup.objects.update_or_create(name=group.name, defaults={'slug': self._slug(getattr(group, "slug", None) or group.name)})

    def _sync_wireless_lans(self, lans, commit):
        for lan in lans:
            if commit:
                WirelessLAN.objects.update_or_create(ssid=lan.ssid)

    def _sync_tags(self, tags, commit):
        for tag in tags:
            if commit:
                Tag.objects.update_or_create(name=tag.name)

    def _sync_config_contexts(self, contexts, commit):
        for ctx in contexts:
            if commit:
                ConfigContext.objects.update_or_create(name=ctx.name)
