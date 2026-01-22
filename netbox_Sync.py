from extras.scripts import Script, StringVar, BooleanVar
import pynetbox
from django.db import transaction
from django.utils.text import slugify

# Import all relevant NetBox models
from dcim.models import (
    Region, SiteGroup, Site, Location, Rack, RackRole,
    Manufacturer, DeviceType, DeviceRole, Platform, Device,
    ModuleType, Module, Interface
)
from ipam.models import IPAddress, Prefix, VLAN, VLANGroup, VRF
from virtualization.models import VirtualMachine, Cluster, ClusterType
from circuits.models import Circuit, CircuitType, Provider
from wireless.models import WirelessLAN, WirelessLANGroup
from extras.models import ConfigContext, Tag


class FullSyncFromProduction(Script):
    class Meta:
        name = "Full Sync from Production"
        description = "Sync all major NetBox objects from production to dev environment in correct dependency order without threading."

    prod_url = StringVar(description="Production NetBox API URL", default="https://netbox.lindab.com")
    api_key = StringVar(description="API Key (first part)")
    api_token = StringVar(description="API Token (second part)")
    ca_cert_path = StringVar(description="Path to CA certificate (optional)", required=False)
    disable_ssl_verify = BooleanVar(description="Disable SSL verification (NOT recommended for production)", default=False)
    full_wipe = BooleanVar(description="Wipe all existing data before sync", default=False)

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

        self.log_info("Starting sync without threading...")

        # Define sync groups (dependency-aware)
        sync_groups = [
            [("Manufacturers", nb.dcim.manufacturers.all, self._sync_manufacturers),
             ("Device Roles", nb.dcim.device_roles.all, self._sync_device_roles),
             ("Platforms", nb.dcim.platforms.all, self._sync_platforms),
             ("Rack Roles", nb.dcim.rack_roles.all, self._sync_rack_roles),
             ("Tags", nb.extras.tags.all, self._sync_tags),
             ("Config Contexts", nb.extras.config_contexts.all, self._sync_config_contexts)],
            [("Device Types", nb.dcim.device_types.all, self._sync_device_types),
             ("Module Types", nb.dcim.module_types.all, self._sync_module_types)],
            [("Regions", nb.dcim.regions.all, self._sync_regions),
             ("Site Groups", nb.dcim.site_groups.all, self._sync_site_groups),
             ("Sites", nb.dcim.sites.all, self._sync_sites),
             ("Locations", nb.dcim.locations.all, self._sync_locations),
             ("Racks", nb.dcim.racks.all, self._sync_racks)],
            [("Devices", nb.dcim.devices.all, self._sync_devices),
             ("Modules", nb.dcim.modules.all, self._sync_modules),
             ("Interfaces", nb.dcim.interfaces.all, self._sync_interfaces)],
            [("VRFs", nb.ipam.vrfs.all, self._sync_vrfs),
             ("Prefixes", nb.ipam.prefixes.all, self._sync_prefixes),
             ("VLAN Groups", nb.ipam.vlan_groups.all, self._sync_vlan_groups),
             ("VLANs", nb.ipam.vlans.all, self._sync_vlans),
             ("IP Addresses", nb.ipam.ip_addresses.all, self._sync_ip_addresses)],
            [("Cluster Types", nb.virtualization.cluster_types.all, self._sync_cluster_types),
             ("Clusters", nb.virtualization.clusters.all, self._sync_clusters),
             ("Virtual Machines", nb.virtualization.virtual_machines.all, self._sync_virtual_machines)],
            [("Providers", nb.circuits.providers.all, self._sync_providers),
             ("Circuit Types", nb.circuits.circuit_types.all, self._sync_circuit_types),
             ("Circuits", nb.circuits.circuits.all, self._sync_circuits)],
            [("Wireless LAN Groups", nb.wireless.wireless_lan_groups.all, self._sync_wireless_lan_groups),
             ("Wireless LANs", nb.wireless.wireless_lans.all, self._sync_wireless_lans)]
        ]

        # Execute groups sequentially with transaction batching
        for group in sync_groups:
            with transaction.atomic():
                for name, fetch, func in group:
                    try:
                        self.log_info(f"Syncing {name}...")
                        records = fetch()
                        func(records, commit)
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

    # Bulk sync for independent objects
    def _sync_manufacturers(self, manufacturers, commit):
        if commit:
            objs = [Manufacturer(name=m.name, slug=self._slug(getattr(m, "slug", None) or m.name)) for m in manufacturers]
            Manufacturer.objects.bulk_create(objs, ignore_conflicts=True)

    def _sync_device_roles(self, roles, commit):
        if commit:
            objs = [DeviceRole(name=r.name, slug=self._slug(getattr(r, "slug", None) or r.name)) for r in roles]
            DeviceRole.objects.bulk_create(objs, ignore_conflicts=True)

    def _sync_platforms(self, platforms, commit):
        if commit:
            objs = [Platform(name=p.name, slug=self._slug(getattr(p, "slug", None) or p.name)) for p in platforms]
            Platform.objects.bulk_create(objs, ignore_conflicts=True)

    def _sync_rack_roles(self, roles, commit):
        if commit:
            objs = [RackRole(name=r.name, slug=self._slug(getattr(r, "slug", None) or r.name)) for r in roles]
            RackRole.objects.bulk_create(objs, ignore_conflicts=True)

    def _sync_tags(self, tags, commit):
        if commit:
            objs = [Tag(name=t.name) for t in tags]
            Tag.objects.bulk_create(objs, ignore_conflicts=True)

    def _sync_config_contexts(self, contexts, commit):
        if commit:
            objs = [ConfigContext(name=c.name) for c in contexts]
            ConfigContext.objects.bulk_create(objs, ignore_conflicts=True)

    # Foreign key-dependent objects use update_or_create
    def _sync_device_types(self, device_types, commit):
        for dt in device_types:
            if commit:
                manufacturer = Manufacturer.objects.filter(name=getattr(dt.manufacturer, "name", None)).first()
                if manufacturer:
                    DeviceType.objects.update_or_create(model=dt.model, defaults={'manufacturer': manufacturer, 'slug': self._slug(dt.model)})

    def _sync_module_types(self, module_types, commit):
        for mt in module_types:
            if commit:
                manufacturer = Manufacturer.objects.filter(name=getattr(mt.manufacturer, "name", None)).first()
                if manufacturer:
                    ModuleType.objects.update_or_create(model=mt.model, defaults={'manufacturer': manufacturer, 'slug': self._slug(mt.model)})

    def _sync_regions(self, regions, commit):
        for region in regions:
            if commit:
                Region.objects.update_or_create(name=region.name, defaults={'slug': self._slug(region.name)})

    def _sync_site_groups(self, site_groups, commit):
        for sg in site_groups:
            if commit:
                SiteGroup.objects.update_or_create(name=sg.name, defaults={'slug': self._slug(sg.name)})

    def _sync_sites(self, sites, commit):
        for site in sites:
            if commit:
                region_obj = Region.objects.filter(name=getattr(site.region, "name", None)).first()
                Site.objects.update_or_create(name=site.name, defaults={'slug': self._slug(site.name), 'region': region_obj})

    def _sync_locations(self, locations, commit):
        for loc in locations:
            if commit:
                site_obj = Site.objects.filter(name=getattr(loc.site, "name", None)).first()
                if site_obj:
                    Location.objects.update_or_create(name=loc.name, defaults={'site': site_obj, 'slug': self._slug(loc.name)})

    def _sync_racks(self, racks, commit):
        for rack in racks:
            if commit:
                site_obj = Site.objects.filter(name=getattr(rack.site, "name", None)).first()
                if site_obj:
                    Rack.objects.update_or_create(name=rack.name, defaults={'site': site_obj, 'slug': self._slug(rack.name)})

    def _sync_devices(self, devices, commit):
        for device in devices:
            if commit:
                site_obj = Site.objects.filter(name=getattr(device.site, "name", None)).first()
                dtype_obj = DeviceType.objects.filter(model=getattr(device.device_type, "model", None)).first()
                role_obj = DeviceRole.objects.filter(name=getattr(device.device_role, "name", None)).first()
                if site_obj and dtype_obj and role_obj:
                    Device.objects.update_or_create(name=device.name, defaults={'site': site_obj, 'device_type': dtype_obj, 'role': role_obj})

    def _sync_modules(self, modules, commit):
        for module in modules:
            if commit:
                device_obj = Device.objects.filter(name=getattr(module.device, "name", None)).first()
                mtype_obj = ModuleType.objects.filter(model=getattr(module.module_type, "model", None)).first()
                if device_obj and mtype_obj:
                    Module.objects.update_or_create(name=module.name, defaults={'device': device_obj, 'module_type': mtype_obj})

    def _sync_interfaces(self, interfaces, commit):
        for iface in interfaces:
            if commit:
                device_obj = Device.objects.filter(name=getattr(iface.device, "name", None)).first()
                if device_obj:
                    Interface.objects.update_or_create(name=iface.name, defaults={'device': device_obj})

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
                ClusterType.objects.update_or_create(name=ct.name, defaults={'slug': self._slug(ct.name)})

    def _sync_clusters(self, clusters, commit):
        for cluster in clusters:
            if commit:
                ctype_obj = ClusterType.objects.filter(name=getattr(cluster.type, "name", None)).first()
                if ctype_obj:
                    Cluster.objects.update_or_create(name=cluster.name, defaults={'type': ctype_obj})

    def _sync_virtual_machines(self, vms, commit):
        for vm in vms:
            if commit:
                VirtualMachine.objects.update_or_create(name=vm.name)

    def _sync_providers(self, providers, commit):
        for provider in providers:
            if commit:
                Provider.objects.update_or_create(name=provider.name, defaults={'slug': self._slug(provider.name)})

    def _sync_circuit_types(self, types, commit):
        for ct in types:
            if commit:
                CircuitType.objects.update_or_create(name=ct.name, defaults={'slug': self._slug(ct.name)})

    def _sync_circuits(self, circuits, commit):
        for circuit in circuits:
            if commit:
                provider_obj = Provider.objects.filter(name=getattr(circuit.provider, "name", None)).first()
                ctype_obj = CircuitType.objects.filter(name=getattr(circuit.type, "name", None)).first()
                if provider_obj and ctype_obj:
                    Circuit.objects.update_or_create(cid=circuit.cid, defaults={'provider': provider_obj, 'type': ctype_obj})

    def _sync_wireless_lan_groups(self, groups, commit):
        for group in groups:
            if commit:
                WirelessLANGroup.objects.update_or_create(name=group.name, defaults={'slug': self._slug(group.name)})

    def _sync_wireless_lans(self, lans, commit):
        for lan in lans:
            if commit:
                WirelessLAN.objects.update_or_create(ssid=lan.ssid)
