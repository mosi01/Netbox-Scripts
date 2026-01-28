from extras.scripts import Script, StringVar, BooleanVar, IntegerVar
import pynetbox
from django.db import transaction
from django.utils.text import slugify

from dcim.models import (
    Region, SiteGroup, Site, Location, Rack, RackRole,
    Manufacturer, DeviceType, DeviceRole, Platform, Device,
    ModuleType, Module, Interface
)
from virtualization.models import VirtualMachine, Cluster, ClusterType
from extras.models import ConfigContext, Tag

class TestSyncFromProduction(Script):
    class Meta:
        name = "Test Sync from Production (Sample Only)"
        description = (
            "Sync a limited sample of objects from production: "
            "N devices and N virtual machines plus their related DCIM/virtualization resources."
        )
        commit_default = False

    prod_url = StringVar(
        description="Production NetBox API URL",
        default="https://netbox.domain.com",
    )
    api_key = StringVar(
        description="API Key (first part)"
    )
    api_token = StringVar(
        description="API Token (second part)"
    )
    ca_cert_path = StringVar(
        description="Path to CA certificate (optional)",
        required=False,
    )
    disable_ssl_verify = BooleanVar(
        description="Disable SSL verification (NOT recommended for production)",
        default=False,
    )
    full_wipe = BooleanVar(
        description="Wipe all existing data in this environment before sync",
        default=False,
    )

    device_limit = IntegerVar(
        description="Number of devices to sync (sample size)",
        default=10,
    )
    vm_limit = IntegerVar(
        description="Number of virtual machines to sync (sample size)",
        default=10,
    )

    #
    # Helper
    #
    def _get_sample(self, queryset, limit):
        """
        Returnerar de första `limit` objekten från en pynetbox-queryset
        utan att iterera igenom hela API-resursen *logiskt*.
        (Pynetbox kan fortfarande hämta en sida i taget internt, men vi
        begränsar vilka objekt vi använder.)
        """
        results = []
        for idx, obj in enumerate(queryset):
            if idx >= limit:
                break
            results.append(obj)
        return results

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

    #
    # Main
    #

    def run(self, data, commit):
        full_token = f"nbt_{data['api_key']}.{data['api_token']}"
        self.log_info(f"Connecting to production NetBox API at {data['prod_url']}...")
        nb = pynetbox.api(data["prod_url"], token=full_token)

        # SSL handling
        if data["disable_ssl_verify"]:
            self.log_warning("SSL verification is DISABLED. This is insecure!")
            nb.http_session.verify = False
        elif data.get("ca_cert_path"):
            nb.http_session.verify = data["ca_cert_path"]
        else:
            nb.http_session.verify = True

        # Full wipe if requested
        if data["full_wipe"] and commit:
            self.log_warning("Performing FULL WIPE of this environment (test script)...")
            with transaction.atomic():
                self._wipe_models(
                    [
                        Interface,
                        Module,
                        Device,
                        DeviceType,
                        ModuleType,
                        Rack,
                        Location,
                        Site,
                        SiteGroup,
                        Region,
                        RackRole,
                        DeviceRole,
                        Platform,
                        Manufacturer,
                        VirtualMachine,
                        Cluster,
                        ClusterType,
                        ConfigContext,
                        Tag,
                    ]
                )
            self.log_success("Full wipe completed.")

        self.log_info("Fetching sample objects from production...")

        # Läs in värden från formuläret
        device_limit = int(data.get("device_limit") or 10)
        vm_limit = int(data.get("vm_limit") or 10)
        self.log_info(f"Requested limits from form: devices={device_limit}, vms={vm_limit}")

        # Hämta endast de första N devices och N VMs
        # OBS: ingen filter(limit=...) här längre
        all_devices_qs = nb.dcim.devices.all()
        all_vms_qs = nb.virtualization.virtual_machines.all()

        sample_devices = self._get_sample(all_devices_qs, device_limit)
        sample_vms = self._get_sample(all_vms_qs, vm_limit)

        # Sanity-check
        if len(sample_devices) > device_limit or len(sample_vms) > vm_limit:
            self.log_warning(
                f"Sample size exceeded requested limit(s)! "
                f"(devices={len(sample_devices)}/{device_limit}, "
                f"vms={len(sample_vms)}/{vm_limit})"
            )

        self.log_info(f"Sample size: {len(sample_devices)} devices, {len(sample_vms)} virtual machines.")

        #
        # Build related-resource sets from the samples
        #

        # Manufacturers, device types, roles, platforms
        remote_device_types = []
        remote_manufacturers = []
        remote_device_roles = []
        remote_platforms = []

        # Sites, locations, racks, regions, site groups
        remote_sites = []
        remote_locations = []
        remote_racks = []
        remote_regions = []
        remote_site_groups = []

        for d in sample_devices:
            # Device type
            dt = getattr(d, "device_type", None)
            if dt and not any(x.id == dt.id for x in remote_device_types):
                remote_device_types.append(dt)
            # Manufacturer
            man = getattr(dt, "manufacturer", None) if dt else None
            if man and not any(x.id == man.id for x in remote_manufacturers):
                remote_manufacturers.append(man)
            # Role
            role = getattr(d, "role", None)
            if role and not any(x.id == role.id for x in remote_device_roles):
                remote_device_roles.append(role)
            # Platform
            platform = getattr(d, "platform", None)
            if platform and not any(x.id == platform.id for x in remote_platforms):
                remote_platforms.append(platform)
            # Site
            site = getattr(d, "site", None)
            if site and not any(x.id == site.id for x in remote_sites):
                remote_sites.append(site)
            # Location
            location = getattr(d, "location", None)
            if location and not any(x.id == location.id for x in remote_locations):
                remote_locations.append(location)
            # Rack
            rack = getattr(d, "rack", None)
            if rack and not any(x.id == rack.id for x in remote_racks):
                remote_racks.append(rack)

        # Regions & site groups from sites
        for s in remote_sites:
            region = getattr(s, "region", None)
            if region and not any(x.id == region.id for x in remote_regions):
                remote_regions.append(region)
            site_group = getattr(s, "group", None)
            if site_group and not any(x.id == site_group.id for x in remote_site_groups):
                remote_site_groups.append(site_group)

        # Config contexts & tags (global, just take a small sample)
        remote_tags = list(nb.extras.tags.filter(limit=50))
        remote_config_contexts = list(nb.extras.config_contexts.filter(limit=50))

        # Modules and interfaces for the sample devices
        remote_modules = []
        remote_interfaces = []

        if sample_devices:
            # Fetch modules/interfaces per device (small numbers -> OK)
            for d in sample_devices:
                dev_modules = list(nb.dcim.modules.filter(device_id=d.id))
                for m in dev_modules:
                    if not any(x.id == m.id for x in remote_modules):
                        remote_modules.append(m)

                dev_ifaces = list(nb.dcim.interfaces.filter(device_id=d.id))
                for iface in dev_ifaces:
                    if not any(x.id == iface.id for x in remote_interfaces):
                        remote_interfaces.append(iface)

        # Virtualization: cluster types, clusters from VMs
        remote_cluster_types = []
        remote_clusters = []
        remote_vm_sites = []

        for vm in sample_vms:
            cluster = getattr(vm, "cluster", None)
            if cluster and not any(x.id == cluster.id for x in remote_clusters):
                remote_clusters.append(cluster)
            ctype = getattr(cluster, "type", None) if cluster else None
            if ctype and not any(x.id == ctype.id for x in remote_cluster_types):
                remote_cluster_types.append(ctype)
            site = getattr(vm, "site", None)
            if site and not any(x.id == site.id for x in remote_vm_sites):
                remote_vm_sites.append(site)

        # Merge VM sites into site list
        for s in remote_vm_sites:
            if not any(x.id == s.id for x in remote_sites):
                remote_sites.append(s)
            region = getattr(s, "region", None)
            if region and not any(x.id == region.id for x in remote_regions):
                remote_regions.append(region)
            site_group = getattr(s, "group", None)
            if site_group and not any(x.id == site_group.id for x in remote_site_groups):
                remote_site_groups.append(site_group)

        self.log_info(
            f"Will sync: "
            f"{len(remote_manufacturers)} manufacturers, "
            f"{len(remote_device_roles)} device roles, "
            f"{len(remote_platforms)} platforms, "
            f"{len(remote_device_types)} device types, "
            f"{len(remote_regions)} regions, "
            f"{len(remote_site_groups)} site groups, "
            f"{len(remote_sites)} sites, "
            f"{len(remote_locations)} locations, "
            f"{len(remote_racks)} racks, "
            f"{len(sample_devices)} devices, "
            f"{len(remote_modules)} modules, "
            f"{len(remote_interfaces)} interfaces, "
            f"{len(remote_cluster_types)} cluster types, "
            f"{len(remote_clusters)} clusters, "
            f"{len(sample_vms)} VMs."
        )

        #
        # Sync in dependency order
        #

        sync_plan = [
            ("Manufacturers", remote_manufacturers, self._sync_manufacturers),
            ("Device Roles", remote_device_roles, self._sync_device_roles),
            ("Platforms", remote_platforms, self._sync_platforms),
            ("Rack Roles", [], self._sync_rack_roles),  # none selected, but function is same
            ("Tags", remote_tags, self._sync_tags),
            ("Config Contexts", remote_config_contexts, self._sync_config_contexts),

            ("Device Types", remote_device_types, self._sync_device_types),
            ("Module Types", [], self._sync_module_types),  # only if you want to derive; left empty here

            ("Regions", remote_regions, self._sync_regions),
            ("Site Groups", remote_site_groups, self._sync_site_groups),
            ("Sites", remote_sites, self._sync_sites),
            ("Locations", remote_locations, self._sync_locations),
            ("Racks", remote_racks, self._sync_racks),

            ("Devices", sample_devices, self._sync_devices),
            ("Modules", remote_modules, self._sync_modules),
            ("Interfaces", remote_interfaces, self._sync_interfaces),

            ("Cluster Types", remote_cluster_types, self._sync_cluster_types),
            ("Clusters", remote_clusters, self._sync_clusters),
            ("Virtual Machines", sample_vms, self._sync_virtual_machines),
        ]

        for name, records, func in sync_plan:
            self.log_info(f"Syncing {name}...")
            try:
                if commit:
                    with transaction.atomic():
                        func(records, commit)
                self.log_success(f"{name} synced successfully.")
            except Exception as e:
                self.log_failure(f"Failed to sync {name}: {e}")

        self.log_success("Test sample sync completed.")

    #
    # Sync methods (oförändrade)
    #

    def _sync_manufacturers(self, manufacturers, commit):
        if not commit:
            return
        for m in manufacturers:
            Manufacturer.objects.update_or_create(
                name=m.name,
                defaults={
                    "slug": self._slug(getattr(m, "slug", None) or m.name),
                },
            )

    def _sync_device_roles(self, roles, commit):
        if not commit:
            return
        for r in roles:
            defaults = {
                "slug": self._slug(getattr(r, "slug", None) or r.name),
            }
            DeviceRole.objects.update_or_create(
                name=r.name,
                defaults=defaults,
            )

    def _sync_platforms(self, platforms, commit):
        if not commit:
            return
        for p in platforms:
            Platform.objects.update_or_create(
                name=p.name,
                defaults={
                    "slug": self._slug(getattr(p, "slug", None) or p.name),
                },
            )

    def _sync_rack_roles(self, roles, commit):
        if not commit:
            return
        for r in roles:
            RackRole.objects.update_or_create(
                name=r.name,
                defaults={
                    "slug": self._slug(getattr(r, "slug", None) or r.name),
                },
            )

    def _sync_tags(self, tags, commit):
        if not commit:
            return
        for t in tags:
            Tag.objects.update_or_create(
                name=t.name,
                defaults={},
            )

    def _sync_config_contexts(self, contexts, commit):
        if not commit:
            return
        for c in contexts:
            ConfigContext.objects.update_or_create(
                name=c.name,
                defaults={},
            )

    def _sync_device_types(self, device_types, commit):
        if not commit:
            return
        for dt in device_types:
            manufacturer_name = getattr(getattr(dt, "manufacturer", None), "name", None)
            manufacturer = Manufacturer.objects.filter(name=manufacturer_name).first()
            if not manufacturer:
                continue
            DeviceType.objects.update_or_create(
                model=dt.model,
                defaults={
                    "manufacturer": manufacturer,
                    "slug": self._slug(dt.model),
                },
            )

    def _sync_module_types(self, module_types, commit):
        if not commit:
            return
        for mt in module_types:
            manufacturer_name = getattr(getattr(mt, "manufacturer", None), "name", None)
            manufacturer = Manufacturer.objects.filter(name=manufacturer_name).first()
            if not manufacturer:
                continue
            ModuleType.objects.update_or_create(
                model=mt.model,
                defaults={
                    "manufacturer": manufacturer,
                    "slug": self._slug(mt.model),
                },
            )

    def _sync_regions(self, regions, commit):
        if not commit:
            return
        for r in regions:
            Region.objects.update_or_create(
                name=r.name,
                defaults={
                    "slug": self._slug(r.name),
                },
            )

    def _sync_site_groups(self, site_groups, commit):
        if not commit:
            return
        for sg in site_groups:
            SiteGroup.objects.update_or_create(
                name=sg.name,
                defaults={
                    "slug": self._slug(sg.name),
                },
            )

    def _sync_sites(self, sites, commit):
        if not commit:
            return
        for s in sites:
            region_name = getattr(getattr(s, "region", None), "name", None)
            region_obj = Region.objects.filter(name=region_name).first()
            Site.objects.update_or_create(
                name=s.name,
                defaults={
                    "slug": self._slug(s.name),
                    "region": region_obj,
                },
            )

    def _sync_locations(self, locations, commit):
        if not commit:
            return
        for loc in locations:
            site_name = getattr(getattr(loc, "site", None), "name", None)
            site_obj = Site.objects.filter(name=site_name).first()
            if not site_obj:
                continue
            Location.objects.update_or_create(
                name=loc.name,
                defaults={
                    "site": site_obj,
                    "slug": self._slug(loc.name),
                },
            )

    def _sync_racks(self, racks, commit):
        if not commit:
            return
        for r in racks:
            site_name = getattr(getattr(r, "site", None), "name", None)
            site_obj = Site.objects.filter(name=site_name).first()
            if not site_obj:
                continue

            role_name = getattr(getattr(r, "role", None), "name", None)
            role_obj = RackRole.objects.filter(name=role_name).first() if role_name else None

            location_name = getattr(getattr(r, "location", None), "name", None)
            location_obj = Location.objects.filter(name=location_name, site=site_obj).first() if location_name else None

            Rack.objects.update_or_create(
                name=r.name,
                defaults={
                    "site": site_obj,
                    "role": role_obj,
                    "location": location_obj,
                },
            )

    def _sync_devices(self, devices, commit):
        if not commit:
            return
        for d in devices:
            site_name = getattr(getattr(d, "site", None), "name", None)
            site_obj = Site.objects.filter(name=site_name).first()

            dtype_model = getattr(getattr(d, "device_type", None), "model", None)
            dtype_obj = DeviceType.objects.filter(model=dtype_model).first()

            role_name = getattr(getattr(d, "role", None), "name", None)
            role_obj = DeviceRole.objects.filter(name=role_name).first()

            platform_name = getattr(getattr(d, "platform", None), "name", None)
            platform_obj = Platform.objects.filter(name=platform_name).first() if platform_name else None

            if not (site_obj and dtype_obj and role_obj):
                continue

            defaults = {
                "site": site_obj,
                "device_type": dtype_obj,
                "role": role_obj,
            }
            if platform_obj:
                defaults["platform"] = platform_obj

            Device.objects.update_or_create(
                name=d.name,
                defaults=defaults,
            )

    def _sync_modules(self, modules, commit):
        if not commit:
            return
        for m in modules:
            device_name = getattr(getattr(m, "device", None), "name", None)
            device_obj = Device.objects.filter(name=device_name).first()

            mtype_model = getattr(getattr(m, "module_type", None), "model", None)
            mtype_obj = ModuleType.objects.filter(model=mtype_model).first()

            if not (device_obj and mtype_obj):
                continue

            Module.objects.update_or_create(
                name=m.name,
                defaults={
                    "device": device_obj,
                    "module_type": mtype_obj,
                },
            )

    def _sync_interfaces(self, interfaces, commit):
        if not commit:
            return
        for iface in interfaces:
            device_name = getattr(getattr(iface, "device", None), "name", None)
            device_obj = Device.objects.filter(name=device_name).first()
            if not device_obj:
                continue

            Interface.objects.update_or_create(
                name=iface.name,
                defaults={
                    "device": device_obj,
                },
            )

    def _sync_cluster_types(self, types, commit):
        if not commit:
            return
        for ct in types:
            ClusterType.objects.update_or_create(
                name=ct.name,
                defaults={
                    "slug": self._slug(ct.name),
                },
            )

    def _sync_clusters(self, clusters, commit):
        if not commit:
            return
        for c in clusters:
            ctype_name = getattr(getattr(c, "type", None), "name", None)
            ctype_obj = ClusterType.objects.filter(name=ctype_name).first()
            Cluster.objects.update_or_create(
                name=c.name,
                defaults={
                    "type": ctype_obj,
                },
            )

    def _sync_virtual_machines(self, vms, commit):
        if not commit:
            return
        for vm in vms:
            VirtualMachine.objects.update_or_create(
                name=vm.name,
                defaults={},
            )
