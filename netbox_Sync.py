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
        description = "Sync all major NetBox objects from production to this environment in dependency order."
        commit_default = False  # safer default

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

    def run(self, data, commit):
        # Build token and connect to prod
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

        # Full wipe of local data (dev/test) if requested
        if data["full_wipe"] and commit:
            self.log_warning("Performing FULL WIPE of this environment...")
            with transaction.atomic():
                self._wipe_models(
                    [
                        # Order matters: children before parents
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
                        IPAddress,
                        Prefix,
                        VLAN,
                        VLANGroup,
                        VRF,
                        VirtualMachine,
                        Cluster,
                        ClusterType,
                        Circuit,
                        CircuitType,
                        Provider,
                        WirelessLAN,
                        WirelessLANGroup,
                        ConfigContext,
                        Tag,
                    ]
                )
            self.log_success("Full wipe completed.")

        self.log_info("Starting full sync (per-model transactions, no threading)...")

        #
        # Sync order – structured by dependency
        #
        sync_plan = [
            # Independent-ish taxonomy
            ("Manufacturers", nb.dcim.manufacturers.all, self._sync_manufacturers),
            ("Device Roles", nb.dcim.device_roles.all, self._sync_device_roles),
            ("Platforms", nb.dcim.platforms.all, self._sync_platforms),
            ("Rack Roles", nb.dcim.rack_roles.all, self._sync_rack_roles),
            ("Tags", nb.extras.tags.all, self._sync_tags),
            ("Config Contexts", nb.extras.config_contexts.all, self._sync_config_contexts),

            # Hardware types
            ("Device Types", nb.dcim.device_types.all, self._sync_device_types),
            ("Module Types", nb.dcim.module_types.all, self._sync_module_types),

            # Geography / locations / racks
            ("Regions", nb.dcim.regions.all, self._sync_regions),
            ("Site Groups", nb.dcim.site_groups.all, self._sync_site_groups),
            ("Sites", nb.dcim.sites.all, self._sync_sites),
            ("Locations", nb.dcim.locations.all, self._sync_locations),
            ("Racks", nb.dcim.racks.all, self._sync_racks),

            # Physical devices & components
            ("Devices", nb.dcim.devices.all, self._sync_devices),
            ("Modules", nb.dcim.modules.all, self._sync_modules),
            ("Interfaces", nb.dcim.interfaces.all, self._sync_interfaces),

            # IPAM
            ("VRFs", nb.ipam.vrfs.all, self._sync_vrfs),
            ("Prefixes", nb.ipam.prefixes.all, self._sync_prefixes),
            ("VLAN Groups", nb.ipam.vlan_groups.all, self._sync_vlan_groups),
            ("VLANs", nb.ipam.vlans.all, self._sync_vlans),
            ("IP Addresses", nb.ipam.ip_addresses.all, self._sync_ip_addresses),

            # Virtualization
            ("Cluster Types", nb.virtualization.cluster_types.all, self._sync_cluster_types),
            ("Clusters", nb.virtualization.clusters.all, self._sync_clusters),
            ("Virtual Machines", nb.virtualization.virtual_machines.all, self._sync_virtual_machines),

            # Circuits
            ("Providers", nb.circuits.providers.all, self._sync_providers),
            ("Circuit Types", nb.circuits.circuit_types.all, self._sync_circuit_types),
            ("Circuits", nb.circuits.circuits.all, self._sync_circuits),

            # Wireless
            ("Wireless LAN Groups", nb.wireless.wireless_lan_groups.all, self._sync_wireless_lan_groups),
            ("Wireless LANs", nb.wireless.wireless_lans.all, self._sync_wireless_lans),
        ]

        # Execute each sync in its own transaction so one failure doesn't poison others
        for name, fetch, func in sync_plan:
            self.log_info(f"Syncing {name}...")
            try:
                records = fetch()
                if commit:
                    with transaction.atomic():
                        func(records, commit)
                else:
                    # Just iterate to ensure API access works; skip DB writes
                    list(records)
                self.log_success(f"{name} synced successfully.")
            except Exception as e:
                self.log_failure(f"Failed to sync {name}: {e}")

        self.log_success("Full sync completed.")

    #
    # Helpers
    #

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
    # Sync implementations
    #

    # --- Basic taxonomies -------------------------------------------------

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
        """
        DeviceRole uses a tree structure (with 'level' etc.), so we must
        use update_or_create (not bulk_create) to let Django/NetBox manage it.
        """
        if not commit:
            return
        for r in roles:
            defaults = {
                "slug": self._slug(getattr(r, "slug", None) or r.name),
            }
            # Parent, color, vm_role, config_template, etc. can be added if needed
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

    # --- Types ------------------------------------------------------------

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

    # --- Geography / Sites / Racks ---------------------------------------

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
        """
        In newer NetBox versions, Rack has no 'slug' field, so we do not set it.
        """
        if not commit:
            return
        for r in racks:
            site_name = getattr(getattr(r, "site", None), "name", None)
            site_obj = Site.objects.filter(name=site_name).first()
            if not site_obj:
                continue

            # Optional: resolve role and location if present
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

    # --- Devices / Modules / Interfaces ----------------------------------

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

            # Optional: map rack, position, face, status etc. if you want
            Rack.objects.filter(
                name=getattr(getattr(d, "rack", None), "name", None)
            )

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

    # --- IPAM -------------------------------------------------------------

    def _sync_vrfs(self, vrfs, commit):
        if not commit:
            return
        for vrf in vrfs:
            VRF.objects.update_or_create(
                name=vrf.name,
                defaults={},
            )

    def _sync_prefixes(self, prefixes, commit):
        if not commit:
            return
        for p in prefixes:
            Prefix.objects.update_or_create(
                prefix=p.prefix,
                defaults={},
            )

    def _sync_vlan_groups(self, groups, commit):
        if not commit:
            return
        for g in groups:
            VLANGroup.objects.update_or_create(
                name=g.name,
                defaults={},
            )

    def _sync_vlans(self, vlans, commit):
        if not commit:
            return
        for v in vlans:
            VLAN.objects.update_or_create(
                vid=v.vid,
                defaults={
                    "name": v.name,
                },
            )

    def _sync_ip_addresses(self, ips, commit):
        if not commit:
            return
        for ip in ips:
            IPAddress.objects.update_or_create(
                address=ip.address,
                defaults={},
            )

    # --- Virtualization ---------------------------------------------------

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
            # Minimal mapping – can be expanded (cluster, status, etc.)
            Cluster.objects.filter(
                name=getattr(getattr(vm, "cluster", None), "name", None)
            )
            VirtualMachine.objects.update_or_create(
                name=vm.name,
                defaults={},
            )

    # --- Circuits ---------------------------------------------------------

    def _sync_providers(self, providers, commit):
        if not commit:
            return
        for p in providers:
            Provider.objects.update_or_create(
                name=p.name,
                defaults={
                    "slug": self._slug(p.name),
                },
            )

    def _sync_circuit_types(self, types, commit):
        if not commit:
            return
        for ct in types:
            CircuitType.objects.update_or_create(
                name=ct.name,
                defaults={
                    "slug": self._slug(ct.name),
                },
            )

    def _sync_circuits(self, circuits, commit):
        if not commit:
            return
        for c in circuits:
            provider_name = getattr(getattr(c, "provider", None), "name", None)
            provider_obj = Provider.objects.filter(name=provider_name).first()

            ctype_name = getattr(getattr(c, "type", None), "name", None)
            ctype_obj = CircuitType.objects.filter(name=ctype_name).first()

            if not (provider_obj and ctype_obj):
                continue

            Circuit.objects.update_or_create(
                cid=c.cid,
                defaults={
                    "provider": provider_obj,
                    "type": ctype_obj,
                },
            )

    # --- Wireless ---------------------------------------------------------

    def _sync_wireless_lan_groups(self, groups, commit):
        if not commit:
            return
        for g in groups:
            WirelessLANGroup.objects.update_or_create(
                name=g.name,
                defaults={
                    "slug": self._slug(g.name),
                },
            )

    def _sync_wireless_lans(self, lans, commit):
        if not commit:
            return
        for lan in lans:
            group_name = getattr(getattr(lan, "group", None), "name", None)
            group_obj = WirelessLANGroup.objects.filter(name=group_name).first() if group_name else None
            WirelessLAN.objects.update_or_create(
                ssid=lan.ssid,
                defaults={
                    "group": group_obj,
                },
            )
