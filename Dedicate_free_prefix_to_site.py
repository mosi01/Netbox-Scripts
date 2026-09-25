"""
dedicate_free_prefix_to_site.py

NetBox Custom Script (NetBox v4.6.4)

Functionality
-------------
- Select a Site.
- Resolve a fixed list of VLANs by exact VLAN ID and VLAN name.
- Allocate fixed /24 prefixes for VLANs 570 and 590.
- Allocate all other VLAN prefixes sequentially from the first IPv4 /18
  tagged "free-prefix".
- Create or reuse a VRF named after the selected Site.

Container-based allocation order
--------------------------------
The following VLANs receive sequential /24 prefixes from the selected /18,
in this exact order:

1.  400-Client
2.  401-Client-WL
3.  410-Printers
4.  430-Security
5.  431-Security-Attendance
6.  432-Security-CCTV
7.  450-Server
8.  460-MGMT
9.  461-MGMT-AP
10. 302-Client-WMS-WL

Fixed site-VRF prefixes
-----------------------
- VLAN 570-IoT:
    192.168.70.0/24
- VLAN 590-Guest:
    192.168.90.0/24

Created-prefix attributes
-------------------------
- Status: Active
- Tenant: Lindab Group (Fortinet)
- Scope: Selected Site
- VLAN: Fixed VLAN object
- Description: VLAN <ID> - <VLAN name>

VRF assignment
--------------
- Container-based prefixes use the "Lindab Group" VRF.
- VLANs 570 and 590 use a VRF named after the selected Site.
- The site VRF is created if it does not already exist.

Container dedication
--------------------
- The first IPv4 /18 tagged "free-prefix" is selected.
- The container is assigned to the selected Site.
- The container is assigned to the "Lindab Group" VRF.
- The container description is cleared.
- The "free-prefix" tag is removed.
- The container status is set to Reserved.

Requirements
------------
The following objects must already exist:

- VRF: Lindab Group
- Role: Client Network
- Tenant: Lindab Group (Fortinet)
- Every VLAN listed in FIXED_VLAN_DEFINITIONS
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Tuple

from django.db import transaction
from netaddr import IPNetwork

from dcim.models import Site
from extras.models import Tag
from extras.scripts import ObjectVar, Script
from ipam.models import Prefix, Role, VLAN, VRF
from tenancy.models import Tenant
from utilities.exceptions import AbortScript


@dataclass(frozen=True)
class VLANDefinition:
    """Static definition of a VLAN processed by the script."""
    
    vid: int
    name: str
    role_name: str
    fixed_prefix: Optional[str] = None
    use_site_vrf: bool = False


@dataclass(frozen=True)
class PlannedPrefix:
    """A planned prefix allocation for a VLAN."""

    vlan: VLAN
    prefix: IPNetwork
    role: Role
    tenant: Tenant
    use_site_vrf: bool
    allocation_order: int


class DedicateFreePrefixToSite(Script):
    """
    Dedicate a free /18 to a Site and create the standard Site VLAN prefixes.
    """

    site = ObjectVar(
        model=Site,
        label="Site",
        description=(
            "Select the Site that should own the prefixes. "
            "VLANs 570 and 590 use a VRF named after this Site."
        ),
        selector=True,
    )

    class Meta:
        name = "Dedicate free /18 and create standard Site prefixes"
        description = (
            "Create the standard Site VLAN prefixes using a free /18, "
            "plus the fixed prefixes for VLANs 570 and 590."
        )
        fieldsets = (
            ("Target", ("site",)),
        )

    LINDAB_GROUP_VRF_NAME = "Lindab Group"
    TENANT_NAME = "Lindab Group (Fortinet)"

    FIXED_VLAN_DEFINITIONS: Tuple[VLANDefinition, ...] = (
        VLANDefinition(
            vid=400,
            name="400-Client",
            role_name="Client Network",
        ),
        VLANDefinition(
            vid=401,
            name="401-Client-WL",
            role_name="Client Network",
        ),
        VLANDefinition(
            vid=410,
            name="410-Printers",
            role_name="Printer Network",
        ),
        VLANDefinition(
            vid=430,
            name="430-Security",
            role_name="Security Network",
        ),
        VLANDefinition(
            vid=431,
            name="431-Security-Attendance",
            role_name="Security Network",
        ),
        VLANDefinition(
            vid=432,
            name="432-Security-CCTV",
            role_name="Security Network",
        ),
        VLANDefinition(
            vid=450,
            name="450-Server",
            role_name="Server Network",
        ),
        VLANDefinition(
            vid=460,
            name="460-MGMT",
            role_name="Management Network",
        ),
        VLANDefinition(
            vid=461,
            name="461-MGMT-AP",
            role_name="Management Network",
        ),
        VLANDefinition(
            vid=302,
            name="302-Client-WMS-WL",
            role_name="WMS",
        ),
        VLANDefinition(
            vid=570,
            name="570-IoT",
            role_name="IoT Network",
            fixed_prefix="192.168.70.0/24",
            use_site_vrf=True,
        ),
        VLANDefinition(
            vid=590,
            name="590-Guest",
            role_name="Guest Network",
            fixed_prefix="192.168.90.0/24",
            use_site_vrf=True,
        ),
    )

    def run(self, data, commit):
        site: Site = data["site"]

        lindab_vrf = self._get_required_vrf(
            self.LINDAB_GROUP_VRF_NAME
        )
        roles_by_name = self._get_required_roles()
        tenant = self._get_required_tenant(self.TENANT_NAME)
        site_vrf = self._get_site_vrf(site)

        resolved_vlans = self._resolve_fixed_vlans()

        container_definitions = [
            definition
            for definition in self.FIXED_VLAN_DEFINITIONS
            if definition.fixed_prefix is None
        ]

        fixed_definitions = [
            definition
            for definition in self.FIXED_VLAN_DEFINITIONS
            if definition.fixed_prefix is not None
        ]

        container = self._get_first_free_container()
        container_net = IPNetwork(str(container.prefix))

        if container_net.version != 4 or container_net.prefixlen != 18:
            raise AbortScript(
                "Selected free prefix is not an IPv4 /18: "
                f"{container.prefix}"
            )

        planned = self._build_allocation_plan(
            container_definitions=container_definitions,
            fixed_definitions=fixed_definitions,
            resolved_vlans=resolved_vlans,
            container_net=container_net,
            roles_by_name=roles_by_name,
            tenant=tenant,
        )

        self._validate_plan(
            planned=planned,
            container=container,
            lindab_vrf=lindab_vrf,
            site_vrf=site_vrf,
        )

        if commit:
            with transaction.atomic():
                if site_vrf is None:
                    site_vrf = self._create_site_vrf(site)

                self._dedicate_container_prefix(
                    container=container,
                    site=site,
                    vrf=lindab_vrf,
                )

                created = self._create_prefixes(
                    planned=planned,
                    site=site,
                    lindab_vrf=lindab_vrf,
                    site_vrf=site_vrf,
                )
        else:
            self.log_info(
                "DRY-RUN MODE (commit=False): "
                "No database changes will be made."
            )

            if site_vrf is None:
                self.log_info(
                    f'Would create site VRF "{site.name}".'
                )

            self._log_container_changes(
                container=container,
                site=site,
                vrf=lindab_vrf,
            )

            created = self._log_prefix_creations(
                planned=planned,
                site=site,
                lindab_vrf=lindab_vrf,
                site_vrf=site_vrf,
            )

        self.log_success(
            f"Completed. Created or planned {created} prefix(es)."
        )

        return self._build_summary(
            planned=planned,
            site=site,
            container=container,
            lindab_vrf=lindab_vrf,
            site_vrf=site_vrf,
        )

    # ------------------------------------------------------------------
    # Fixed VLAN resolution
    # ------------------------------------------------------------------

    def _resolve_fixed_vlans(self) -> dict[int, VLAN]:
        """
        Resolve every required VLAN by exact VLAN ID and VLAN name.

        The script aborts if a required VLAN is missing or if multiple VLAN
        objects match the same definition.
        """

        resolved: dict[int, VLAN] = {}

        for definition in self.FIXED_VLAN_DEFINITIONS:
            matches = VLAN.objects.filter(
                vid=definition.vid,
                name=definition.name,
            )

            match_count = matches.count()

            if match_count == 0:
                raise AbortScript(
                    "Required VLAN does not exist: "
                    f"{definition.vid} ({definition.name})."
                )

            if match_count > 1:
                raise AbortScript(
                    "Multiple VLAN objects match the required VLAN: "
                    f"{definition.vid} ({definition.name}). "
                    "The script cannot select one safely."
                )

            resolved[definition.vid] = matches.first()

        return resolved

    # ------------------------------------------------------------------
    # Required object resolution
    # ------------------------------------------------------------------

    def _get_required_vrf(self, name: str) -> VRF:
        """Return one existing VRF by exact name."""

        matches = VRF.objects.filter(name=name)
        match_count = matches.count()

        if match_count == 0:
            raise AbortScript(
                f'Required VRF "{name}" does not exist. '
                "Create it before running this script."
            )

        if match_count > 1:
            raise AbortScript(
                f'Multiple VRFs named "{name}" exist. '
                "The script cannot select one safely."
            )

        return matches.first()

    def _get_required_roles(self) -> dict[str, Role]:
        """Load all Prefix/VLAN Roles required by the configured VLANs."""
    
        required_names = {
            definition.role_name
            for definition in self.FIXED_VLAN_DEFINITIONS
        }
    
        roles_by_name = {
            role.name: role
            for role in Role.objects.filter(name__in=required_names)
        }
    
        missing_roles = required_names - set(roles_by_name)
    
        if missing_roles:
            raise AbortScript(
                "Missing required Prefix/VLAN Role(s) in NetBox: "
                + ", ".join(sorted(missing_roles))
                + ". Create these roles before running the script."
            )
    
        return roles_by_name


    def _get_required_tenant(self, name: str) -> Tenant:
        """Return one existing Tenant by exact name."""

        matches = Tenant.objects.filter(name=name)
        match_count = matches.count()

        if match_count == 0:
            raise AbortScript(
                f'Required Tenant "{name}" does not exist. '
                "Create it before running this script."
            )

        if match_count > 1:
            raise AbortScript(
                f'Multiple Tenants named "{name}" exist. '
                "The script cannot select one safely."
            )

        return matches.first()

    def _get_site_vrf(self, site: Site) -> Optional"""Return the site-named VRF if it already exists."""

        matches = VRF.objects.filter(name=site.name)
        match_count = matches.count()

        if match_count > 1:
            raise AbortScript(
                f'Multiple VRFs named "{site.name}" exist. '
                "The script cannot select one safely."
            )

        return matches.first()

    def _create_site_vrf(self, site: Site) -> VRF:
        """Create and return a VRF named after the selected Site."""

        site_vrf = VRF(
            name=site.name,
            description=f"Site-specific VRF for {site.name}",
        )
        site_vrf.full_clean()
        site_vrf.save()

        self.log_success(
            f'Created site VRF "{site_vrf.name}".',
            obj=site_vrf,
        )

        return site_vrf

    # ------------------------------------------------------------------
    # Container prefix selection and dedication
    # ------------------------------------------------------------------

    def _get_first_free_container(self) -> Prefix:
        """Return the first IPv4 /18 tagged with free-prefix."""

        queryset = Prefix.objects.filter(
            tags__slug="free-prefix"
        ).order_by("prefix")

        for prefix in queryset:
            try:
                network = IPNetwork(str(prefix.prefix))
            except Exception:
                continue

            if network.version == 4 and network.prefixlen == 18:
                self.log_info(
                    f"Selected free container prefix: {prefix.prefix}",
                    obj=prefix,
                )
                return prefix

        raise AbortScript(
            'No IPv4 /18 prefix tagged with slug "free-prefix" was found.'
        )

    def _dedicate_container_prefix(
        self,
        container: Prefix,
        site: Site,
        vrf: VRF,
    ) -> None:
        """Assign the free /18 to the selected Site and Lindab Group VRF."""

        if container.pk and hasattr(container, "snapshot"):
            container.snapshot()

        container.scope = site
        container.vrf = vrf
        container.description = ""
        container.status = "reserved"

        container.full_clean()
        container.save()

        try:
            free_tag = Tag.objects.get(slug="free-prefix")
            container.tags.remove(free_tag)
        except Tag.DoesNotExist:
            self.log_warning(
                'Tag "free-prefix" does not exist; it could not be removed.',
                obj=container,
            )

        self.log_success(
            f"Dedicated container {container.prefix} to Site "
            f"{site.name} and VRF {vrf.name}.",
            obj=container,
        )

    def _log_container_changes(
        self,
        container: Prefix,
        site: Site,
        vrf: VRF,
    ) -> None:
        """Log the planned changes to the free /18."""

        self.log_info(f"Would update container {container.prefix}:")
        self.log_info(f"  - scope = Site({site.name})")
        self.log_info(f"  - vrf = {vrf.name}")
        self.log_info("  - description cleared")
        self.log_info('  - remove tag "free-prefix"')
        self.log_info('  - status = "reserved"')

    # ------------------------------------------------------------------
    # Allocation planning
    # ------------------------------------------------------------------

    def _build_allocation_plan(
        self,
        container_definitions: List[VLANDefinition],
        fixed_definitions: List[VLANDefinition],
        resolved_vlans: dict[int, VLAN],
        container_net: IPNetwork,
        roles_by_name: dict[str, Role],
        tenant: Tenant,
    ) -> List"""Build the complete allocation plan in the configured order."""
    
        planned: List[PlannedPrefix] = []
        container_subnets = list(container_net.subnet(24))
    
        if len(container_definitions) > len(container_subnets):
            raise AbortScript(
                f"Container {container_net} does not contain enough "
                "/24 prefixes for the configured VLANs."
            )
    
        allocation_order = 0
    
        for subnet_index, definition in enumerate(
            container_definitions
        ):
            planned.append(
                PlannedPrefix(
                    vlan=resolved_vlans[definition.vid],
                    prefix=container_subnets[subnet_index],
                    role=roles_by_name[definition.role_name],
                    tenant=tenant,
                    use_site_vrf=False,
                    allocation_order=allocation_order,
                )
            )
            allocation_order += 1
    
        for definition in fixed_definitions:
            if not definition.fixed_prefix:
                raise AbortScript(
                    "Internal configuration error: VLAN "
                    f"{definition.vid} does not have a fixed prefix."
                )
    
            fixed_network = IPNetwork(definition.fixed_prefix)
    
            if fixed_network.version != 4:
                raise AbortScript(
                    f"Fixed prefix {fixed_network} for VLAN "
                    f"{definition.vid} is not IPv4."
                )
    
            if fixed_network.prefixlen != 24:
                raise AbortScript(
                    f"Fixed prefix {fixed_network} for VLAN "
                    f"{definition.vid} is not a /24."
                )
    
            planned.append(
                PlannedPrefix(
                    vlan=resolved_vlans[definition.vid],
                    prefix=fixed_network,
                    role=roles_by_name[definition.role_name],
                    tenant=tenant,
                    use_site_vrf=definition.use_site_vrf,
                    allocation_order=allocation_order,
                )
            )
            allocation_order += 1
    
        return planned

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def _validate_plan(
        self,
        planned: List[PlannedPrefix],
        container: Prefix,
        lindab_vrf: VRF,
        site_vrf: Optional[VRF],
    ) -> None:
        """Validate generated prefixes and target-VRF overlaps."""

        self._validate_internal_overlaps(planned)

        container_net = IPNetwork(str(container.prefix))

        for item in planned:
            if item.prefix.prefixlen != 24:
                raise AbortScript(
                    f"Generated prefix {item.prefix} for VLAN "
                    f"{item.vlan.vid} is not a /24."
                )

            if not item.use_site_vrf:
                if not self._network_contains(
                    container_net,
                    item.prefix,
                ):
                    raise AbortScript(
                        f"Generated prefix {item.prefix} for VLAN "
                        f"{item.vlan.vid} is outside container "
                        f"{container.prefix}."
                    )

        collisions: List[str] = []

        for item in planned:
            target_vrf = (
                site_vrf
                if item.use_site_vrf
                else lindab_vrf
            )

            if item.use_site_vrf and target_vrf is None:
                continue

            existing_prefixes = Prefix.objects.filter(
                vrf=target_vrf
            ).exclude(
              status="container"
            )

            if not item.use_site_vrf:
                existing_prefixes = existing_prefixes.exclude(
                    pk=container.pk
                )

            for existing in existing_prefixes:
                try:
                    existing_network = IPNetwork(
                        str(existing.prefix)
                    )
                except Exception:
                    continue

                if self._networks_overlap(
                    item.prefix,
                    existing_network,
                ):
                    collisions.append(
                        f"{item.prefix} for VLAN {item.vlan.vid} "
                        f"overlaps {existing.prefix} in VRF "
                        f"{target_vrf.name}"
                    )

        if collisions:
            raise AbortScript(
                "Cannot create prefixes because address-space "
                "collisions were found: "
                + "; ".join(sorted(set(collisions)))
            )

    def _validate_internal_overlaps(
        self,
        planned: List[PlannedPrefix],
    ) -> None:
        """Ensure planned prefixes do not overlap in the same target VRF."""

        collisions: List[str] = []

        for index, first in enumerate(planned):
            for second in planned[index + 1:]:
                if first.use_site_vrf != second.use_site_vrf:
                    continue

                if self._networks_overlap(
                    first.prefix,
                    second.prefix,
                ):
                    collisions.append(
                        f"{first.prefix} for VLAN {first.vlan.vid} "
                        f"overlaps {second.prefix} for VLAN "
                        f"{second.vlan.vid}"
                    )

        if collisions:
            raise AbortScript(
                "The generated allocation plan contains overlapping "
                "prefixes: "
                + "; ".join(collisions)
            )

    @staticmethod
    def _network_contains(
        container: IPNetwork,
        child: IPNetwork,
    ) -> bool:
        """Return whether a network is fully contained in another network."""

        if container.version != child.version:
            return False

        return (
            container.first <= child.first
            and child.last <= container.last
        )

    @staticmethod
    def _networks_overlap(
        first: IPNetwork,
        second: IPNetwork,
    ) -> bool:
        """Return whether two IP networks overlap."""

        if first.version != second.version:
            return False

        return (
            first.first <= second.last
            and second.first <= first.last
        )

    # ------------------------------------------------------------------
    # Prefix creation
    # ------------------------------------------------------------------

    def _create_prefixes(
        self,
        planned: List[PlannedPrefix],
        site: Site,
        lindab_vrf: VRF,
        site_vrf: Optional[VRF],
    ) -> int:
        """Create every planned VLAN prefix."""

        if site_vrf is None:
            raise AbortScript(
                "Internal error: The site VRF was not created."
            )

        created = 0

        for item in sorted(
            planned,
            key=lambda value: value.allocation_order,
        ):
            target_vrf = (
                site_vrf
                if item.use_site_vrf
                else lindab_vrf
            )

            prefix = Prefix(
                prefix=str(item.prefix),
                status="active",
                vrf=target_vrf,
                scope=site,
                vlan=item.vlan,
                role=item.role,
                tenant=item.tenant,
                description=self._prefix_description(item.vlan),
            )

            prefix.full_clean()
            prefix.save()
            created += 1

            self.log_success(
                f"Created {prefix.prefix} for VLAN "
                f"{item.vlan.vid} ({item.vlan.name}) in VRF "
                f"{target_vrf.name}.",
                obj=prefix,
            )

        return created

    def _log_prefix_creations(
        self,
        planned: List[PlannedPrefix],
        site: Site,
        lindab_vrf: VRF,
        site_vrf: Optional[VRF],
    ) -> int:
        """Log every planned VLAN prefix creation."""

        for item in sorted(
            planned,
            key=lambda value: value.allocation_order,
        ):
            vrf_name = (
                site_vrf.name
                if item.use_site_vrf and site_vrf is not None
                else site.name
                if item.use_site_vrf
                else lindab_vrf.name
            )

            self.log_info(
                f"Would create {item.prefix} | "
                f"VLAN={item.vlan.vid} ({item.vlan.name}) | "
                f"Role={item.role.name} | "
                f"Tenant={item.tenant.name} | "
                f"VRF={vrf_name} | "
                f"Status=active | "
                f"Scope=Site({site.name}) | "
                f"Description="
                f"{self._prefix_description(item.vlan)}"
            )

        return len(planned)

    @staticmethod
    def _prefix_description(vlan: VLAN) -> str:
        """Return the required description for a VLAN prefix."""

        return f"VLAN {vlan.vid} - {vlan.name}"

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def _build_summary(
        self,
        planned: List[PlannedPrefix],
        site: Site,
        container: Prefix,
        lindab_vrf: VRF,
        site_vrf: Optional[VRF],
    ) -> str:
        """Return the readable script output summary."""

        site_vrf_name = (
            site_vrf.name
            if site_vrf is not None
            else site.name
        )

        summary_lines = [
            f"Site: {site.name}",
            f"Organization VRF: {lindab_vrf.name}",
            f"Site VRF: {site_vrf_name}",
            f"Container (/18): {container.prefix}",
            f"Container VRF: {lindab_vrf.name}",
            "Container status: reserved",
            "",
            "Created / Planned Prefixes:",
        ]

        for item in sorted(
            planned,
            key=lambda value: value.allocation_order,
        ):
            vrf_name = (
                site_vrf_name
                if item.use_site_vrf
                else lindab_vrf.name
            )

            summary_lines.append(
                f"- {item.prefix} | "
                f"VLAN {item.vlan.vid} ({item.vlan.name}) | "
                f"Role: {item.role.name} | "
                f"Tenant: {item.tenant.name} | "
                f"VRF: {vrf_name} | "
                f"Status: active | "
                f"Scope: Site {site.name} | "
                f"Description: {self._prefix_description(item.vlan)}"
            )

        return "\n".join(summary_lines)
