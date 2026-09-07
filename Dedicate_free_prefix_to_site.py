"""
dedicate_free_prefix_to_site.py

NetBox Custom Script (NetBox v4.6.4)

Functionality
-------------
- Select a Site.
- Select one or more VLANs filtered to VLANs tagged "local-site-vlan".
- Optionally skip the grouped prefix placement rules.

Behavior
--------
- VLANs with IDs from 500 through 599 receive:
    192.168.<VLAN ID modulo 100>.0/24
- VLANs from 500 through 599 are assigned to a VRF named after the Site.
- The site VRF is created if it does not already exist.
- All other VLANs are allocated from the first IPv4 /18 tagged "free-prefix".
- The /18 and its child prefixes are assigned to the "Lindab Group" VRF.
- VLAN names listed in PREFIX_25_VLAN_NAMES receive /25 prefixes.
- Other VLANs allocated from the /18 receive /24 prefixes.
- Adjacent /25 allocations are packed into the same /24 where possible.
- The /18 description is cleared, its "free-prefix" tag is removed, and its
  status is set to reserved.
- All created prefixes are scoped to the selected Site and set to reserved.

Placement rules
---------------
When Skip prefix validation is enabled:
- Regular VLANs are sorted numerically.
- /25 VLANs consume one half of a /24.
- /24 VLANs are aligned to the next /24 boundary.

When Skip prefix validation is disabled:
- Regular VLANs below 1000 are grouped by their VLAN tens base.
- Each group receives a block equivalent to ten /24 prefixes.
- VLANs within each selected group are packed numerically.
- Regular VLANs of 1000 or higher are allocated last, starting at the next
  ten-prefix block boundary.

Role assignment rules
---------------------
- VLAN ID 430-439: Security Network
- VLAN ID 3500-4050: DMZ/IDMZ
- Otherwise, roles are assigned by VLAN-name substring.

Notes
-----
- The "Lindab Group" VRF must already exist.
- Required Prefix/VLAN Roles must already exist.
- VLANs from 500 through 599 always receive /24 prefixes, even if their VLAN
  name is listed in PREFIX_25_VLAN_NAMES.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from django.db import transaction
from netaddr import IPNetwork

from dcim.models import Site
from extras.models import Tag
from extras.scripts import BooleanVar, MultiObjectVar, ObjectVar, Script
from ipam.models import Prefix, Role, VLAN, VRF
from utilities.exceptions import AbortScript


@dataclass(frozen=True)
class PlannedPrefix:
    """A planned prefix allocation for a VLAN."""

    vlan: VLAN
    prefix: IPNetwork
    role: Optional[Role]
    use_site_vrf: bool
    allocation_order: int


class DedicateFreePrefixToSite(Script):
    """
    Dedicate a free /18 to a Site and create VLAN prefixes in the appropriate
    organization or site VRF.
    """

    site = ObjectVar(
        model=Site,
        label="Site",
        description=(
            "Select the Site. VLANs 500-599 use a VRF named after this Site."
        ),
        selector=True,
    )

    vlans = MultiObjectVar(
        model=VLAN,
        label="VLANs",
        description=(
            'Select VLANs to create prefixes for. VLANs are filtered to the '
            'tag "local-site-vlan".'
        ),
        query_params={"tag": "local-site-vlan"},
        required=True,
        selector=True,
    )

    skip_prefix_validation = BooleanVar(
        label="Skip prefix validation",
        description=(
            "Allocate regular VLAN prefixes sequentially instead of using "
            "ten-prefix VLAN groups."
        ),
        default=False,
        required=False,
    )

    class Meta:
        name = "Dedicate free /18 to site and create VLAN prefixes"
        description = (
            "Create site-specific 192.168.x.0/24 prefixes for VLANs 500-599 "
            "and allocate all other selected VLANs from a free /18."
        )
        fieldsets = (
            ("Target", ("site",)),
            ("VLAN Selection", ("vlans",)),
            ("Options", ("skip_prefix_validation",)),
        )

    LINDAB_GROUP_VRF_NAME = "Lindab Group"

    SITE_VRF_VLAN_MIN = 500
    SITE_VRF_VLAN_MAX = 599

    PREFIX_25_VLAN_NAMES: Tuple[str, ...] = (
        "460-MGMT",
        "461-MGMT-AP",
        "462-MGMT-OP",
        "463-MGMT-EXT",
        "469-MGMT-FW",
    )

    ROLE_BY_NAME_CONTAINS: Tuple[Tuple[str, str], ...] = (
        ("client", "Client Network"),
        ("printer", "Printer Network"),
        ("wms", "WMS"),
        ("mgmt", "Management Network"),
        ("server", "Server Network"),
    )

    def run(self, data, commit):
        site: Site = data["site"]
        vlans: List[VLAN] = list(data["vlans"] or [])
        skip_validation = bool(data.get("skip_prefix_validation", False))

        if not vlans:
            raise AbortScript("No VLANs were selected. Nothing to do.")

        self._validate_unique_vlan_ids(vlans)

        lindab_vrf = self._get_required_vrf(self.LINDAB_GROUP_VRF_NAME)
        site_vrf = self._get_site_vrf(site)

        site_vlans = [
            vlan for vlan in vlans if self._uses_site_vrf(vlan)
        ]
        regular_vlans = [
            vlan for vlan in vlans if not self._uses_site_vrf(vlan)
        ]

        container: Optional[Prefix] = None
        container_net: Optional[IPNetwork] = None

        if regular_vlans:
            container = self._get_first_free_container()
            container_net = IPNetwork(str(container.prefix))

            if container_net.version != 4 or container_net.prefixlen != 18:
                raise AbortScript(
                    f"Selected free prefix is not an IPv4 /18: "
                    f"{container.prefix}"
                )

        role_by_name = self._get_required_roles(vlans)

        planned: List[PlannedPrefix] = []

        if regular_vlans and container_net is not None:
            planned.extend(
                self._plan_regular_allocations(
                    vlans=regular_vlans,
                    container_net=container_net,
                    skip_validation=skip_validation,
                    role_by_name=role_by_name,
                )
            )

        planned.extend(
            self._plan_site_vrf_allocations(
                vlans=site_vlans,
                role_by_name=role_by_name,
                starting_order=len(planned),
            )
        )

        self._validate_plan(
            planned=planned,
            container=container,
            lindab_vrf=lindab_vrf,
            site_vrf=site_vrf,
        )

        if commit:
            with transaction.atomic():
                if site_vrf is None and site_vlans:
                    site_vrf = self._create_site_vrf(site)

                if container is not None:
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

            if site_vrf is None and site_vlans:
                self.log_info(
                    f'Would create site VRF "{site.name}".'
                )

            if container is not None:
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
    # VRF resolution
    # ------------------------------------------------------------------

    def _get_required_vrf(self, name: str) -> VRF:
        """Return one existing VRF by exact name."""

        matches = VRF.objects.filter(name=name)

        if not matches.exists():
            raise AbortScript(
                f'Required VRF "{name}" does not exist. '
                "Create it before running this script."
            )

        if matches.count() > 1:
            raise AbortScript(
                f'Multiple VRFs named "{name}" exist. '
                "The script cannot select one safely."
            )

        return matches.first()

    def _get_site_vrf(self, site: Site) -> Optional[VRF]:
        """Return the site-named VRF if it already exists."""

        matches = VRF.objects.filter(name=site.name)

        if matches.count() > 1:
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
        """Assign the free /18 to the Site and Lindab Group VRF."""

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

    def _plan_regular_allocations(
        self,
        vlans: List[VLAN],
        container_net: IPNetwork,
        skip_validation: bool,
        role_by_name: Dict[str, Role],
    ) -> List[PlannedPrefix]:
        """
            Plan /24 and /25 allocations from the selected free /18.
            Allocation positions are represented as /25 units. A /25 consumes one
            unit and a /24 consumes two aligned units.
        """

        subnets_25 = list(container_net.subnet(25))
        vlans_sorted = sorted(vlans, key=lambda vlan: int(vlan.vid))

        if skip_validation:
            return self._pack_vlan_block(
                vlans=vlans_sorted,
                subnets_25=subnets_25,
                starting_unit=0,
                maximum_unit=len(subnets_25),
                starting_order=0,
                role_by_name=role_by_name,
            )

        planned: List[PlannedPrefix] = []
        vlans_3d = [
            vlan for vlan in vlans_sorted if int(vlan.vid) < 1000
        ]
        vlans_4d = [
            vlan for vlan in vlans_sorted if int(vlan.vid) >= 1000
        ]

        groups: Dict[int, List[VLAN]] = {}

        for vlan in vlans_3d:
            vid = int(vlan.vid)
            base = vid - (vid % 10)
            groups.setdefault(base, []).append(vlan)

        next_order = 0
        used_group_count = 0

        for group_index, base in enumerate(sorted(groups)):
            group_start_unit = group_index * 20
            group_end_unit = group_start_unit + 20

            group_plan = self._pack_vlan_block(
                vlans=sorted(
                    groups[base],
                    key=lambda vlan: int(vlan.vid),
                ),
                subnets_25=subnets_25,
                starting_unit=group_start_unit,
                maximum_unit=group_end_unit,
                starting_order=next_order,
                role_by_name=role_by_name,
            )

            planned.extend(group_plan)
            next_order += len(group_plan)
            used_group_count = group_index + 1

        if vlans_4d:
            four_digit_start = used_group_count * 20

            four_digit_plan = self._pack_vlan_block(
                vlans=vlans_4d,
                subnets_25=subnets_25,
                starting_unit=four_digit_start,
                maximum_unit=len(subnets_25),
                starting_order=next_order,
                role_by_name=role_by_name,
            )

            planned.extend(four_digit_plan)

        return planned

    def _pack_vlan_block(
        self,
        vlans: List[VLAN],
        subnets_25: List[IPNetwork],
        starting_unit: int,
        maximum_unit: int,
        starting_order: int,
        role_by_name: Dict[str, Role],
    ) -> List[PlannedPrefix]:
    
        """Pack VLANs into a bounded range of /25 allocation units."""

        planned: List[PlannedPrefix] = []
        unit_index = starting_unit

        for offset, vlan in enumerate(vlans):
            is_prefix_25 = self._uses_prefix_25(vlan)

            if not is_prefix_25 and unit_index % 2:
                unit_index += 1

            required_units = 1 if is_prefix_25 else 2

            if (
                unit_index + required_units > maximum_unit
                or unit_index + required_units > len(subnets_25)
            ):
                raise AbortScript(
                    f"Not enough address space to allocate VLAN "
                    f"{vlan.vid} ({vlan.name})."
                )

            if is_prefix_25:
                network = subnets_25[unit_index]
            else:
                network = IPNetwork(
                    f"{subnets_25[unit_index].network}/24"
                )

            planned.append(
                PlannedPrefix(
                    vlan=vlan,
                    prefix=network,
                    role=self._role_for_vlan(vlan, role_by_name),
                    use_site_vrf=False,
                    allocation_order=starting_order + offset,
                )
            )

            unit_index += required_units

        return planned

    def _plan_site_vrf_allocations(
        self,
        vlans: List[VLAN],
        role_by_name: Dict[str, Role],
        starting_order: int,
    ) -> List[PlannedPrefix]:
        """Plan deterministic /24 prefixes for VLANs 500 through 599."""

        planned: List[PlannedPrefix] = []

        for offset, vlan in enumerate(
            sorted(vlans, key=lambda item: int(item.vid))
        ):
            vid = int(vlan.vid)
            third_octet = vid % 100
            network = IPNetwork(
                f"192.168.{third_octet}.0/24"
            )

            planned.append(
                PlannedPrefix(
                    vlan=vlan,
                    prefix=network,
                    role=self._role_for_vlan(vlan, role_by_name),
                    use_site_vrf=True,
                    allocation_order=starting_order + offset,
                )
            )

        return planned

    def _uses_prefix_25(self, vlan: VLAN) -> bool:
        """Return whether a regular VLAN should receive a /25."""

        vlan_name = (vlan.name or "").strip().casefold()
        configured_names = {
            name.strip().casefold()
            for name in self.PREFIX_25_VLAN_NAMES
        }

        return vlan_name in configured_names

    def _uses_site_vrf(self, vlan: VLAN) -> bool:
        """Return whether a VLAN uses the site-specific VRF."""

        vid = int(vlan.vid)
        return self.SITE_VRF_VLAN_MIN <= vid <= self.SITE_VRF_VLAN_MAX

    # ------------------------------------------------------------------
    # Role resolution
    # ------------------------------------------------------------------

    def _determine_role_name(self, vlan: VLAN) -> Optional[str]:
        """Return the required role name for a VLAN."""

        vid = int(vlan.vid)

        if 430 <= vid <= 439:
            return "Security Network"

        if 3500 <= vid <= 4050:
            return "DMZ/IDMZ"

        vlan_name = (vlan.name or "").casefold()

        for name_fragment, role_name in self.ROLE_BY_NAME_CONTAINS:
            if name_fragment.casefold() in vlan_name:
                return role_name

        return None

    def _get_required_roles(
        self,
        vlans: List[VLAN],
    ) -> Dict[str, Role]:
        """Load all roles required by the selected VLANs."""

        required_names = {
            role_name
            for vlan in vlans
            for role_name in [self._determine_role_name(vlan)]
            if role_name
        }

        roles = {
            role.name: role
            for role in Role.objects.filter(name__in=required_names)
        }

        missing = required_names - set(roles)

        if missing:
            raise AbortScript(
                "Missing required Prefix/VLAN Role(s) in NetBox: "
                + ", ".join(sorted(missing))
                + ". Create these roles first, then rerun."
            )

        return roles

    def _role_for_vlan(
        self,
        vlan: VLAN,
        role_by_name: Dict[str, Role],
    ) -> Optional[Role]:
        """Return the loaded role for a VLAN."""

        role_name = self._determine_role_name(vlan)

        if not role_name:
            return None

        return role_by_name[role_name]

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def _validate_unique_vlan_ids(self, vlans: List[VLAN]) -> None:
        """Ensure selected VLAN IDs are unique."""

        vlan_ids = [int(vlan.vid) for vlan in vlans]
        duplicate_ids = sorted(
            {
                vid
                for vid in vlan_ids
                if vlan_ids.count(vid) > 1
            }
        )

        if duplicate_ids:
            raise AbortScript(
                "Multiple selected VLAN objects use the same VLAN ID: "
                + ", ".join(str(vid) for vid in duplicate_ids)
                + ". Select only one VLAN object for each VLAN ID."
            )

    def _validate_plan(
        self,
        planned: List[PlannedPrefix],
        container: Optional[Prefix],
        lindab_vrf: VRF,
        site_vrf: Optional[VRF],
    ) -> None:
        """Validate generated prefixes and target-VRF overlaps."""

        self._validate_internal_overlaps(planned)

        collisions: List[str] = []

        for item in planned:
            target_vrf = site_vrf if item.use_site_vrf else lindab_vrf

            if item.use_site_vrf and target_vrf is None:
                continue

            existing_prefixes = Prefix.objects.filter(vrf=target_vrf)

            if (
                container is not None
                and not item.use_site_vrf
            ):
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
                        f"{item.prefix} overlaps "
                        f"{existing.prefix} in VRF {target_vrf.name}"
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
        """Ensure planned prefixes do not overlap within the same target VRF."""

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
        """Create all planned VLAN prefixes."""

        if any(item.use_site_vrf for item in planned) and site_vrf is None:
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
                status="reserved",
                vrf=target_vrf,
                scope=site,
                vlan=item.vlan,
                role=item.role,
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
        """Log all planned VLAN prefix creations."""

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
                f"VLAN {item.vlan.vid} ({item.vlan.name}) | "
                f"Role="
                f"{item.role.name if item.role else '(none)'} | "
                f"VRF={vrf_name} | "
                f"Status=reserved | "
                f"Scope=Site({site.name})"
            )

        return len(planned)

    @staticmethod
    def _prefix_description(vlan: VLAN) -> str:
        """Return the description used for a VLAN prefix."""

        if vlan.name:
            return f"VLAN {vlan.vid} - {vlan.name}"

        return f"VLAN {vlan.vid}"

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def _build_summary(
        self,
        planned: List[PlannedPrefix],
        site: Site,
        container: Optional[Prefix],
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
        ]

        if container is not None:
            summary_lines.extend(
                [
                    f"Container (/18): {container.prefix}",
                    f"Container VRF: {lindab_vrf.name}",
                    "Container status: reserved",
                ]
            )
        else:
            summary_lines.append(
                "Container (/18): Not required for the selected VLANs"
            )

        summary_lines.extend(
            [
                "",
                "Created / Planned Prefixes:",
            ]
        )

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
                f"Role: "
                f"{item.role.name if item.role else '(none)'} | "
                f"VRF: {vrf_name} | "
                f"Status: reserved | "
                f"Scope: Site {site.name}"
            )

        return "\n".join(summary_lines)
