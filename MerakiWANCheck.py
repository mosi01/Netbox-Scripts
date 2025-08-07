from extras.scripts import Script, StringVar
import requests
import re
from dcim.models import Site
from circuits.models import CircuitTermination

class MerakiSiteWANCheck(Script):
    class Meta:
        name = "Meraki Site WAN vs NetBox Circuits"
        description = "Compare Meraki WAN connections per site with NetBox circuit registrations"
        field_order = ['meraki_api_key']

    meraki_api_key = StringVar(
        description="Meraki Dashboard API key",
        required=True
    )

    def run(self, data, commit):
        api_key = data['meraki_api_key']
        headers = {
            "X-Cisco-Meraki-API-Key": api_key,
            "Content-Type": "application/json"
        }

        # CSV header
        csv_lines = ["Company ID;Meraki Site Name;NetBox Site Name;Meraki WAN Connections;NetBox Circuit Count"]

        # Get organization ID
        orgs = requests.get("https://api.meraki.com/api/v1/organizations", headers=headers).json()
        org_id = orgs[0]['id']

        # Get networks (Meraki sites)
        networks = requests.get(
            f"https://api.meraki.com/api/v1/organizations/{org_id}/networks",
            headers=headers
        ).json()
        network_lookup = {net['id']: net['name'] for net in networks}

        # Get all devices
        devices = requests.get(
            f"https://api.meraki.com/api/v1/organizations/{org_id}/devices",
            headers=headers
        ).json()

        # Group WAN counts per network
        site_wan_map = {}
        for device in devices:
            if not device['model'].startswith('MX'):
                continue
            net_id = device.get('networkId')
            if not net_id:
                continue
            site_name = network_lookup.get(net_id, 'Unknown')
            site_wan_map.setdefault(site_name, 0)
            if device.get('wan1Ip'):
                site_wan_map[site_name] += 1
            if device.get('wan2Ip'):
                site_wan_map[site_name] += 1

        # Compare with NetBox circuits
        for meraki_site_name, wan_count in site_wan_map.items():
            company_id = self.extract_company_id(meraki_site_name)
            netbox_site = self.get_netbox_site_by_name(meraki_site_name)
            netbox_site_name = netbox_site.name if netbox_site else "Not Found"
            circuit_count = self.get_circuit_count_for_site(netbox_site) if netbox_site else 0

            # Smarter reporting logic
            if wan_count > circuit_count and (circuit_count * 2) < wan_count:
                csv_lines.append(
                    f"{company_id};{meraki_site_name};{netbox_site_name};{wan_count};{circuit_count}"
                )

        return "\n".join(csv_lines)

    def extract_company_id(self, site_name):
        match = re.match(r'^(\d+)', site_name)
        return match.group(1).zfill(3) if match else 'Unknown'

    def get_netbox_site_by_name(self, name):
        return Site.objects.filter(name=name).first()

    def get_circuit_count_for_site(self, site):
        return CircuitTermination.objects.filter(
            termination_type__model='site',
            termination_id=site.id
        ).count()