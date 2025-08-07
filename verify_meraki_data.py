from extras.scripts import Script, StringVar
from dcim.models import Device, Manufacturer, DeviceType, DeviceRole, Site
from ipam.models import IPAddress
from extras.models import Tag
import requests
from datetime import datetime, timedelta


class VerifyMerakiData(Script):
    api_key = StringVar(
        label="Meraki API Key",
        description="Your Cisco Meraki API key"
    )

    class Meta:
        name = "Verify Meraki Device Data"
        description = "Validates Meraki device data against NetBox records and syncs mismatch tags."
        field_order = ["api_key"]

    def run(self, data, commit):
        headers = {
            "X-Cisco-Meraki-API-Key": data["api_key"],
            "Accept": "application/json"
        }

        # 1. Fetch organization
        orgs = requests.get("https://api.meraki.com/api/v1/organizations", headers=headers).json()
        if not orgs or not orgs[0].get("id"):
            self.log_failure("❌ No organization found.")
            return
        org_id = orgs[0]["id"]

        # 2. Fetch networks
        networks = requests.get(
            f"https://api.meraki.com/api/v1/organizations/{org_id}/networks", headers=headers
        ).json()
        network_map = {n["id"]: n["name"] for n in networks if "id" in n and "name" in n}

        # 3. Fetch Meraki devices
        devices = requests.get(
            f"https://api.meraki.com/api/v1/organizations/{org_id}/devices", headers=headers
        ).json()

        # 4. Fetch Meraki device statuses
        statuses = requests.get(
            f"https://api.meraki.com/api/v1/organizations/{org_id}/devices/statuses", headers=headers
        ).json()
        status_map = {s["serial"]: s for s in statuses if "serial" in s}

        # 5. Ensure tags exist
        firmware_tag, _ = Tag.objects.get_or_create(name="FIRMWARE_MISS")
        status_tag, _ = Tag.objects.get_or_create(name="STATUS_MISS")

        mismatches = []
        manufacturer = Manufacturer.objects.filter(name="Cisco Meraki").first()

        for dev in devices:
            serial = dev.get("serial")
            if not serial:
                continue

            try:
                nb_device = Device.objects.get(serial=serial)
            except Device.DoesNotExist:
                mismatches.append(f"Not found in NetBox: {serial}")
                continue

            # Match name
            if nb_device.name != dev.get("name", ""):
                mismatches.append(f"Name mismatch: NB='{nb_device.name}', Meraki='{dev.get('name', '')}'")

            # Match model
            if nb_device.device_type.model != dev.get("model", ""):
                mismatches.append(f"Model mismatch for {serial}: NB='{nb_device.device_type.model}', Meraki='{dev.get('model', '')}'")

            # Match site
            meraki_network_name = network_map.get(dev.get("networkId"), "")
            if not nb_device.site or nb_device.site.name != meraki_network_name:
                mismatches.append(f"Site mismatch for {serial}: NB='{nb_device.site.name if nb_device.site else 'None'}', Meraki='{meraki_network_name}'")

            # Match role
            expected_role = self._get_role_from_model(dev.get("model", ""))
            if not nb_device.role or nb_device.role.name != expected_role:
                mismatches.append(f"Role mismatch for {serial}: NB='{nb_device.role.name if nb_device.role else 'None'}', Expected='{expected_role}'")

            # Match asset_tag ← MAC
            if nb_device.asset_tag != dev.get("mac", ""):
                mismatches.append(f"Asset tag mismatch for {serial}: NB='{nb_device.asset_tag}', Meraki='{dev.get('mac', '')}'")

            # ✅ Enhanced status validation
            status_info = status_map.get(serial)
            meraki_status = status_info.get("status") if status_info else None
            last_seen_str = status_info.get("lastReportedAt") if status_info else None

            expected_status = "active"  # Default assumption

            if meraki_status in ["offline", "dormant"]:
                if last_seen_str:
                    try:
                        last_seen = datetime.fromisoformat(last_seen_str.replace("Z", "+00:00"))
                        now = datetime.utcnow().replace(tzinfo=last_seen.tzinfo)
                        inactive_duration = now - last_seen

                        if inactive_duration > timedelta(days=60):
                            expected_status = "inventory"
                        else:
                            expected_status = "offline"
                    except Exception as e:
                        mismatches.append(f"Error parsing lastReportedAt for {serial}: {e}")
                        continue
                else:
                    expected_status = "offline"

            # Compare NetBox status with expected
            status_mismatch = False
            if nb_device.status != expected_status:
                if not (nb_device.status == "inventory" and expected_status == "offline"):
                    status_mismatch = True
                    mismatches.append(
                        f"Status mismatch for {serial}: NB='{nb_device.status}', Meraki='{meraki_status}', Expected='{expected_status}'"
                    )
                    if commit:
                        nb_device.tags.add(status_tag)
            else:
                # Status matches — remove tag if present
                if commit and status_tag in nb_device.tags.all():
                    nb_device.tags.remove(status_tag)

            # IP match
            expected_ip = dev.get("wanIp") if dev.get("model", "").startswith("MX") else dev.get("lanIp")
            if nb_device.primary_ip and str(nb_device.primary_ip.address).split("/")[0] != expected_ip:
                mismatches.append(f"IP mismatch for {serial}: NB='{nb_device.primary_ip}', Meraki='{expected_ip}'")

            # Firmware match
            expected_fw = dev.get("firmware", "")
            actual_fw = nb_device.custom_field_data.get("lindab_firmware_ver", "")
            firmware_mismatch = expected_fw and actual_fw != expected_fw

            if firmware_mismatch:
                mismatches.append(f"Firmware mismatch for {serial}: NB='{actual_fw}', Meraki='{expected_fw}'")
                if commit:
                    nb_device.tags.add(firmware_tag)
            else:
                # Firmware matches — remove tag if present
                if commit and firmware_tag in nb_device.tags.all():
                    nb_device.tags.remove(firmware_tag)

            if commit:
                nb_device.save()

        if not mismatches:
            return "✅ All Meraki device records match NetBox."

        return "\n".join(mismatches)

    def _get_role_from_model(self, model):
        if model.startswith("MR"):
            return "Access Point"
        elif model.startswith("MS"):
            return "Access Switch"
        elif model.startswith("MX") or model.startswith("MG"):
            return "Firewall"
        elif model.startswith("MA"):
            return "Aggregate Switch"
        return "N/A"
