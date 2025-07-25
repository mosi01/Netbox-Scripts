from extras.scripts import Script, StringVar
from dcim.models import Device, Manufacturer
from dcim.choices import DeviceStatusChoices
from extras.models import Tag
import requests

class TagOrphanedMerakiDevices(Script):
    api_key = StringVar(
        label="Meraki API Key",
        description="Your Cisco Meraki API key"
    )

    class Meta:
        name = "Tag Orphaned Meraki Devices"
        description = (
            "Tag Cisco Meraki devices in NetBox not present in the Meraki Dashboard "
            "with tag 'Orphaned' and set their status to 'Offline'. Devices currently in 'Inventory' status are skipped."
        )
        field_order = ["api_key"]

    def run(self, data, commit):
        api_key = data["api_key"]
        headers = {
            "X-Cisco-Meraki-API-Key": api_key,
            "Accept": "application/json",
        }

        # Fetch Meraki org and devices
        try:
            orgs = requests.get("https://api.meraki.com/api/v1/organizations", headers=headers).json()
            org_id = orgs[0].get("id")
            if not org_id:
                self.log_failure("❌ No Meraki organization found.")
                return
        except Exception as e:
            self.log_failure(f"❌ Meraki org error: {e}")
            return

        try:
            dashboard = requests.get(
                f"https://api.meraki.com/api/v1/organizations/{org_id}/devices", headers=headers
            ).json()
        except Exception as e:
            self.log_failure(f"❌ Error fetching Meraki devices: {e}")
            return

        dashboard_serials = {d.get("serial") for d in dashboard if d.get("serial")}

        # Ensure manufacturer and tag exist
        try:
            manufacturer = Manufacturer.objects.get(name="Cisco Meraki")
        except Manufacturer.DoesNotExist:
            self.log_failure("❌ Manufacturer 'Cisco Meraki' not found in NetBox.")
            return

        try:
            orphaned_tag = Tag.objects.get(slug="orphaned")
        except Tag.DoesNotExist:
            self.log_failure("❌ Tag with slug='orphaned' not found.")
            return

        # Identify orphaned devices (Meraki in NetBox but not in dashboard), skipping Inventory
        orphaned = Device.objects.filter(
            device_type__manufacturer=manufacturer
        ).exclude(
            serial__in=dashboard_serials
        ).exclude(
            status=DeviceStatusChoices.STATUS_INVENTORY
        )

        offline_status = DeviceStatusChoices.STATUS_OFFLINE
        updated = 0

        for dev in orphaned:
            if commit:
                dev.status = offline_status
                dev.tags.add(orphaned_tag)
                dev.save()
            updated += 1

        if updated:
            self.log_success(f"✅ {updated} orphaned Meraki device(s) tagged and set to Offline.")
        else:
            self.log_info("ℹ️ No orphaned Meraki devices found (excluding 'Inventory').")
