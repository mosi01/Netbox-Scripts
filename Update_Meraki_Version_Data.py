"""
Update Meraki Firmware Data Script for NetBox

This script synchronizes Cisco Meraki device firmware versions and status tags in NetBox.
It performs the following actions:
- Fetches all Cisco Meraki devices and their firmware versions from the Meraki Dashboard API.
- Fetches device availability (status) for all devices.
- Updates the 'lindab_firmware_ver' custom field on NetBox devices to match the Meraki-reported firmware.
- Applies or updates tags on devices that are not running the configured firmware version, based on their Meraki status.
- Removes tags from devices that are now running the configured version.
- Handles all known and unknown Meraki statuses, creating tags as needed.
- All tag and custom field operations are wrapped in try/except blocks to ensure the script continues on errors, which are logged.
- The output provides a per-device summary of firmware and tag changes, including explicit actions (added, removed, changed).

Requirements:
- NetBox with the 'lindab_firmware_ver' custom field on Device objects.
- NetBox must have a Manufacturer named 'Cisco Meraki'.
- The script must be run with a valid Cisco Meraki API key.

Author: Simon Möller Ahlquist, Lindab Group
Date: 2025-07-26
"""

from extras.scripts import Script, StringVar
from dcim.models import Device, Manufacturer
from extras.models import Tag
import requests

class UpdateMerakiFirmware(Script):
    api_key = StringVar(
        label="Meraki API Key",
        description="Your Cisco Meraki API key"
    )

    class Meta:
        name = "Update Meraki Firmware Data"
        description = (
            "Updates the lindab_firmware_ver custom field on NetBox devices with the firmware version from Meraki. "
            "Tags devices as not-updated, not-updated-offline, not-updated-warning, not-updated-dormant, etc. if not running configured version."
        )
        field_order = ["api_key"]

    def run(self, data, commit):
        # Get API key from user input
        api_key = data["api_key"]
        headers = {
            "X-Cisco-Meraki-API-Key": api_key,
            "Accept": "application/json"
        }

        # Fetch Meraki organizations
        orgs = requests.get("https://api.meraki.com/api/v1/organizations", headers=headers).json()
        if not orgs or not orgs[0].get("id"):
            self.log_failure("Manufacturer Cisco Meraki not found in NetBox.")
            return
        org_id = orgs[0]["id"]

        # Fetch all Meraki devices in the organization
        devices = requests.get(
            f"https://api.meraki.com/api/v1/organizations/{org_id}/devices", headers=headers
        ).json()

        # Fetch device availabilities (statuses) for all devices
        availabilities = requests.get(
            f"https://api.meraki.com/api/v1/organizations/{org_id}/devices/availabilities", headers=headers
        ).json()
        # Map serial number to status (lowercase)
        serial_status_map = {a["serial"]: a.get("status", "").lower() for a in availabilities if "serial" in a}

        # Get the Cisco Meraki manufacturer object from NetBox
        manufacturer = Manufacturer.objects.filter(name="Cisco Meraki").first()
        if not manufacturer:
            self.log_failure("Manufacturer Cisco Meraki not found in NetBox.")
            return

        # Define tag mapping for known Meraki statuses
        tag_map = {
            "online": ("not-updated", "ff6600"),
            "offline": ("not-updated-offline", "808080"),
            "warning": ("not-updated-warning", "ffcc00"),
            "dormant": ("not-updated-dormant", "b0b0b0"),
            "alerting": ("not-updated-warning", "ffcc00"),
        }
        # Add any unknown statuses dynamically to the tag map
        all_statuses = set(serial_status_map.values())
        for status in all_statuses:
            if status and status not in tag_map:
                tag_map[status] = (f"not-updated-{status}", "cccccc")

        # Ensure all tags exist in NetBox, create if missing
        tags = {}
        for status, (slug, color) in tag_map.items():
            tag, _ = Tag.objects.get_or_create(
                slug=slug,
                defaults={"name": slug.replace("-", " ").title(), "color": color}
            )
            tags[status] = tag

        # Prepare output lists
        output_rows = []
        not_running_rows = []

        # Process each Meraki device
        for dev in devices:
            serial = dev.get("serial")
            firmware = dev.get("firmware", "")
            meraki_status = serial_status_map.get(serial, "")
            if not serial or not firmware:
                continue

            # Normalize status for tagging (treat alerting as warning)
            if meraki_status == "alerting":
                meraki_status = "warning"

            # Find the corresponding NetBox device
            nb_device = Device.objects.filter(serial=serial, device_type__manufacturer=manufacturer).first()
            if not nb_device:
                continue

            # Get the old firmware version from the custom field
            old_fw = nb_device.custom_field_data.get("lindab_firmware_ver", "")
            fw_changed = old_fw != firmware

            # Find any existing not-updated tag on the device
            current_tags = list(nb_device.tags.filter(slug__in=[t[0] for t in tag_map.values()]))

            tag_action = ""
            tag_to_add = None
            old_tag = None

            # If device is not running configured version, handle tag logic
            if firmware == "Not running configured version":
                tag_to_add = tags.get(meraki_status)
                # If there is an old not-updated tag and it's not the correct one, change it
                if current_tags and tag_to_add and tag_to_add not in current_tags:
                    old_tag = current_tags[0]
                    if commit:
                        try:
                            nb_device.tags.remove(old_tag)
                            nb_device.tags.add(tag_to_add)
                            nb_device.save()
                            tag_action = f"Tag changed from: {old_tag.slug}, to: {tag_to_add.slug}"
                        except Exception as e:
                            self.log_failure(f"Failed to change tag from {old_tag.slug} to {tag_to_add.slug} on {nb_device.name} ({serial}): {e}")
                    else:
                        tag_action = f"Tag changed from: {old_tag.slug}, to: {tag_to_add.slug}"
                # If the correct tag is not present and no other not-updated tag, add it
                elif tag_to_add and not current_tags and tag_to_add not in nb_device.tags.all():
                    if commit:
                        try:
                            nb_device.tags.add(tag_to_add)
                            nb_device.save()
                            tag_action = f"Tag added: {tag_to_add.slug}"
                        except Exception as e:
                            self.log_failure(f"Failed to add tag {tag_to_add.slug} to {nb_device.name} ({serial}): {e}")
                    else:
                        tag_action = f"Tag added: {tag_to_add.slug}"
                # If there is an old not-updated tag and no new tag to add (unknown status), remove it
                elif not tag_to_add and current_tags:
                    old_tag = current_tags[0]
                    if commit:
                        try:
                            nb_device.tags.remove(old_tag)
                            nb_device.save()
                            tag_action = f"Tag removed: {old_tag.slug}"
                        except Exception as e:
                            self.log_failure(f"Failed to remove tag {old_tag.slug} from {nb_device.name} ({serial}): {e}")
                    else:
                        tag_action = f"Tag removed: {old_tag.slug}"
            else:
                # If device is now running configured version, remove all not-updated tags
                removed_tags = []
                for t in current_tags:
                    if commit:
                        try:
                            nb_device.tags.remove(t)
                            nb_device.save()
                            removed_tags.append(t.slug)
                        except Exception as e:
                            self.log_failure(f"Failed to remove tag {t.slug} from {nb_device.name} ({serial}): {e}")
                    else:
                        removed_tags.append(t.slug)
                if removed_tags:
                    tag_action = "Tag removed: " + ", ".join(removed_tags)

            # Update the firmware custom field if it has changed
            if fw_changed and commit:
                try:
                    nb_device.custom_field_data["lindab_firmware_ver"] = firmware
                    nb_device.save()
                except Exception as e:
                    self.log_failure(f"Failed to update firmware for {nb_device.name} ({serial}): {e}")

            # Only show in output if firmware or tags changed
            if fw_changed or tag_action:
                row = f"{nb_device.name} ({serial}): {old_fw} -> {firmware}"
                if firmware == "Not running configured version":
                    row += f", The device has status: {meraki_status}"
                    if tag_to_add:
                        row += f", tag set: {tag_to_add.slug}"
                if tag_action:
                    row += f" [{tag_action}]"
                output_rows.append(row)
                if firmware == "Not running configured version":
                    not_running_rows.append(row)

        # Prepare the final output
        output = []
        output.extend(output_rows)
        if not_running_rows:
            output.append("\nDevices with Not running configured version:")
            output.extend(not_running_rows)
        if not output_rows:
            output.append("No firmware or tag changes made.")

        return "\n".join(output)