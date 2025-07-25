# netbox/extras/scripts/meraki_inventory_report.py

from extras.scripts import Script, StringVar, BooleanVar
from dcim.models import Device, DeviceType, DeviceRole, Manufacturer, Site
import requests
from collections import Counter


class MerakiInventoryReport(Script):
    api_key = StringVar(
        label="Meraki API Key",
        description="Your Cisco Meraki API key"
    )

    show_orphaned = BooleanVar(
        label="Show orphaned NetBox devices",
        description="Devices in NetBox but not found in Meraki",
        default=True
    )

    show_import_eval = BooleanVar(
        label="Show importable/skipped Meraki devices",
        description="Breakdown of devices that can or cannot be imported",
        default=True
    )

    class Meta:
        name = "Meraki Inventory Report"
        description = "Summarize Meraki devices: importable, existing, orphaned (NetBox-only)"
        field_order = ["api_key", "show_orphaned", "show_import_eval"]

    def run(self, data, commit):
        api_key = data["api_key"]
        headers = {
            "X-Cisco-Meraki-API-Key": api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        try:
            orgs = requests.get("https://api.meraki.com/api/v1/organizations", headers=headers).json()
            if not orgs or "id" not in orgs[0]:
                self.log_failure("❌ No organizations found from Meraki API.")
                return
            org_id = orgs[0]["id"]
        except Exception as e:
            self.log_failure(f"❌ Error fetching organizations: {str(e)}")
            return

        try:
            devices = requests.get(
                f"https://api.meraki.com/api/v1/organizations/{org_id}/devices", headers=headers
            ).json()
        except Exception as e:
            self.log_failure(f"❌ Error fetching Meraki devices: {str(e)}")
            return

        try:
            meraki_manufacturer = Manufacturer.objects.get(name="Cisco Meraki")
        except Manufacturer.DoesNotExist:
            self.log_failure("❌ Manufacturer 'Cisco Meraki' not found in NetBox.")
            return

        total_devices = len(devices)
        importable_count = 0
        skipped_count = 0
        model_counter = Counter()
        meraki_serials_in_dashboard = set()
        importable_devices = []
        skipped_devices = []

        for dev in devices:
            model = dev.get("model", "")
            serial = dev.get("serial", "")
            name = dev.get("name", "")
            firmware = dev.get("firmware", "")
            role_name = self._get_role_from_model(model)

            meraki_serials_in_dashboard.add(serial)
            model_counter[model] += 1

            if Device.objects.filter(serial=serial).exists():
                skipped_count += 1
                if data["show_import_eval"]:
                    skipped_devices.append(f"{name} ({serial}) — Already exists in NetBox")
                continue

            if not DeviceType.objects.filter(model=model).exists():
                skipped_count += 1
                if data["show_import_eval"]:
                    skipped_devices.append(f"{name} ({serial}) — Missing DeviceType '{model}'")
                continue

            if not DeviceRole.objects.filter(name=role_name).exists():
                skipped_count += 1
                if data["show_import_eval"]:
                    skipped_devices.append(f"{name} ({serial}) — Missing DeviceRole '{role_name}'")
                continue

            importable_count += 1
            if data["show_import_eval"]:
                importable_devices.append(f"{name} ({serial}) — {model}, Firmware: {firmware}")

        orphaned_serials = []
        if data["show_orphaned"]:
            netbox_meraki_serials = Device.objects.filter(
                device_type__manufacturer=meraki_manufacturer
            ).values_list("serial", flat=True)
            orphaned_serials = [s for s in netbox_meraki_serials if s not in meraki_serials_in_dashboard]

        # Build human-readable summary
        output_lines = [
            f"📦 Total Meraki Devices Found in Dashboard: {total_devices}",
            f"✅ Devices Importable to NetBox: {importable_count}",
            f"⛔ Devices Skipped (duplicate or missing info): {skipped_count}",
            f"🧩 Orphaned Devices in NetBox (not in Meraki): {len(orphaned_serials)}",
            "",
            "📊 Device Counts by Model:"
        ]

        for model, count in model_counter.items():
            output_lines.append(f" - {model}: {count}")

        if data["show_import_eval"]:
            output_lines.append("\n✅ Devices That Would Be Imported:")
            output_lines.extend(importable_devices or ["(None)"])

            output_lines.append("\n⛔ Devices That Would Be Skipped:")
            output_lines.extend(skipped_devices or ["(None)"])

        if data["show_orphaned"]:
            output_lines.append("\n🧾 Orphaned Devices in NetBox:")
            output_lines.extend(orphaned_serials or ["(None)"])

        return "\n".join(output_lines)

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
