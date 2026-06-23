"""
tag_eol_cisco_fortinet_devices.py

NetBox 4.5.0 custom script
--------------------------
Purpose:
    - Query Cisco lifecycle data using Cisco's authenticated EoX API
    - Read Fortinet lifecycle data from a CSV file on the NetBox server
    - Match NetBox devices against those lifecycle sources
    - Tag devices that are already EOL / EOS with the tag "EOL"
    - Log matched devices and print summary counters at the end

Design notes:
    - Cisco:
        * Uses OAuth2 client credentials
        * Looks up by Product ID first (DeviceType.part_number or model)
        * Falls back to Serial Number if needed
    - Fortinet:
        * Reads a CSV file from a server-side path
        * Uses configurable CSV column names so the script can adapt to the
          actual export format used in your environment

NetBox compatibility:
    - Written for NetBox 4.5.x custom scripts
"""

from __future__ import annotations

import csv
import os
from datetime import datetime, date
from urllib.parse import quote
from collections import defaultdict

import requests
from requests import RequestException
from django.db.models import Q
from django.forms.widgets import PasswordInput

from dcim.models import Device
from extras.models import Tag
from extras.scripts import Script, StringVar


class TagEOLCiscoFortinetDevices(Script):
    """
    Custom script to tag Cisco and Fortinet devices as EOL based on:
      - Cisco authenticated EoX API
      - Fortinet lifecycle CSV file
    """

    # ---------------------------------------------------------------------
    # User inputs shown in the NetBox UI
    # ---------------------------------------------------------------------

    cisco_client_id = StringVar(
        label="Cisco Client ID",
        description="Cisco Support API Client ID (OAuth2 client credentials).",
        required=False,
    )

    cisco_client_secret = StringVar(
        label="Cisco Client Secret",
        description="Cisco Support API Client Secret.",
        required=False,
        widget=PasswordInput,
    )

    fortinet_csv_path = StringVar(
        label="Fortinet CSV path",
        description=(
            "Absolute path on the NetBox server to the Fortinet lifecycle CSV file, "
            "for example: /opt/netbox/netbox/scripts/data/fortinet_eol.csv"
        ),
        required=False,
    )

    fortinet_identifier_column = StringVar(
        label="Fortinet CSV identifier column",
        description=(
            "Column name in the Fortinet CSV that identifies the product, "
            "for example: Product, SKU, Model, Part Number"
        ),
        default="Product",
        required=False,
    )

    fortinet_eol_date_column = StringVar(
        label="Fortinet CSV EOL/EOS date column",
        description=(
            "Column name in the Fortinet CSV that contains the EOL / EOS date, "
            "for example: End of Support, EOS, End of Service Life"
        ),
        default="End of Support",
        required=False,
    )

    class Meta:
        name = "Tag Cisco / Fortinet EOL Devices"
        description = (
            "Uses Cisco's authenticated EoX API and a Fortinet CSV file to identify "
            "EOL / EOS devices in NetBox, tag them with 'EOL', and print counters."
        )
        field_order = [
            "cisco_client_id",
            "cisco_client_secret",
            "fortinet_csv_path",
            "fortinet_identifier_column",
            "fortinet_eol_date_column",
        ]
        commit_default = True
        scheduling_enabled = True

    # ---------------------------------------------------------------------
    # Generic helpers
    # ---------------------------------------------------------------------

    def _today(self) -> date:
        """Return today's date."""
        return date.today()

    def _normalise(self, value):
        """
        Normalise identifiers for matching.

        The function:
            - casts to string
            - strips whitespace
            - uppercases the value
        """
        if value is None:
            return None

        value = str(value).strip()
        if not value:
            return None

        return value.upper()

    def _parse_date(self, value):
        """
        Parse a date from several known formats.

        Supports:
            - Cisco dict format: {"value": "YYYY-MM-DD", ...}
            - Plain strings:
                * YYYY-MM-DD
                * YYYY/MM/DD
                * DD-MM-YYYY
                * DD/MM/YYYY
        """
        if value is None:
            return None

        # Cisco often returns dates as dictionaries with a "value" key.
        if isinstance(value, dict):
            value = value.get("value")

        if value is None:
            return None

        value = str(value).strip()
        if not value or value in {"-", "N/A", "NONE"}:
            return None

        for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%d-%m-%Y", "%d/%m/%Y"):
            try:
                return datetime.strptime(value, fmt).date()
            except ValueError:
                continue

        return None

    def _chunked(self, items, size):
        """
        Yield the given list in fixed-size chunks.
        Useful because Cisco's API supports batching.
        """
        batch = []
        for item in items:
            batch.append(item)
            if len(batch) >= size:
                yield batch
                batch = []

        if batch:
            yield batch

    def _ensure_eol_tag(self):
        """
        Ensure the NetBox tag 'EOL' exists.

        This mirrors the tagging pattern already used in the existing
        tag-orphaned-meraki-devices.py script.
        """
        tag, _ = Tag.objects.get_or_create(
            slug="eol",
            defaults={
                "name": "EOL",
                "description": "Device is end-of-life / end-of-support",
                "color": "red",
            },
        )
        return tag

    def _device_vendor(self, device):
        """
        Return the lowercase device manufacturer name, if available.
        """
        manufacturer = getattr(getattr(device, "device_type", None), "manufacturer", None)
        if not manufacturer or not manufacturer.name:
            return None

        return str(manufacturer.name).strip().lower()

    def _device_identifier(self, device):
        """
        Preferred lifecycle identifier for the device.

        Order:
            1. DeviceType.part_number
            2. DeviceType.model
        """
        device_type = getattr(device, "device_type", None)
        if not device_type:
            return None

        part_number = getattr(device_type, "part_number", None)
        model = getattr(device_type, "model", None)

        return self._normalise(part_number or model)

    def _device_serial(self, device):
        """
        Return the device serial number in normalised form.
        """
        return self._normalise(getattr(device, "serial", None))

    # ---------------------------------------------------------------------
    # Cisco API helpers
    # ---------------------------------------------------------------------

    def _get_cisco_token(self, client_id, client_secret):
        """
        Obtain a Cisco bearer token using the documented OAuth2
        client-credentials flow.
        """
        token_url = "https://id.cisco.com/oauth2/default/v1/token"

        response = requests.post(
            token_url,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
            },
            timeout=60,
        )
        response.raise_for_status()

        payload = response.json()
        access_token = payload.get("access_token")
        if not access_token:
            raise RuntimeError("Cisco token response did not contain access_token.")

        return access_token

    def _select_best_cisco_record(self, records):
        """
        Cisco can return multiple EoX records for a single PID.
        Keep the record with the latest LastDateOfSupport.
        """
        def sort_key(record):
            lifecycle_date = self._parse_date(record.get("LastDateOfSupport"))
            return lifecycle_date or date.min

        return sorted(records, key=sort_key, reverse=True)[0]

    def _cisco_lookup_by_pid(self, bearer_token, product_ids):
        """
        Look up Cisco lifecycle entries by Product ID.

        The Cisco API supports up to 20 product IDs per request.
        Returns:
            dict[PID] = best record
        """
        headers = {
            "Authorization": f"Bearer {bearer_token}",
            "Accept": "application/json",
        }

        records_by_pid = defaultdict(list)

        for batch in self._chunked(sorted(set(product_ids)), 20):
            joined = ",".join(batch)
            encoded = quote(joined, safe=",=*")

            url = (
                "https://apix.cisco.com/supporttools/eox/rest/5/"
                f"EOXByProductID/1/{encoded}?responseencoding=json"
            )

            response = requests.get(url, headers=headers, timeout=120)
            response.raise_for_status()

            payload = response.json()
            records = payload.get("EOXRecord", [])
            if isinstance(records, dict):
                records = [records]

            for record in records:
                returned_pid = self._normalise(record.get("EOLProductID"))
                if returned_pid:
                    records_by_pid[returned_pid].append(record)

                input_value = self._normalise(record.get("EOXInputValue"))
                if input_value:
                    records_by_pid[input_value].append(record)

        return {
            pid: self._select_best_cisco_record(lines)
            for pid, lines in records_by_pid.items()
        }

    def _cisco_lookup_by_serial(self, bearer_token, serials):
        """
        Look up Cisco lifecycle entries by Serial Number.

        The Cisco API supports up to 20 serial numbers per request.
        Returns:
            dict[SERIAL] = record
        """
        headers = {
            "Authorization": f"Bearer {bearer_token}",
            "Accept": "application/json",
        }

        records_by_serial = {}

        for batch in self._chunked(sorted(set(serials)), 20):
            joined = ",".join(batch)
            encoded = quote(joined, safe=",")

            url = (
                "https://apix.cisco.com/supporttools/eox/rest/5/"
                f"EOXBySerialNumber/1/{encoded}?responseencoding=json"
            )

            response = requests.get(url, headers=headers, timeout=120)
            response.raise_for_status()

            payload = response.json()
            records = payload.get("EOXRecord", [])
            if isinstance(records, dict):
                records = [records]

            for record in records:
                input_value = self._normalise(record.get("EOXInputValue"))
                if input_value:
                    records_by_serial[input_value] = record

        return records_by_serial

    def _is_cisco_eol(self, record):
        """
        Determine whether a Cisco record is already EOL.

        Rule:
            EOL if LastDateOfSupport <= today
        """
        last_support = self._parse_date(record.get("LastDateOfSupport"))
        return bool(last_support and last_support <= self._today())

    # ---------------------------------------------------------------------
    # Fortinet CSV helpers
    # ---------------------------------------------------------------------

    def _detect_csv_dialect(self, file_path):
        """
        Detect whether the Fortinet CSV uses comma or semicolon separators.
        Falls back to csv.excel if sniffer cannot determine the dialect.
        """
        with open(file_path, "r", encoding="utf-8-sig", newline="") as handle:
            sample = handle.read(4096)
            handle.seek(0)

            try:
                return csv.Sniffer().sniff(sample, delimiters=",;")
            except csv.Error:
                return csv.excel

    def _load_fortinet_csv(self, file_path, identifier_column, eol_date_column):
        """
        Load Fortinet lifecycle data from a CSV file.

        Returns:
            dict[IDENTIFIER] = {
                "raw_identifier": original value,
                "eol_date": parsed date,
                "row": full CSV row
            }
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Fortinet CSV file does not exist: {file_path}")

        dialect = self._detect_csv_dialect(file_path)
        lifecycle_map = {}

        with open(file_path, "r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle, dialect=dialect)

            if not reader.fieldnames:
                raise ValueError("Fortinet CSV appears to be empty or missing headers.")

            missing = [
                col for col in [identifier_column, eol_date_column]
                if col not in reader.fieldnames
            ]
            if missing:
                raise ValueError(
                    f"Fortinet CSV is missing expected column(s): {', '.join(missing)}. "
                    f"Detected columns: {', '.join(reader.fieldnames)}"
                )

            for row in reader:
                raw_identifier = row.get(identifier_column)
                key = self._normalise(raw_identifier)
                if not key:
                    continue

                parsed_date = self._parse_date(row.get(eol_date_column))
                lifecycle_map[key] = {
                    "raw_identifier": raw_identifier,
                    "eol_date": parsed_date,
                    "row": row,
                }

        return lifecycle_map

    def _is_fortinet_eol(self, entry):
        """
        Determine whether a Fortinet CSV entry is already EOL / EOS.

        Rule:
            EOL if CSV EOL date <= today
        """
        date_value = entry.get("eol_date")
        return bool(date_value and date_value <= self._today())

    # ---------------------------------------------------------------------
    # Main logic
    # ---------------------------------------------------------------------

    def run(self, data, commit):
        """
        Main script entrypoint.
        """
        # Read form data.
        cisco_client_id = (data.get("cisco_client_id") or "").strip()
        cisco_client_secret = (data.get("cisco_client_secret") or "").strip()

        fortinet_csv_path = (data.get("fortinet_csv_path") or "").strip()
        fortinet_identifier_column = (data.get("fortinet_identifier_column") or "Product").strip()
        fortinet_eol_date_column = (data.get("fortinet_eol_date_column") or "End of Support").strip()

        # Ensure the EOL tag exists.
        eol_tag = self._ensure_eol_tag()

        # Collect Cisco and Fortinet devices from NetBox.
        devices = (
            Device.objects
            .select_related("site", "device_type__manufacturer")
            .filter(
                Q(device_type__manufacturer__name__icontains="cisco") |
                Q(device_type__manufacturer__name__icontains="fortinet")
            )
            .order_by("name")
        )

        cisco_devices = []
        fortinet_devices = []

        for device in devices:
            vendor = self._device_vendor(device)
            if not vendor:
                self.log_warning(
                    f"{device.name or '[unnamed device]'}: Missing manufacturer on device type."
                )
                continue

            if "cisco" in vendor:
                cisco_devices.append(device)
            elif "fortinet" in vendor:
                fortinet_devices.append(device)

        self.log_info(f"Cisco devices found: {len(cisco_devices)}")
        self.log_info(f"Fortinet devices found: {len(fortinet_devices)}")

        # -----------------------------------------------------------------
        # Cisco lookups
        # -----------------------------------------------------------------
        cisco_records_by_pid = {}
        cisco_records_by_serial = {}

        if cisco_devices:
            if not cisco_client_id or not cisco_client_secret:
                self.log_warning(
                    "Cisco credentials were not supplied, so Cisco EOL checks are skipped."
                )
            else:
                try:
                    bearer_token = self._get_cisco_token(
                        cisco_client_id,
                        cisco_client_secret,
                    )

                    pid_list = [
                        self._device_identifier(device)
                        for device in cisco_devices
                        if self._device_identifier(device)
                    ]
                    serial_list = [
                        self._device_serial(device)
                        for device in cisco_devices
                        if self._device_serial(device)
                    ]

                    if pid_list:
                        cisco_records_by_pid = self._cisco_lookup_by_pid(
                            bearer_token,
                            pid_list,
                        )
                        self.log_info(
                            f"Cisco Product ID lookups completed: {len(set(pid_list))} identifiers."
                        )

                    if serial_list:
                        cisco_records_by_serial = self._cisco_lookup_by_serial(
                            bearer_token,
                            serial_list,
                        )
                        self.log_info(
                            f"Cisco serial lookups completed: {len(set(serial_list))} serials."
                        )

                except RequestException as exc:
                    self.log_failure(f"Cisco API request failed: {exc}")
                except Exception as exc:
                    self.log_failure(f"Cisco lookup failed: {exc}")

        # -----------------------------------------------------------------
        # Fortinet CSV load
        # -----------------------------------------------------------------
        fortinet_lifecycle = {}

        if fortinet_devices:
            if not fortinet_csv_path:
                self.log_warning(
                    "Fortinet CSV path was not supplied, so Fortinet EOL checks are skipped."
                )
            else:
                try:
                    fortinet_lifecycle = self._load_fortinet_csv(
                        fortinet_csv_path,
                        fortinet_identifier_column,
                        fortinet_eol_date_column,
                    )
                    self.log_info(
                        f"Fortinet CSV loaded successfully: {len(fortinet_lifecycle)} lifecycle entries."
                    )
                except Exception as exc:
                    self.log_failure(f"Fortinet CSV load failed: {exc}")

        # -----------------------------------------------------------------
        # Evaluate devices and tag EOL devices
        # -----------------------------------------------------------------
        evaluated = 0
        no_match = 0
        total_eol = 0
        cisco_eol = 0
        fortinet_eol = 0
        newly_tagged = 0
        already_tagged = 0

        # Cisco evaluation
        for device in cisco_devices:
            evaluated += 1

            identifier = self._device_identifier(device)
            serial = self._device_serial(device)

            record = None
            source = None

            # Prefer Product ID
            if identifier and identifier in cisco_records_by_pid:
                record = cisco_records_by_pid[identifier]
                source = f"PID:{identifier}"

            # Fallback to Serial
            elif serial and serial in cisco_records_by_serial:
                record = cisco_records_by_serial[serial]
                source = f"SERIAL:{serial}"

            if not record:
                no_match += 1
                self.log_warning(
                    f"[Cisco] No lifecycle match for device={device.name}, "
                    f"site={device.site.name if device.site else '-'}, "
                    f"identifier={identifier}, serial={serial}"
                )
                continue

            if self._is_cisco_eol(record):
                total_eol += 1
                cisco_eol += 1

                already_present = device.tags.filter(slug="eol").exists()

                if commit and not already_present:
                    device.tags.add(eol_tag)
                    device.save()

                if already_present:
                    already_tagged += 1
                else:
                    newly_tagged += 1

                last_support = self._parse_date(record.get("LastDateOfSupport"))
                matched_pid = record.get("EOLProductID")
                bulletin = record.get("ProductBulletinNumber")

                self.log_success(
                    f"[Cisco][EOL] device={device.name} | "
                    f"site={device.site.name if device.site else '-'} | "
                    f"matched_pid={matched_pid} | "
                    f"last_date_of_support={last_support} | "
                    f"bulletin={bulletin} | "
                    f"lookup_source={source}"
                )

        # Fortinet evaluation
        for device in fortinet_devices:
            evaluated += 1

            identifier = self._device_identifier(device)
            serial = self._device_serial(device)

            # For Fortinet CSV matching, prefer identifier first; optionally try serial
            # if your CSV is based on serial numbers instead of product identifiers.
            entry = None
            source = None

            if identifier and identifier in fortinet_lifecycle:
                entry = fortinet_lifecycle[identifier]
                source = f"CSV_ID:{identifier}"
            elif serial and serial in fortinet_lifecycle:
                entry = fortinet_lifecycle[serial]
                source = f"CSV_SERIAL:{serial}"

            if not entry:
                no_match += 1
                self.log_warning(
                    f"[Fortinet] No lifecycle match for device={device.name}, "
                    f"site={device.site.name if device.site else '-'}, "
                    f"identifier={identifier}, serial={serial}"
                )
                continue

            if self._is_fortinet_eol(entry):
                total_eol += 1
                fortinet_eol += 1

                already_present = device.tags.filter(slug="eol").exists()

                if commit and not already_present:
                    device.tags.add(eol_tag)
                    device.save()

                if already_present:
                    already_tagged += 1
                else:
                    newly_tagged += 1

                self.log_success(
                    f"[Fortinet][EOL] device={device.name} | "
                    f"site={device.site.name if device.site else '-'} | "
                    f"csv_identifier={entry.get('raw_identifier')} | "
                    f"eol_date={entry.get('eol_date')} | "
                    f"lookup_source={source}"
                )

        # -----------------------------------------------------------------
        # Final summary
        # -----------------------------------------------------------------
        summary = (
            "\n"
            "==== EOL Summary ====\n"
            f"Evaluated devices: {evaluated}\n"
            f"Cisco devices found: {len(cisco_devices)}\n"
            f"Fortinet devices found: {len(fortinet_devices)}\n"
            f"EOL devices total: {total_eol}\n"
            f" - Cisco EOL: {cisco_eol}\n"
            f" - Fortinet EOL: {fortinet_eol}\n"
            f"Newly tagged with 'EOL': {newly_tagged}\n"
            f"Already tagged with 'EOL': {already_tagged}\n"
            f"No lifecycle match found: {no_match}\n"
            f"Commit mode: {commit}\n"
        )

        self.log_info(summary)
        return summary
