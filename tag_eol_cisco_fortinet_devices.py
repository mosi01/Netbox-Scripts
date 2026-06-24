"""
tag_eol_cisco_fortinet_devices.py

NetBox custom script
--------------------
Purpose:
    - Cisco:
        * If "Use API" is unchecked:
            - Use Cisco EOL CSV only
            - Do not call Cisco API
        * If "Use API" is checked:
            - Use Cisco API only
            - Do not load or use Cisco CSV
    - Fortinet:
        * Use Fortinet EOL CSV only
    - Tag EOL/EOS devices with "EOL"
    - Print detailed logs and counters

Recommended Cisco CSV example:
    Product,LastDateOfSupport
    C9300-48P,2029-10-31
    ISR4331/K9,2026-12-31

Recommended Fortinet CSV example:
    Product,End of Support
    FG-100F,2030-01-01
    FG-200E,2028-06-30
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
from extras.scripts import Script, StringVar, BooleanVar


class TagEOLCiscoFortinetDevices(Script):
    """
    Tags Cisco and Fortinet devices as EOL based on:
      - Cisco CSV only when Use API is unchecked
      - Cisco API only when Use API is checked
      - Fortinet CSV only
    """

    # ---------------------------------------------------------------------
    # Cisco mode selector
    # ---------------------------------------------------------------------

    use_api = BooleanVar(
        label="Use API",
        description=(
            "Unchecked = Cisco EOL is checked using Cisco CSV only. "
            "Checked = Cisco EOL is checked using Cisco API only."
        ),
        default=False,
        required=False,
    )

    # ---------------------------------------------------------------------
    # Cisco API inputs
    # Not mandatory in the form
    # ---------------------------------------------------------------------

    cisco_client_id = StringVar(
        label="Cisco Client ID",
        description=(
            "Cisco Support APIs / EoX Client ID. "
            "Only used when 'Use API' is checked."
        ),
        required=False,
    )

    cisco_client_secret = StringVar(
        label="Cisco Client Secret",
        description=(
            "Cisco Support APIs / EoX Client Secret. "
            "Only used when 'Use API' is checked."
        ),
        required=False,
        widget=PasswordInput,
    )

    # ---------------------------------------------------------------------
    # Cisco CSV inputs
    # Not mandatory in the form
    # ---------------------------------------------------------------------

    cisco_csv_path = StringVar(
        label="Cisco EOL CSV path",
        description=(
            "Absolute path on the NetBox server to the Cisco EOL CSV file. "
            "Only used when 'Use API' is unchecked. "
            "Example: /opt/netbox/netbox/scripts/Cisco_EOL.csv"
        ),
        required=False,
    )

    cisco_identifier_column = StringVar(
        label="Cisco CSV identifier column",
        description=(
            "Column name in the Cisco CSV that identifies the product or serial. "
            "Examples: Product, PID, SKU, Model, Serial"
        ),
        default="Product",
        required=False,
    )

    cisco_eol_date_column = StringVar(
        label="Cisco CSV EOL date column",
        description=(
            "Column name in the Cisco CSV containing the EOL / Last Date of Support. "
            "Examples: LastDateOfSupport, Last Date of Support, End of Support"
        ),
        default="LastDateOfSupport",
        required=False,
    )

    # ---------------------------------------------------------------------
    # Fortinet CSV inputs
    # Not mandatory in the form
    # ---------------------------------------------------------------------

    fortinet_csv_path = StringVar(
        label="Fortinet EOL CSV path",
        description=(
            "Absolute path on the NetBox server to the Fortinet lifecycle CSV file. "
            "Example: /opt/netbox/netbox/scripts/Fortinet_EOL_260623.csv"
        ),
        required=False,
    )

    fortinet_identifier_column = StringVar(
        label="Fortinet CSV identifier column",
        description=(
            "Column name in the Fortinet CSV that identifies the product. "
            "Examples: Product, SKU, Model, Part Number, Serial"
        ),
        default="Product",
        required=False,
    )

    fortinet_eol_date_column = StringVar(
        label="Fortinet CSV EOL/EOS date column",
        description=(
            "Column name in the Fortinet CSV containing the End of Support / EOS date. "
            "Examples: End of Support, EOS, End of Service Life"
        ),
        default="End of Support",
        required=False,
    )

    class Meta:
        name = "Tag Cisco / Fortinet EOL Devices"
        description = (
            "Checks Cisco EOL using either CSV or API depending on the 'Use API' checkbox. "
            "Checks Fortinet EOL using CSV. Tags EOL devices with 'EOL' and prints counters."
        )
        field_order = [
            "use_api",
            "cisco_client_id",
            "cisco_client_secret",
            "cisco_csv_path",
            "cisco_identifier_column",
            "cisco_eol_date_column",
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
        return date.today()

    def _clean_path(self, value):
        """
        Clean path input from accidental surrounding quotes or trailing apostrophes.
        """
        if value is None:
            return ""

        value = str(value).strip()

        # Remove surrounding quotes if user pasted them
        value = value.strip("'").strip('"').strip()

        return value

    def _normalise(self, value):
        """
        Normalise identifiers for matching.

        Example:
            " fg-100f " -> "FG-100F"
        """
        if value is None:
            return None

        value = str(value).strip()
        if not value:
            return None

        return value.upper()

    def _parse_date(self, value):
        """
        Parse dates from:
            - Cisco API dict format:
                {"value": "2029-10-31", "dateFormat": "YYYY-MM-DD"}
            - Plain strings:
                YYYY-MM-DD
                YYYY/MM/DD
                DD-MM-YYYY
                DD/MM/YYYY
        """
        if value is None:
            return None

        if isinstance(value, dict):
            value = value.get("value")

        if value is None:
            return None

        value = str(value).strip()

        if not value or value.upper() in {"-", "N/A", "NONE", "NULL"}:
            return None

        for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%d-%m-%Y", "%d/%m/%Y"):
            try:
                return datetime.strptime(value, fmt).date()
            except ValueError:
                continue

        return None

    def _chunked(self, items, size):
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
        Uses NetBox colour value f44336, which is red.
        """
        tag, _ = Tag.objects.get_or_create(
            slug="eol",
            defaults={
                "name": "EOL",
                "description": "Device is end-of-life / end-of-support",
                "color": "f44336",
            },
        )
        return tag

    def _device_vendor(self, device):
        manufacturer = getattr(getattr(device, "device_type", None), "manufacturer", None)

        if not manufacturer or not manufacturer.name:
            return None

        return str(manufacturer.name).strip().lower()

    def _device_identifier(self, device):
        """
        Preferred lifecycle identifier.

        Order:
            1. Device Type Part Number
            2. Device Type Model
        """
        device_type = getattr(device, "device_type", None)

        if not device_type:
            return None

        part_number = getattr(device_type, "part_number", None)
        model = getattr(device_type, "model", None)

        return self._normalise(part_number or model)

    def _device_serial(self, device):
        return self._normalise(getattr(device, "serial", None))

    def _tag_device(self, device, tag, commit):
        """
        Add EOL tag to a device if not already present.

        Returns:
            True  = tag already existed
            False = tag did not exist before this run
        """
        already_present = device.tags.filter(slug=tag.slug).exists()

        if commit and not already_present:
            device.tags.add(tag)
            device.save()

        return already_present

    # ---------------------------------------------------------------------
    # Generic CSV loader
    # ---------------------------------------------------------------------

    def _detect_csv_dialect(self, file_path):
        """
        Detect comma or semicolon delimiter.
        Defaults to standard CSV if detection fails.
        """
        with open(file_path, "r", encoding="utf-8-sig", newline="") as handle:
            sample = handle.read(4096)

        try:
            return csv.Sniffer().sniff(sample, delimiters=",;")
        except csv.Error:
            return csv.excel

    def _load_lifecycle_csv(self, file_path, identifier_column, eol_date_column, label):
        """
        Load lifecycle CSV into a dictionary.

        Returns:
            {
                "NORMALISED_IDENTIFIER": {
                    "raw_identifier": "...",
                    "eol_date": date(...),
                    "row": {...}
                }
            }
        """
        if not file_path:
            return {}

        file_path = self._clean_path(file_path)

        if not os.path.exists(file_path):
            raise FileNotFoundError(f"{label} CSV file does not exist: {file_path}")

        dialect = self._detect_csv_dialect(file_path)
        lifecycle_map = {}

        with open(file_path, "r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle, dialect=dialect)

            if not reader.fieldnames:
                raise ValueError(f"{label} CSV is empty or missing headers.")

            missing_columns = [
                column
                for column in [identifier_column, eol_date_column]
                if column not in reader.fieldnames
            ]

            if missing_columns:
                raise ValueError(
                    f"{label} CSV is missing column(s): {', '.join(missing_columns)}. "
                    f"Detected columns: {', '.join(reader.fieldnames)}"
                )

            for row in reader:
                raw_identifier = row.get(identifier_column)
                key = self._normalise(raw_identifier)

                if not key:
                    continue

                lifecycle_map[key] = {
                    "raw_identifier": raw_identifier,
                    "eol_date": self._parse_date(row.get(eol_date_column)),
                    "row": row,
                }

        return lifecycle_map

    def _is_csv_eol(self, entry):
        eol_date = entry.get("eol_date")
        return bool(eol_date and eol_date <= self._today())

    # ---------------------------------------------------------------------
    # Cisco API helpers
    # ---------------------------------------------------------------------

    def _get_cisco_token(self, client_id, client_secret):
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
        token = payload.get("access_token")

        if not token:
            raise RuntimeError("Cisco token response did not include access_token.")

        return token

    def _select_best_cisco_record(self, records):
        """
        Cisco can return multiple EoX records for the same PID.
        Select the one with the latest LastDateOfSupport.
        """
        def sort_key(record):
            return self._parse_date(record.get("LastDateOfSupport")) or date.min

        return sorted(records, key=sort_key, reverse=True)[0]

    def _cisco_lookup_by_pid(self, bearer_token, product_ids):
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
                input_value = self._normalise(record.get("EOXInputValue"))

                if returned_pid:
                    records_by_pid[returned_pid].append(record)

                if input_value:
                    records_by_pid[input_value].append(record)

        return {
            pid: self._select_best_cisco_record(records)
            for pid, records in records_by_pid.items()
        }

    def _cisco_lookup_by_serial(self, bearer_token, serials):
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

    def _is_cisco_api_eol(self, record):
        last_support = self._parse_date(record.get("LastDateOfSupport"))
        return bool(last_support and last_support <= self._today())

    # ---------------------------------------------------------------------
    # Main
    # ---------------------------------------------------------------------

    def run(self, data, commit):
        eol_tag = self._ensure_eol_tag()

        use_api = data.get("use_api", False)

        cisco_client_id = (data.get("cisco_client_id") or "").strip()
        cisco_client_secret = (data.get("cisco_client_secret") or "").strip()

        cisco_csv_path = self._clean_path(data.get("cisco_csv_path") or "")
        cisco_identifier_column = (data.get("cisco_identifier_column") or "Product").strip()
        cisco_eol_date_column = (data.get("cisco_eol_date_column") or "LastDateOfSupport").strip()

        fortinet_csv_path = self._clean_path(data.get("fortinet_csv_path") or "")
        fortinet_identifier_column = (data.get("fortinet_identifier_column") or "Product").strip()
        fortinet_eol_date_column = (data.get("fortinet_eol_date_column") or "End of Support").strip()

        self.log_info(f"Cisco Use API mode: {use_api}")

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
                    f"{device.name or '[unnamed]'}: Missing manufacturer on device type."
                )
                continue

            if "cisco" in vendor:
                cisco_devices.append(device)
            elif "fortinet" in vendor:
                fortinet_devices.append(device)

        self.log_info(f"Cisco devices found: {len(cisco_devices)}")
        self.log_info(f"Fortinet devices found: {len(fortinet_devices)}")

        # -----------------------------------------------------------------
        # Source state
        # -----------------------------------------------------------------

        cisco_csv_lifecycle = {}
        cisco_api_available = False
        cisco_records_by_pid = {}
        cisco_records_by_serial = {}

        fortinet_lifecycle = {}

        cisco_source_enabled = False
        fortinet_source_enabled = False

        # -----------------------------------------------------------------
        # Cisco source selection
        # -----------------------------------------------------------------

        if use_api:
            # Cisco API ONLY
            self.log_info("Cisco mode selected: API only. Cisco CSV will not be loaded.")

            if not cisco_client_id or not cisco_client_secret:
                self.log_warning(
                    "Use API is checked, but Cisco Client ID and/or Cisco Client Secret is missing. "
                    "Cisco EOL checks will be skipped."
                )
            else:
                try:
                    token = self._get_cisco_token(cisco_client_id, cisco_client_secret)
                    cisco_api_available = True
                    cisco_source_enabled = True

                    cisco_pids = [
                        self._device_identifier(device)
                        for device in cisco_devices
                        if self._device_identifier(device)
                    ]

                    cisco_serials = [
                        self._device_serial(device)
                        for device in cisco_devices
                        if self._device_serial(device)
                    ]

                    if cisco_pids:
                        cisco_records_by_pid = self._cisco_lookup_by_pid(token, cisco_pids)
                        self.log_info(
                            f"Cisco API PID lookups completed: {len(set(cisco_pids))} unique identifiers."
                        )

                    if cisco_serials:
                        cisco_records_by_serial = self._cisco_lookup_by_serial(token, cisco_serials)
                        self.log_info(
                            f"Cisco API serial lookups completed: {len(set(cisco_serials))} unique serials."
                        )

                except RequestException as exc:
                    self.log_failure(
                        f"Cisco API request failed. Since Use API is checked, Cisco CSV will not be used. "
                        f"Error: {exc}"
                    )
                except Exception as exc:
                    self.log_failure(
                        f"Cisco API lookup failed. Since Use API is checked, Cisco CSV will not be used. "
                        f"Error: {exc}"
                    )

        else:
            # Cisco CSV ONLY
            self.log_info("Cisco mode selected: CSV only. Cisco API will not be called.")

            if not cisco_csv_path:
                self.log_warning(
                    "Use API is unchecked, but Cisco CSV path is missing. "
                    "Cisco EOL checks will be skipped."
                )
            else:
                try:
                    cisco_csv_lifecycle = self._load_lifecycle_csv(
                        cisco_csv_path,
                        cisco_identifier_column,
                        cisco_eol_date_column,
                        "Cisco",
                    )

                    cisco_source_enabled = True

                    self.log_info(
                        f"Cisco CSV loaded: {len(cisco_csv_lifecycle)} entries."
                    )

                except Exception as exc:
                    self.log_failure(f"Cisco CSV load failed: {exc}")

        # -----------------------------------------------------------------
        # Fortinet CSV load
        # -----------------------------------------------------------------

        if not fortinet_csv_path:
            self.log_warning(
                "Fortinet CSV path is missing. Fortinet EOL checks will be skipped."
            )
        else:
            try:
                fortinet_lifecycle = self._load_lifecycle_csv(
                    fortinet_csv_path,
                    fortinet_identifier_column,
                    fortinet_eol_date_column,
                    "Fortinet",
                )

                fortinet_source_enabled = True

                self.log_info(
                    f"Fortinet CSV loaded: {len(fortinet_lifecycle)} entries."
                )

            except Exception as exc:
                self.log_failure(f"Fortinet CSV load failed: {exc}")

        # -----------------------------------------------------------------
        # Evaluation counters
        # -----------------------------------------------------------------

        evaluated = 0
        skipped_due_to_missing_source = 0
        total_eol = 0

        cisco_eol_api = 0
        cisco_eol_csv = 0
        fortinet_eol_csv = 0

        newly_tagged = 0
        already_tagged = 0
        no_match = 0

        # -----------------------------------------------------------------
        # Cisco evaluation
        # -----------------------------------------------------------------

        if not cisco_source_enabled:
            skipped_due_to_missing_source += len(cisco_devices)
            self.log_warning(
                f"Cisco EOL checks skipped for {len(cisco_devices)} devices because no Cisco source is available."
            )
        else:
            for device in cisco_devices:
                evaluated += 1

                identifier = self._device_identifier(device)
                serial = self._device_serial(device)

                # ---------------------------------------------------------
                # Cisco API ONLY mode
                # ---------------------------------------------------------

                if use_api:
                    api_record = None

                    if identifier and identifier in cisco_records_by_pid:
                        api_record = cisco_records_by_pid[identifier]
                    elif serial and serial in cisco_records_by_serial:
                        api_record = cisco_records_by_serial[serial]

                    if not api_record:
                        no_match += 1
                        self.log_warning(
                            f"[Cisco][API] No lifecycle match for device={device.name} | "
                            f"site={device.site.name if device.site else '-'} | "
                            f"identifier={identifier} | serial={serial}"
                        )
                        continue

                    if self._is_cisco_api_eol(api_record):
                        total_eol += 1
                        cisco_eol_api += 1

                        was_already_tagged = self._tag_device(device, eol_tag, commit)

                        if was_already_tagged:
                            already_tagged += 1
                        else:
                            newly_tagged += 1

                        last_support = self._parse_date(api_record.get("LastDateOfSupport"))

                        self.log_success(
                            f"[Cisco][API][EOL] device={device.name} | "
                            f"site={device.site.name if device.site else '-'} | "
                            f"identifier={identifier} | serial={serial} | "
                            f"last_date_of_support={last_support} | "
                            f"matched_pid={api_record.get('EOLProductID')}"
                        )

                    continue

                # ---------------------------------------------------------
                # Cisco CSV ONLY mode
                # ---------------------------------------------------------

                csv_entry = None

                if identifier and identifier in cisco_csv_lifecycle:
                    csv_entry = cisco_csv_lifecycle[identifier]
                elif serial and serial in cisco_csv_lifecycle:
                    csv_entry = cisco_csv_lifecycle[serial]

                if not csv_entry:
                    no_match += 1
                    self.log_warning(
                        f"[Cisco][CSV] No lifecycle match for device={device.name} | "
                        f"site={device.site.name if device.site else '-'} | "
                        f"identifier={identifier} | serial={serial}"
                    )
                    continue

                if self._is_csv_eol(csv_entry):
                    total_eol += 1
                    cisco_eol_csv += 1

                    was_already_tagged = self._tag_device(device, eol_tag, commit)

                    if was_already_tagged:
                        already_tagged += 1
                    else:
                        newly_tagged += 1

                    self.log_success(
                        f"[Cisco][CSV][EOL] device={device.name} | "
                        f"site={device.site.name if device.site else '-'} | "
                        f"identifier={identifier} | serial={serial} | "
                        f"csv_identifier={csv_entry.get('raw_identifier')} | "
                        f"eol_date={csv_entry.get('eol_date')}"
                    )

        # -----------------------------------------------------------------
        # Fortinet evaluation
        # -----------------------------------------------------------------

        if not fortinet_source_enabled:
            skipped_due_to_missing_source += len(fortinet_devices)
            self.log_warning(
                f"Fortinet EOL checks skipped for {len(fortinet_devices)} devices because no Fortinet CSV source is available."
            )
        else:
            for device in fortinet_devices:
                evaluated += 1

                identifier = self._device_identifier(device)
                serial = self._device_serial(device)

                entry = None

                if identifier and identifier in fortinet_lifecycle:
                    entry = fortinet_lifecycle[identifier]
                elif serial and serial in fortinet_lifecycle:
                    entry = fortinet_lifecycle[serial]

                if not entry:
                    no_match += 1
                    self.log_warning(
                        f"[Fortinet][CSV] No lifecycle match for device={device.name} | "
                        f"site={device.site.name if device.site else '-'} | "
                        f"identifier={identifier} | serial={serial}"
                    )
                    continue

                if self._is_csv_eol(entry):
                    total_eol += 1
                    fortinet_eol_csv += 1

                    was_already_tagged = self._tag_device(device, eol_tag, commit)

                    if was_already_tagged:
                        already_tagged += 1
                    else:
                        newly_tagged += 1

                    self.log_success(
                        f"[Fortinet][CSV][EOL] device={device.name} | "
                        f"site={device.site.name if device.site else '-'} | "
                        f"identifier={identifier} | serial={serial} | "
                        f"csv_identifier={entry.get('raw_identifier')} | "
                        f"eol_date={entry.get('eol_date')}"
                    )

        # -----------------------------------------------------------------
        # Final summary
        # -----------------------------------------------------------------

        summary = (
            "\n"
            "==== EOL Summary ====\n"
            f"Evaluated devices: {evaluated}\n"
            f"Skipped due to missing source: {skipped_due_to_missing_source}\n"
            f"Cisco devices found: {len(cisco_devices)}\n"
            f"Fortinet devices found: {len(fortinet_devices)}\n"
            f"Cisco Use API mode: {use_api}\n"
            f"Cisco API authentication successful: {cisco_api_available}\n"
            f"Cisco CSV entries loaded: {len(cisco_csv_lifecycle)}\n"
            f"Fortinet CSV entries loaded: {len(fortinet_lifecycle)}\n"
            f"EOL devices total: {total_eol}\n"
            f" - Cisco EOL from API: {cisco_eol_api}\n"
            f" - Cisco EOL from CSV: {cisco_eol_csv}\n"
            f" - Fortinet EOL from CSV: {fortinet_eol_csv}\n"
            f"Newly tagged with EOL: {newly_tagged}\n"
            f"Already tagged with EOL: {already_tagged}\n"
            f"No lifecycle match: {no_match}\n"
            f"Commit mode: {commit}\n"
        )

        self.log_info(summary)
        return summary
