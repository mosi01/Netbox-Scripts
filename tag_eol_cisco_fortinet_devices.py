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
    - Tag devices as EOL if their lifecycle date is in the past
    - Treat products as OK if the lifecycle column says SUPPORTED
    - Treat products as OK if lifecycle date is in the future
    - Print detailed counters

CSV format expected for both Cisco and Fortinet:
    Product,End of Life
    MX250,SUPPORTED
    MS225,2031-04-30
    AIR-AP2802I,2028-03-31

The headers are configurable in the script form:
    Product column       default: Product
    End of Life column   default: End of Life
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

    Cisco:
        - CSV only when Use API is unchecked
        - API only when Use API is checked

    Fortinet:
        - CSV only

    CSV logic:
        - If End of Life column contains SUPPORTED => OK / supported
        - If End of Life column contains a future date => OK / supported
        - If End of Life column contains a past date => EOL
        - If product is missing from CSV/API => No lifecycle match
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
    # Not mandatory
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
    # CSV paths
    # Not mandatory
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

    fortinet_csv_path = StringVar(
        label="Fortinet EOL CSV path",
        description=(
            "Absolute path on the NetBox server to the Fortinet EOL CSV file. "
            "Example: /opt/netbox/netbox/scripts/Fortinet_EOL_260623.csv"
        ),
        required=False,
    )

    # ---------------------------------------------------------------------
    # Shared CSV header configuration
    # Applies to BOTH Cisco and Fortinet CSV files
    # ---------------------------------------------------------------------

    product_column = StringVar(
        label="Product column",
        description=(
            "CSV column containing the product identifier. "
            "This same header is used for both Cisco and Fortinet CSV files."
        ),
        default="Product",
        required=False,
    )

    end_of_life_column = StringVar(
        label="End of Life column",
        description=(
            "CSV column containing either an EOL/EOS date or the value SUPPORTED. "
            "This same header is used for both Cisco and Fortinet CSV files."
        ),
        default="End of Life",
        required=False,
    )

    class Meta:
        name = "Tag Cisco / Fortinet EOL Devices"
        description = (
            "Checks Cisco EOL using either CSV or API depending on the 'Use API' checkbox. "
            "Checks Fortinet EOL using CSV. Treats SUPPORTED as OK. "
            "Tags EOL devices with 'EOL' and prints counters."
        )
        field_order = [
            "use_api",
            "cisco_client_id",
            "cisco_client_secret",
            "cisco_csv_path",
            "fortinet_csv_path",
            "product_column",
            "end_of_life_column",
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
        Clean path input from accidental surrounding quotes or apostrophes.
        """
        if value is None:
            return ""

        value = str(value).strip()
        value = value.strip("'").strip('"').strip()

        return value

    def _normalise(self, value):
        """
        Normalise identifiers for matching.

        Example:
            " mx250 " -> "MX250"
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
                Month DD, YYYY
                Mon DD, YYYY
        """
        if value is None:
            return None

        if isinstance(value, dict):
            value = value.get("value")

        if value is None:
            return None

        value = str(value).strip()

        if not value or value.upper() in {"-", "N/A", "NONE", "NULL", "SUPPORTED"}:
            return None

        formats = (
            "%Y-%m-%d",
            "%Y/%m/%d",
            "%d-%m-%Y",
            "%d/%m/%Y",
            "%B %d, %Y",
            "%b %d, %Y",
        )

        for fmt in formats:
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
    # CSV helpers
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

    def _normalise_header(self, value):
        """
        Normalise CSV headers to improve matching.
        """
        if value is None:
            return ""

        return str(value).strip().lower()

    def _resolve_csv_column(self, fieldnames, requested_column):
        """
        Resolve a CSV column name case-insensitively.

        Example:
            Requested: End of Life
            CSV has:  end of life
            => match
        """
        requested = self._normalise_header(requested_column)

        for field in fieldnames:
            if self._normalise_header(field) == requested:
                return field

        return None

    def _load_lifecycle_csv(self, file_path, product_column, end_of_life_column, label):
        """
        Load lifecycle CSV into a dictionary.

        Returns:
            {
                "NORMALISED_IDENTIFIER": {
                    "raw_identifier": "...",
                    "raw_lifecycle_value": "...",
                    "status": "supported" | "eol_date" | "unknown",
                    "eol_date": date(...) or None,
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

            resolved_product_column = self._resolve_csv_column(
                reader.fieldnames,
                product_column,
            )

            resolved_end_of_life_column = self._resolve_csv_column(
                reader.fieldnames,
                end_of_life_column,
            )

            missing_columns = []

            if not resolved_product_column:
                missing_columns.append(product_column)

            if not resolved_end_of_life_column:
                missing_columns.append(end_of_life_column)

            if missing_columns:
                raise ValueError(
                    f"{label} CSV is missing column(s): {', '.join(missing_columns)}. "
                    f"Detected columns: {', '.join(reader.fieldnames)}"
                )

            for row in reader:
                raw_identifier = row.get(resolved_product_column)
                key = self._normalise(raw_identifier)

                if not key:
                    continue

                raw_lifecycle_value = row.get(resolved_end_of_life_column)
                raw_lifecycle_value_clean = (
                    str(raw_lifecycle_value).strip()
                    if raw_lifecycle_value is not None
                    else ""
                )

                raw_lifecycle_value_upper = raw_lifecycle_value_clean.upper()

                if "SUPPORTED" in raw_lifecycle_value_upper:
                    status = "supported"
                    parsed_date = None
                else:
                    parsed_date = self._parse_date(raw_lifecycle_value_clean)

                    if parsed_date:
                        status = "eol_date"
                    else:
                        status = "unknown"

                lifecycle_map[key] = {
                    "raw_identifier": raw_identifier,
                    "raw_lifecycle_value": raw_lifecycle_value_clean,
                    "status": status,
                    "eol_date": parsed_date,
                    "row": row,
                }

        return lifecycle_map

    def _evaluate_csv_entry(self, entry):
        """
        Evaluate CSV lifecycle entry.

        Returns:
            "supported"
            "eol"
            "unknown"
        """
        status = entry.get("status")

        if status == "supported":
            return "supported"

        if status == "eol_date":
            eol_date = entry.get("eol_date")

            if not eol_date:
                return "unknown"

            if eol_date <= self._today():
                return "eol"

            return "supported"

        return "unknown"

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

    def _evaluate_cisco_api_record(self, record):
        """
        Evaluate Cisco API record.

        Returns:
            "supported"
            "eol"
            "unknown"
        """
        last_support = self._parse_date(record.get("LastDateOfSupport"))

        if not last_support:
            return "unknown"

        if last_support <= self._today():
            return "eol"

        return "supported"

    # ---------------------------------------------------------------------
    # Main
    # ---------------------------------------------------------------------

    def run(self, data, commit):
        eol_tag = self._ensure_eol_tag()

        use_api = data.get("use_api", False)

        cisco_client_id = (data.get("cisco_client_id") or "").strip()
        cisco_client_secret = (data.get("cisco_client_secret") or "").strip()

        cisco_csv_path = self._clean_path(data.get("cisco_csv_path") or "")
        fortinet_csv_path = self._clean_path(data.get("fortinet_csv_path") or "")

        product_column = (data.get("product_column") or "Product").strip()
        end_of_life_column = (data.get("end_of_life_column") or "End of Life").strip()

        self.log_info(f"Cisco Use API mode: {use_api}")
        self.log_info(f"CSV Product column: {product_column}")
        self.log_info(f"CSV End of Life column: {end_of_life_column}")

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
                        cisco_records_by_pid = self._cisco_lookup_by_pid(
                            token,
                            cisco_pids,
                        )
                        self.log_info(
                            f"Cisco API PID lookups completed: {len(set(cisco_pids))} unique identifiers."
                        )

                    if cisco_serials:
                        cisco_records_by_serial = self._cisco_lookup_by_serial(
                            token,
                            cisco_serials,
                        )
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
                        product_column,
                        end_of_life_column,
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
                    product_column,
                    end_of_life_column,
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
        total_supported = 0
        total_unknown = 0

        cisco_eol_api = 0
        cisco_supported_api = 0
        cisco_unknown_api = 0

        cisco_eol_csv = 0
        cisco_supported_csv = 0
        cisco_unknown_csv = 0

        fortinet_eol_csv = 0
        fortinet_supported_csv = 0
        fortinet_unknown_csv = 0

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
                        total_unknown += 1
                        cisco_unknown_api += 1

                        self.log_warning(
                            f"[Cisco][API] No lifecycle match for device={device.name} | "
                            f"site={device.site.name if device.site else '-'} | "
                            f"identifier={identifier} | serial={serial}"
                        )
                        continue

                    api_status = self._evaluate_cisco_api_record(api_record)

                    if api_status == "eol":
                        total_eol += 1
                        cisco_eol_api += 1

                        was_already_tagged = self._tag_device(device, eol_tag, commit)

                        if was_already_tagged:
                            already_tagged += 1
                        else:
                            newly_tagged += 1

                        last_support = self._parse_date(
                            api_record.get("LastDateOfSupport")
                        )

                        self.log_success(
                            f"[Cisco][API][EOL] device={device.name} | "
                            f"site={device.site.name if device.site else '-'} | "
                            f"identifier={identifier} | serial={serial} | "
                            f"last_date_of_support={last_support} | "
                            f"matched_pid={api_record.get('EOLProductID')}"
                        )

                    elif api_status == "supported":
                        total_supported += 1
                        cisco_supported_api += 1

                    else:
                        total_unknown += 1
                        cisco_unknown_api += 1

                        self.log_warning(
                            f"[Cisco][API][UNKNOWN] device={device.name} | "
                            f"site={device.site.name if device.site else '-'} | "
                            f"identifier={identifier} | serial={serial} | "
                            f"matched_pid={api_record.get('EOLProductID')} | "
                            f"reason=No valid LastDateOfSupport"
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
                    total_unknown += 1
                    cisco_unknown_csv += 1

                    self.log_warning(
                        f"[Cisco][CSV] No lifecycle match for device={device.name} | "
                        f"site={device.site.name if device.site else '-'} | "
                        f"identifier={identifier} | serial={serial}"
                    )
                    continue

                csv_status = self._evaluate_csv_entry(csv_entry)

                if csv_status == "eol":
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
                        f"lifecycle_value={csv_entry.get('raw_lifecycle_value')} | "
                        f"eol_date={csv_entry.get('eol_date')}"
                    )

                elif csv_status == "supported":
                    total_supported += 1
                    cisco_supported_csv += 1

                else:
                    total_unknown += 1
                    cisco_unknown_csv += 1

                    self.log_warning(
                        f"[Cisco][CSV][UNKNOWN] device={device.name} | "
                        f"site={device.site.name if device.site else '-'} | "
                        f"identifier={identifier} | serial={serial} | "
                        f"csv_identifier={csv_entry.get('raw_identifier')} | "
                        f"lifecycle_value={csv_entry.get('raw_lifecycle_value')}"
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
                    total_unknown += 1
                    fortinet_unknown_csv += 1

                    self.log_warning(
                        f"[Fortinet][CSV] No lifecycle match for device={device.name} | "
                        f"site={device.site.name if device.site else '-'} | "
                        f"identifier={identifier} | serial={serial}"
                    )
                    continue

                csv_status = self._evaluate_csv_entry(entry)

                if csv_status == "eol":
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
                        f"lifecycle_value={entry.get('raw_lifecycle_value')} | "
                        f"eol_date={entry.get('eol_date')}"
                    )

                elif csv_status == "supported":
                    total_supported += 1
                    fortinet_supported_csv += 1

                else:
                    total_unknown += 1
                    fortinet_unknown_csv += 1

                    self.log_warning(
                        f"[Fortinet][CSV][UNKNOWN] device={device.name} | "
                        f"site={device.site.name if device.site else '-'} | "
                        f"identifier={identifier} | serial={serial} | "
                        f"csv_identifier={entry.get('raw_identifier')} | "
                        f"lifecycle_value={entry.get('raw_lifecycle_value')}"
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
            f"CSV Product column: {product_column}\n"
            f"CSV End of Life column: {end_of_life_column}\n"
            "\n"
            "Lifecycle result totals:\n"
            f" - EOL devices total: {total_eol}\n"
            f" - Supported devices total: {total_supported}\n"
            f" - Unknown lifecycle devices total: {total_unknown}\n"
            "\n"
            "Cisco details:\n"
            f" - Cisco EOL from API: {cisco_eol_api}\n"
            f" - Cisco supported from API: {cisco_supported_api}\n"
            f" - Cisco unknown from API: {cisco_unknown_api}\n"
            f" - Cisco EOL from CSV: {cisco_eol_csv}\n"
            f" - Cisco supported from CSV: {cisco_supported_csv}\n"
            f" - Cisco unknown from CSV: {cisco_unknown_csv}\n"
            "\n"
            "Fortinet details:\n"
            f" - Fortinet EOL from CSV: {fortinet_eol_csv}\n"
            f" - Fortinet supported from CSV: {fortinet_supported_csv}\n"
            f" - Fortinet unknown from CSV: {fortinet_unknown_csv}\n"
            "\n"
            "Tagging:\n"
            f" - Newly tagged with EOL: {newly_tagged}\n"
            f" - Already tagged with EOL: {already_tagged}\n"
            f" - No lifecycle match: {no_match}\n"
            f"Commit mode: {commit}\n"
        )

        self.log_info(summary)
        return summary
