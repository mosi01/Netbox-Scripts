from extras.scripts import Script, StringVar, BooleanVar
import pynetbox
from django.db import transaction
from django.utils.text import slugify
from django.contrib.contenttypes.models import ContentType
from django.core.files.base import ContentFile
import os
import requests

from extras.models import (
    CustomLink,
    CustomField,
    CustomFieldChoiceSet,
    ExportTemplate,
    SavedFilter,
    TableConfig,
    Tag,
    ImageAttachment
)

from netbox.models import ObjectType


class SyncExtrasFromProduction(Script):
    class Meta:
        name = "Sync Extras from Production"
        description = (
            "Sync extras (custom links, custom field choice sets, custom fields, "
            "export templates, saved filters, table configs, tags, and image attachments) "
            "from a remote NetBox instance. "
            "Custom fields are created if missing and updated if attributes change."
        )
        commit_default = False

    #
    # Script input variables (same base as TestSyncFromProduction)
    #
    prod_url = StringVar(
        description="Production NetBox API URL",
        default="https://netbox.example.com",
    )

    api_key = StringVar(
        description="API Key (first part)"
    )

    api_token = StringVar(
        description="API Token (second part)"
    )

    ca_cert_path = StringVar(
        description="Path to CA certificate (optional)",
        required=False,
    )

    disable_ssl_verify = BooleanVar(
        description="Disable SSL verification (NOT recommended for production)",
        default=False,
    )

    #
    # Helpers
    #
    def _slug(self, value):
        return slugify(value) if value else None

    def _build_nb_client(self, data):
        """
        Build a pynetbox API client toward the remote/production NetBox.
        """
        full_token = f"nbt_{data['api_key']}.{data['api_token']}"
        self.log_info(f"Connecting to production NetBox API at {data['prod_url']}...")
        nb = pynetbox.api(data["prod_url"], token=full_token)

        # SSL handling
        if data["disable_ssl_verify"]:
            self.log_warning("SSL verification is DISABLED. This is insecure!")
            nb.http_session.verify = False
        elif data.get("ca_cert_path"):
            nb.http_session.verify = data["ca_cert_path"]
        else:
            nb.http_session.verify = True

        return nb

    def _get_object_type_from_remote(self, ot_data):
        """
        Map a remote ObjectType/ContentType representation (dict or pynetbox Record)
        to a local extras.ObjectType instance.
        """
        if not ot_data:
            return None

        # ot_data may be a pynetbox Record or a plain dict
        app_label = getattr(ot_data, "app_label", None) or getattr(
            ot_data, "app", None
        )
        model = getattr(ot_data, "model", None)

        if hasattr(ot_data, "dict"):
            # Some pynetbox records can be cast to dict
            d = ot_data.dict()
            app_label = d.get("app_label") or d.get("app") or app_label
            model = d.get("model") or model
        elif isinstance(ot_data, dict):
            app_label = ot_data.get("app_label") or ot_data.get("app") or app_label
            model = ot_data.get("model") or model

        if not app_label or not model:
            return None

        # NetBox v4: ObjectType proxy model; fallback to ContentType if needed.
        try:
            return ObjectType.objects.filter(app_label=app_label, model=model).first()
        except Exception:
            ct = ContentType.objects.filter(app_label=app_label, model=model).first()
            if ct:
                try:
                    return ObjectType.objects.get_for_model(ct.model_class())
                except Exception:
                    return None
        return None

    def _map_object_types_list(self, remote_list):
        """
        Map a list of remote object type “stubs” (as returned by API) to
        local ObjectType instances.
        """
        if not remote_list:
            return []
        local_ots = []
        for ot in remote_list:
            local_ot = self._get_object_type_from_remote(ot)
            if local_ot and local_ot not in local_ots:
                local_ots.append(local_ot)
        return local_ots

    #
    # Main
    #
    def run(self, data, commit):
        nb = self._build_nb_client(data)

        self.log_info("Fetching extras from production...")

        # Remote collections (full sets; no sampling)
        remote_custom_links = list(nb.extras.custom_links.all())
        remote_cf_choice_sets = list(nb.extras.custom_field_choice_sets.all())
        remote_custom_fields = list(nb.extras.custom_fields.all())
        remote_export_templates = list(nb.extras.export_templates.all())
        remote_saved_filters = list(nb.extras.saved_filters.all())
        remote_table_configs = list(nb.extras.table_configs.all())
        remote_tags = list(nb.extras.tags.all())
        remote_image_attachments = list(nb.extras.image_attachments.all())

        self.log_info(
            "Will sync: "
            f"{len(remote_custom_links)} custom links, "
            f"{len(remote_cf_choice_sets)} custom field choice sets, "
            f"{len(remote_custom_fields)} custom fields, "
            f"{len(remote_export_templates)} export templates, "
            f"{len(remote_saved_filters)} saved filters, "
            f"{len(remote_table_configs)} table configs, "
            f"{len(remote_tags)} tags, "
            f"{len(remote_image_attachments)} image attachments."
        )

        #
        # Sync in the requested order:
        # 1. Custom Links
        # 2. Custom Field Choices (Choice Sets)
        # 3. Custom Fields
        # 4. Export Templates
        # 5. Saved Filters
        # 6. Table Configs
        # 7. Tags
        # 8. Image Attachments
        #
        sync_plan = [
            ("Custom Links", remote_custom_links, self._sync_custom_links),
            (
                "Custom Field Choice Sets",
                remote_cf_choice_sets,
                self._sync_custom_field_choice_sets,
            ),
            ("Custom Fields", remote_custom_fields, self._sync_custom_fields),
            ("Export Templates", remote_export_templates, self._sync_export_templates),
            ("Saved Filters", remote_saved_filters, self._sync_saved_filters),
            ("Table Configs", remote_table_configs, self._sync_table_configs),
            ("Tags", remote_tags, self._sync_tags),
            (
                "Image Attachments",
                remote_image_attachments,
                self._sync_image_attachments,
            ),
        ]

        for name, records, func in sync_plan:
            self.log_info(f"Syncing {name}...")
            try:
                if commit:
                    with transaction.atomic():
                        func(records, commit)
                else:
                    # Dry-run: still iterate and log what would be done
                    func(records, commit=False)
                self.log_success(f"{name} synced successfully.")
            except Exception as e:
                self.log_failure(f"Failed to sync {name}: {e}")

        self.log_success("Extras sync completed.")

    #
    # Sync methods
    #

    def _sync_custom_links(self, records, commit):
        """
        Sync extras.CustomLink objects.
        Key: name
        """
        for r in records:
            # Map content types
            remote_cts = getattr(r, "content_types", None) or []
            local_ots = self._map_object_types_list(remote_cts)

            defaults = {
                "weight": getattr(r, "weight", 100),
                "group_name": getattr(r, "group_name", "") or "",
                "button_class": getattr(r, "button_class", "") or "",
                "text": getattr(r, "text", "") or "",
                "target_url": getattr(r, "target_url", "") or "",
                "enabled": getattr(r, "enabled", True),
                "new_window": getattr(r, "new_window", False),
            }

            if commit:
                obj, created = CustomLink.objects.update_or_create(
                    name=r.name,
                    defaults=defaults,
                )
                if local_ots:
                    obj.content_types.set(local_ots)
            else:
                self.log_info(f"Would sync CustomLink: {r.name}")

    def _sync_custom_field_choice_sets(self, records, commit):
        """
        Sync extras.CustomFieldChoiceSet objects.
        Key: name
        """
        for cs in records:
            defaults = {
                "slug": self._slug(getattr(cs, "slug", None) or cs.name),
                "description": getattr(cs, "description", "") or "",
                "extra_choices": getattr(cs, "extra_choices", []) or [],
                "base_choices": getattr(cs, "base_choices", None),
                "order_alphabetically": getattr(cs, "order_alphabetically", False),
            }

            if commit:
                CustomFieldChoiceSet.objects.update_or_create(
                    name=cs.name,
                    defaults=defaults,
                )
            else:
                self.log_info(f"Would sync CustomFieldChoiceSet: {cs.name}")

    def _sync_custom_fields(self, records, commit):
        """
        Sync extras.CustomField objects.
        Key: name

        - Create if not present.
        - Update attributes if changed.
        - Map choice_set and object_types where possible.
        """
        for cf in records:
            # Map choice_set
            choice_set = getattr(cf, "choice_set", None)
            choice_set_obj = None
            if choice_set:
                # choice_set may be a nested representation with name/slug
                cs_name = getattr(choice_set, "name", None)
                if hasattr(choice_set, "dict"):
                    d = choice_set.dict()
                    cs_name = d.get("name") or cs_name
                elif isinstance(choice_set, dict):
                    cs_name = choice_set.get("name") or cs_name

                if cs_name:
                    choice_set_obj = CustomFieldChoiceSet.objects.filter(
                        name=cs_name
                    ).first()

            defaults = {
                "label": getattr(cf, "label", None) or cf.name,
                "type": getattr(cf, "type", "text"),
                "description": getattr(cf, "description", "") or "",
                "required": getattr(cf, "required", False),
                "filter_logic": getattr(cf, "filter_logic", "loose"),
                "default": getattr(cf, "default", None),
                "weight": getattr(cf, "weight", 100),
                "validation_regex": getattr(cf, "validation_regex", "") or "",
                "ui_visible": getattr(cf, "ui_visible", True),
                "ui_editable": getattr(cf, "ui_editable", True),
                "group_name": getattr(cf, "group_name", "") or "",
                "search_weight": getattr(cf, "search_weight", 100),
                "choice_set": choice_set_obj,
            }

            if commit:
                cf_obj, created = CustomField.objects.update_or_create(
                    name=cf.name,
                    defaults=defaults,
                )

                # Map object_types / content_types M2M
                remote_ots = getattr(cf, "object_types", None) or getattr(
                    cf, "content_types", None
                )
                local_ots = self._map_object_types_list(remote_ots)
                if local_ots:
                    cf_obj.object_types.set(local_ots)
            else:
                self.log_info(f"Would sync CustomField: {cf.name}")

    def _sync_export_templates(self, records, commit):
        """
        Sync extras.ExportTemplate objects.
        Key: name + content_type
        """
        for et in records:
            remote_ct = getattr(et, "content_type", None)
            local_ot = self._get_object_type_from_remote(remote_ct)

            if not local_ot:
                self.log_warning(
                    f"Skipping ExportTemplate '{et.name}' (no matching content_type)."
                )
                continue

            defaults = {
                "description": getattr(et, "description", "") or "",
                "template_code": getattr(et, "template_code", "") or "",
                "mime_type": getattr(et, "mime_type", "") or "",
                "file_extension": getattr(et, "file_extension", "") or "",
                "as_attachment": getattr(et, "as_attachment", False),
            }

            if commit:
                ExportTemplate.objects.update_or_create(
                    name=et.name,
                    content_type=local_ot,
                    defaults=defaults,
                )
            else:
                self.log_info(f"Would sync ExportTemplate: {et.name}")

    def _sync_saved_filters(self, records, commit):
        """
        Sync extras.SavedFilter objects.
        Key: name + content_type

        Note: This does *not* attempt to map users; saved filters will be
        owner-less (global/shared) unless you extend this logic.
        """
        for sf in records:
            remote_ct = getattr(sf, "content_type", None)
            local_ot = self._get_object_type_from_remote(remote_ct)
            if not local_ot:
                self.log_warning(
                    f"Skipping SavedFilter '{sf.name}' (no matching content_type)."
                )
                continue

            defaults = {
                "description": getattr(sf, "description", "") or "",
                "parameters": getattr(sf, "parameters", {}) or {},
                "shared": getattr(sf, "shared", True),
            }

            if commit:
                SavedFilter.objects.update_or_create(
                    name=sf.name,
                    content_type=local_ot,
                    defaults=defaults,
                )
            else:
                self.log_info(f"Would sync SavedFilter: {sf.name}")

    def _sync_table_configs(self, records, commit):
        """
        Sync extras.TableConfig objects.
        Key: name + content_type

        Note: This does *not* attempt to map per-user/owner configs;
        it assumes global/shared configs.
        """
        for tc in records:
            remote_ct = getattr(tc, "content_type", None)
            local_ot = self._get_object_type_from_remote(remote_ct)
            if not local_ot:
                self.log_warning(
                    f"Skipping TableConfig '{tc.name}' (no matching content_type)."
                )
                continue

            defaults = {
                "description": getattr(tc, "description", "") or "",
                "config": getattr(tc, "config", {}) or {},
                "weight": getattr(tc, "weight", 100),
            }

            if commit:
                TableConfig.objects.update_or_create(
                    name=tc.name,
                    content_type=local_ot,
                    defaults=defaults,
                )
            else:
                self.log_info(f"Would sync TableConfig: {tc.name}")

    def _sync_tags(self, records, commit):
        """
        Sync extras.Tag objects.
        Key: name
        """
        for t in records:
            defaults = {
                "slug": self._slug(getattr(t, "slug", None) or t.name),
                "color": getattr(t, "color", "") or "",
                "description": getattr(t, "description", "") or "",
            }

            if commit:
                Tag.objects.update_or_create(
                    name=t.name,
                    defaults=defaults,
                )
            else:
                self.log_info(f"Would sync Tag: {t.name}")

    def _sync_image_attachments(self, records, commit):
        """
        Sync extras.ImageAttachment objects.

        This:
        - Downloads the image from the remote NetBox.
        - Creates/updates an ImageAttachment referencing the same object.

        Key: name + content_type + object_id
        """
        if not records:
            return

        # Base URL for media; if remote "image" is already absolute, we'll use it directly.
        base_url = self.prod_url

        for img in records:
            remote_ct = getattr(img, "content_type", None)
            local_ot = self._get_object_type_from_remote(remote_ct)
            if not local_ot:
                self.log_warning(
                    f"Skipping ImageAttachment '{getattr(img, 'name', 'unnamed')}' "
                    f"(no matching content_type)."
                )
                continue

            object_id = getattr(img, "object_id", None)
            image_url = getattr(img, "image", None)

            if not image_url or not object_id:
                self.log_warning(
                    f"Skipping ImageAttachment '{getattr(img, 'name', 'unnamed')}' "
                    f"(missing image or object_id)."
                )
                continue

            # Make image URL absolute if needed
            if not image_url.startswith("http"):
                image_url = base_url.rstrip("/") + image_url

            if not commit:
                self.log_info(
                    f"Would sync ImageAttachment: "
                    f"{getattr(img, 'name', 'unnamed')} (URL={image_url})"
                )
                continue

            try:
                resp = requests.get(image_url, verify=not self.disable_ssl_verify)
                resp.raise_for_status()
            except Exception as e:
                self.log_warning(
                    f"Failed to download image from {image_url}: {e}"
                )
                continue

            filename = os.path.basename(image_url.split("?")[0])

            ia, created = ImageAttachment.objects.get_or_create(
                name=getattr(img, "name", filename),
                content_type=local_ot,
                object_id=object_id,
            )

            ia.image.save(filename, ContentFile(resp.content), save=True)