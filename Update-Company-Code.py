from extras.scripts import Script
from dcim.models import Device
import re

class UpdateCompanyField(Script):
    class Meta:
        name = "Set Company Code from Site Name"
        description = "Applies company code for billable devices using site name prefix"
        field_order = []

    def run(self, data, commit):
        updated = 0

        for device in Device.objects.prefetch_related('site').all():
            is_billable = device.custom_field_data.get('Billable', False)
            site = device.site

            if is_billable and site and site.name:
                match = re.match(r'^(\d+)', site.name.strip())
                if match:
                    code = match.group(1).zfill(3)
                    current_code = device.custom_field_data.get('company')

                    if current_code != code:
                        self.log_info(f"{device.name}: Will set company = {code}")
                        if commit:
                            device.custom_field_data['company'] = code
                            device.save()
                            updated += 1
                else:
                    self.log_warning(f"{device.name}: Site name '{site.name}' has no numeric prefix.")

        self.log_success(f"Updated {updated} devices.")