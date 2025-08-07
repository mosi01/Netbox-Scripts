from extras.scripts import Script
from dcim.models import Device, Interface, ConsolePort, PowerPort
import csv
import io

class ExportDeviceData(Script):
    class Meta:
        name = "Export Device Data"
        description = "Exports device data to CSV format with semicolon delimiter"
        field_order = []

    def run(self, data, commit):
        output = io.StringIO()
        writer = csv.writer(output, delimiter=';')

        # Write CSV header
        writer.writerow([
            "Device Name",
            "Site Name",
            "Model",
            "Interface Port Count",
            "Management Port Count",
            "Power Ports Count",
            "Console Ports Count"
        ])

        for device in Device.objects.all():
            # Count all interfaces
            interface_ports = Interface.objects.filter(device=device).count() or 0

            # Count management interfaces (based on name containing 'mgmt')
            mgmt_ports = Interface.objects.filter(device=device, name__icontains='mgmt').count() or 0

            # Count power ports
            power_ports = PowerPort.objects.filter(device=device).count() or 0

            # Count console ports
            console_ports = ConsolePort.objects.filter(device=device).count() or 0

            writer.writerow([
                device.name or "",
                device.site.name if device.site else "",
                device.device_type.model if device.device_type else "",
                interface_ports,
                mgmt_ports,
                power_ports,
                console_ports
            ])

        return output.getvalue()
