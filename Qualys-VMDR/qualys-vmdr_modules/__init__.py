from sekoia_automation.module import Module
from qualys-vmdr_modules.models import Qualys-VmdrModuleConfiguration


class Qualys-VmdrModule(Module):
    configuration: Qualys-VmdrModuleConfiguration
