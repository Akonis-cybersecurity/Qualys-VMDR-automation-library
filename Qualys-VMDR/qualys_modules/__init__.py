from pydantic.v1 import BaseModel, Field
from sekoia_automation.module import Module


class QualysVMDRModuleConfiguration(BaseModel):
    base_url: str = Field(..., description="Base URL of the Qualys platform (e.g. https://qualysapi.qualys.com)")
    username: str = Field(..., description="Qualys username")
    password: str = Field(..., secret=True, description="Qualys password")


class QualysVMDRModule(Module):
    configuration: QualysVMDRModuleConfiguration
