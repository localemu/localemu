from localemu.services.stores import AccountRegionBundle, BaseStore, LocalAttribute


class GuardDutyStore(BaseStore):
    # detector id => {finding id => finding (PascalCase, ASF-shaped)}
    findings: dict[str, dict[str, dict]] = LocalAttribute(default=dict)


guardduty_stores = AccountRegionBundle("guardduty", GuardDutyStore)
