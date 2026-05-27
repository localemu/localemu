import collections
import datetime

from localemu.aws.api.cloudwatch import (
    AlarmHistoryItem,
    CompositeAlarm,
    DashboardBody,
    MetricAlarm,
    StateValue,
)
from localemu.services.stores import (
    AccountRegionBundle,
    BaseStore,
    LocalAttribute,
)
from localemu.utils.aws import arns
from localemu.utils.tagging import Tags


class LocalEmuMetricAlarm:
    region: str
    account_id: str
    alarm: MetricAlarm

    def __init__(self, account_id: str, region: str, alarm: MetricAlarm):
        self.account_id = account_id
        self.region = region
        self.alarm = alarm
        # Tags are already stored as part of Tagging Service or RGTA plugin
        self.alarm.pop("Tags", None)
        self.set_default_attributes()

    def set_default_attributes(self):
        current_time = datetime.datetime.now(datetime.UTC)
        self.alarm["AlarmArn"] = arns.cloudwatch_alarm_arn(
            self.alarm["AlarmName"], account_id=self.account_id, region_name=self.region
        )
        self.alarm["AlarmConfigurationUpdatedTimestamp"] = current_time
        self.alarm.setdefault("ActionsEnabled", True)
        self.alarm.setdefault("OKActions", [])
        self.alarm.setdefault("AlarmActions", [])
        self.alarm.setdefault("InsufficientDataActions", [])
        self.alarm["StateValue"] = StateValue.INSUFFICIENT_DATA
        self.alarm["StateReason"] = "Unchecked: Initial alarm creation"
        self.alarm["StateUpdatedTimestamp"] = current_time
        self.alarm.setdefault("Dimensions", [])
        self.alarm["StateTransitionedTimestamp"] = current_time


class LocalEmuCompositeAlarm:
    region: str
    account_id: str
    alarm: CompositeAlarm

    def __init__(self, account_id: str, region: str, alarm: CompositeAlarm):
        self.account_id = account_id
        self.region = region
        self.alarm = alarm
        # Tags are already stored as part of Tagging Service or RGTA plugin
        self.alarm.pop("Tags", None)
        self.set_default_attributes()

    def set_default_attributes(self):
        current_time = datetime.datetime.now(datetime.UTC)
        self.alarm["AlarmArn"] = arns.cloudwatch_alarm_arn(
            self.alarm["AlarmName"], account_id=self.account_id, region_name=self.region
        )
        self.alarm["AlarmConfigurationUpdatedTimestamp"] = current_time
        self.alarm.setdefault("ActionsEnabled", True)
        self.alarm.setdefault("OKActions", [])
        self.alarm.setdefault("AlarmActions", [])
        self.alarm.setdefault("InsufficientDataActions", [])
        self.alarm["StateValue"] = StateValue.INSUFFICIENT_DATA
        self.alarm["StateReason"] = "Unchecked: Initial alarm creation"
        self.alarm["StateUpdatedTimestamp"] = current_time
        self.alarm["StateTransitionedTimestamp"] = current_time


class LocalEmuDashboard:
    region: str
    account_id: str
    dashboard_name: str
    dashboard_arn: str
    dashboard_body: DashboardBody
    last_modified: datetime.datetime
    size: int

    def __init__(
        self, account_id: str, region: str, dashboard_name: str, dashboard_body: DashboardBody
    ):
        self.account_id = account_id
        self.region = region
        self.dashboard_name = dashboard_name
        self.dashboard_arn = arns.cloudwatch_dashboard_arn(
            self.dashboard_name, account_id=self.account_id, region_name=self.region
        )
        self.dashboard_body = dashboard_body
        self.last_modified = datetime.datetime.now()
        self.size = 225  # TODO: calculate size


LocalEmuAlarm = LocalEmuMetricAlarm | LocalEmuCompositeAlarm


class CloudWatchStore(BaseStore):
    # maps resource ARN to alarms
    alarms: dict[str, LocalEmuAlarm] = LocalAttribute(default=dict)

    # Contains all the Alarm Histories. Per documentation, an alarm history is retained even if the alarm is deleted,
    # making it necessary to save this at store level.
    # Bounded to 10000 entries to prevent unbounded memory growth (1.2 fix).
    histories: list[AlarmHistoryItem] = LocalAttribute(
        default=lambda: collections.deque(maxlen=10000)
    )

    dashboards: dict[str, LocalEmuDashboard] = LocalAttribute(default=dict)
    # Maps resource ARN to tags
    tags: Tags = LocalAttribute(default=Tags)


cloudwatch_stores = AccountRegionBundle("cloudwatch", CloudWatchStore)
