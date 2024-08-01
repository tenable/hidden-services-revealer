# 3 Layers 3 filters
from itertools import tee
from pprint import *
from typing import List, Generator

import boto3
from datetime import datetime, timedelta
import json
import click
import click_log
import logging
import colorlog

logger = logging.getLogger("jengnizer")


def _initialize_logger() -> None:
    click_log.basic_config(logger)
    root_handler = logger.handlers[0]
    formatter = colorlog.ColoredFormatter(
        "%(log_color)s[%(asctime)s,%(msecs)d %(levelname)-8s"
        " %(filename)s:%(lineno)d - %(funcName)20s()]%(reset)s"
        " %(white)s%(message)s",
        datefmt="%H:%M:%S",
        reset=True,
        log_colors={
            "DEBUG": "blue",
            "INFO": "green",
            "WARNING": "yellow",
            "ERROR": "red",
            "CRITICAL": "red",
        },
    )
    root_handler.setFormatter(formatter)


_initialize_logger()


def is_read_only_event(cloudtrail_event: dict) -> bool:
    event_name = cloudtrail_event.get("eventName")
    # filter out verbs get, list, describe
    if (
        event_name.startswith("Get")
        or event_name.startswith("List")
        or event_name.startswith("Describe")
    ):
        return True
    return False


def paginate_cloudtrail_events(
    cloudtrail_client: boto3.client,
    start_time: datetime,
    end_time: datetime,
    lookup_attributes: List[dict] = None,
) -> Generator[dict, None, None]:
    """
    This function paginates through CloudTrail events for a given time range
    and filters by provided lookup attributes (optional).

    Args:
        cloudtrail_client (CloudTrailClient): A boto3 client for CloudTrail.
        start_time (datetime): The start time for the event lookup.
        end_time (datetime): The end time for the event lookup.
        lookup_attributes (List[dict], optional): A list of dictionaries representing
                                            lookup attributes for filtering events.
                                            Defaults to None (no filters).

    Yields:
        Generator[dict, None, None]: A generator yielding CloudTrail events for each page.
    """

    paginator = cloudtrail_client.get_paginator("lookup_events")
    starting_token = None

    # Handle potential absence of lookup attributes
    if not lookup_attributes:
        lookup_attributes = []

    for page in paginator.paginate(
        StartTime=start_time,
        EndTime=end_time,
        LookupAttributes=lookup_attributes,
        PaginationConfig={"StartingToken": starting_token},
    ):
        for event in page["Events"]:
            yield event
        starting_token = page.get("NextToken")
        if not starting_token:
            break


def is_triggered_event(event: dict, event_sources: list) -> bool:
    return (
        event.get("sourceIPAddress") in event_sources
        or event.get("userIdentity", {}).get("invokedBy") in event_sources
    )


def get_event_name(cloudtrail_event):
    return f"{cloudtrail_event.get('eventSource').split('.')[0]}:{cloudtrail_event.get('eventName')}"


def filter_triggered_events(
    username: str,
    profile_name: str,
    region_name: str,
    time_start: datetime,
    time_end: datetime,
    depth: int = 0,
    output_file: str = "triggered_events.json",
    event_sources: list = (),
):
    # Create a session using your AWS credentials
    session = boto3.Session(profile_name=profile_name, region_name=region_name)

    # Create CloudTrail client
    cloudtrail = session.client("cloudtrail")
    fd = open(output_file, "w")
    # Get event history
    cloudtrail_paginated_events = paginate_cloudtrail_events(
        cloudtrail,
        time_start,
        time_end,
        lookup_attributes=[{"AttributeKey": "ReadOnly", "AttributeValue": "false"}],
    )
    username_filtered_events = []
    filtered_event_names = []

    for event in cloudtrail_paginated_events:
        # filter by username
        cloudtrail_event = json.loads(event["CloudTrailEvent"])
        event_username = (
            cloudtrail_event["userIdentity"].get("principalId", "").split(":")[-1]
        )
        logger.debug(f"Event username: {event_username}")
        if event_username is not None and event_username == username:
            username_filtered_events.append(cloudtrail_event)
            event_sources.append(cloudtrail_event.get("eventSource"))
            logger.debug(
                f"Service: {cloudtrail_event.get('eventSource')}, Event: {cloudtrail_event.get('eventName')}"
            )
            filtered_event_names.append(get_event_name(cloudtrail_event))
            json.dump(cloudtrail_event, fd)
            fd.write("\n")
    for i in range(depth):
        cloudtrail_paginated_events = paginate_cloudtrail_events(
            cloudtrail,
            time_start,
            time_end,
            lookup_attributes=[{"AttributeKey": "ReadOnly", "AttributeValue": "false"}],
        )
        for event in cloudtrail_paginated_events:
            cloudtrail_event = json.loads(event["CloudTrailEvent"])
            if is_triggered_event(cloudtrail_event, event_sources):
                # if the event source is not in the list of event sources triggered by the user, add it
                if cloudtrail_event.get("eventSource") not in event_sources:
                    event_sources.append(cloudtrail_event.get("eventSource"))
                logger.debug(
                    f"Service: {cloudtrail_event.get('eventSource')}, Event: {cloudtrail_event.get('eventName')}"
                )
                filtered_event_names.append(get_event_name(cloudtrail_event))
                json.dump(cloudtrail_event, fd)
                fd.write("\n")
    pprint(set(filtered_event_names))
    fd.close()


@click.command()
@click.option("--username", help="The username to filter events by", required=True)
@click.option("--profile-name", help="The AWS profile name to use", default=None)
@click.option("--region-name", help="The AWS region name to use", default="us-east-1")
@click.option(
    "--time-start",
    help="The start time for the event filter, format: YYYY-MM-DD HH:MM:SS+00:00",
)
@click.option(
    "--time-end",
    help="The end time for the event filter, format: YYYY-MM-DD HH:MM:SS+00:00",
)
@click.option(
    "--time-span",
    help="The time span, in minutes, to filter, going back from now "
         "(use this instead of time_start and time_end)",
)
@click.option(
    "--depth", '-d',
    help="The depth of triggered events to follow. "
         "Depth=0: only initial calls by the user, "
         "Depth=1: initial calls and calls triggered by the initial calls, etc.",
    default=0,
)
@click.option(
    "--output", '-o',
    help="The output file to write the triggered events to",
    default="triggered_events.json",
)
@click_log.simple_verbosity_option(logger)
def cli(
    username: str,
    profile_name: str,
    region_name: str = "us-east-1",
    time_start: str = "",
    time_end: str = "",
    time_span: str = "",
    depth: int = 0,
    output: str = "triggered_events.json"
) -> None:
    # if the command is run without any arguments, print the help message
    if not any([username, profile_name, region_name, time_start, time_end, time_span]):
        click.echo(click.get_current_context().get_help())
        return

    time_start_datetime = None
    time_end_datetime = None

    if time_span:
        if time_start or time_end:
            logger.error(
                "You must not provide time_span and time_start/time_end together"
            )
            return

        time_start_datetime = datetime.now() - timedelta(minutes=float(time_span))
        time_end_datetime = datetime.now()
        logger.info(f"Time start: {time_start_datetime}, Time end: {time_end}")

    elif time_end and not time_start:
        logger.error("You must provide time_start if you provide time_end")
        return

    elif time_start:
        if not time_end:
            time_end = datetime.now()
        time_start_datetime = datetime.fromisoformat(time_start)
        time_end_datetime = datetime.fromisoformat(time_end)
        logger.info(f"Time start: {time_start}, Time end: {time_end}")

    filter_triggered_events(
        username,
        profile_name,
        region_name,
        time_start_datetime,
        time_end_datetime,
        depth,
        output
    )
