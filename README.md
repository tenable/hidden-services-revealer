# Jenganizer - Hidden Service Revealer for AWS
Jenganizer is a tool to map hidden services in AWS. It does this by following the triggered events of a user's actions.
When a user performs an action in AWS, it can trigger other events in other services. By following these events, users
can identify services that are indirectly deployed by their actions. This can be important, as these resources can 
present security risks which should be managed and controlled.

## Installation
### Quick Install
The simplest way to install the package is to use pip:
```bash
pip install jenganizer
```

### Development Install
To install the package in development mode, clone the repository and install the package using pip:
```bash
git clone
cd hidden-services-revealer
pip install -e .
```

## Usage

```bash
jenganizer --help
```

```
Usage: jenganizer [OPTIONS]

Options:
  --username TEXT      The username to filter events by  [required]
  --profile-name TEXT  The AWS profile name to use
  --region-name TEXT   The AWS region name to use
  --time-start TEXT    The start time for the event filter, format: YYYY-MM-DD
                       HH:MM:SS+00:00
  --time-end TEXT      The end time for the event filter, format: YYYY-MM-DD
                       HH:MM:SS+00:00
  --time-span TEXT     The time span, in minutes, to filter, going back from
                       now (use this instead of time_start and time_end)
  -d, --depth INTEGER  The depth of triggered events to follow. Depth=0: only
                       initial calls by the user, Depth=1: initial calls and
                       calls triggered by the initial calls, etc.
  -o, --output TEXT    The output file to write the triggered events to
  -v, --verbosity LVL  Either CRITICAL, ERROR, WARNING, INFO or DEBUG
  --help               Show this message and exit.


```

The way to map hidden services is to perform the initial call to the service with a specific user for the action you 
want to map, `jenganizer` will then follow the triggered events to find the resource indirectly deployed to other services.

In order to zoom in on the right events, you can use the `--time-start` and `--time-end`, or `--time-span`.

### The depth parameter
The `--depth` parameter is used to specify how many levels of triggered events to follow. Level 0 only looks at events
called directly from the user, level 1 looks at events called by the user and events called by the services used 
by those events. Such an examination naturally highlights some false positive, so it is important to verify the results.

### Results
The results are printed to the console as a list of events, and a file 
(default name: `triggered_events.json`) is written with the full events.
These events can be used to identify hidden services in AWS.


