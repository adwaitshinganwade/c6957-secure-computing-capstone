from os import path

def is_path_sensitive(path: str, protected_locations: [str]) -> bool:
    """
    Determines if a path is sensitive by comparing it against each location prefix
    in PROTECTED_LOCATIONS. A path is considered sensitive if a location prefix matches
    (appears at the beginning) of the provided path.
    :param path: The path to be inspected
    :param protected_locations: A list of path prefixes to locations considered safe
    :return: True if the path is sensitive, else False
    """
    for location_prefix in protected_locations:
        if path.startswith(location_prefix):
            return True
    return False
        

def resolve_path_wrt_cwd(relative_path: str, current_working_directory: str) -> str:
    """
    Resolves a path with respect to the specified current working directory. For instance, the
    path ../a/b will be resolved to /home/user/a/b if the current working directory is
    /home/user/folder.
    <b>NOTE:</b> This function should be used to process paths recorded on the same
    system type as the on which this function will be executed (e.g., Linux paths should
    <b>NOT</b> be passed to this function if it will be invoked on a Windows machine).
    :param relative_path: The relative path to be resolved
    :param current_working_directory: The current working directory
    :return: The resolved path, as explained above.
    """
    joined_path = path.join(current_working_directory, relative_path)
    return path.normpath(joined_path)

def get_event_as_dict(log_event: str):
    """
    Transforms an event reported by ausearch into a dictonary, with each key-value pair
    representing one attribute-value pair from the event log.
    :param log_event: A string containing a single event log
    :return: The event from log_event as a dictionary
    """

    # The actual event data follows " : " in each event
    # event = log_event.split(" : ")[1]
    event_dict = dict()

    # The event payload is composed of space separated attribute=value pairs
    for key_value_pair in log_event.split(" "):
        kv_pair = key_value_pair.strip()
        if len(kv_pair) == 0:
            continue
        split_pair = kv_pair.split("=")
        if len(split_pair) != 2:
            continue
        event_dict[split_pair[0]] = split_pair[1]
    return event_dict