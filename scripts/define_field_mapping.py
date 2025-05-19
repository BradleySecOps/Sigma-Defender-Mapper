import json

def get_initial_field_mapping():
    """
    Defines the initial mapping from Sigma fields to CSV columns,
    starting with the 'process_creation' category.
    """
    mapping = {
        "process_creation": {
            # Sigma Field: CSV Column
            "Image": "File Name",  # Name of the process created
            "process.name": "File Name", # Alias for Image
            "process.executable": "File Name", # Alias for Image
            "CommandLine": "Process Command Line", # Command line of the created process
            "process.command_line": "Process Command Line", # Alias
            "ParentImage": "Initiating Process File Name", # Name of the parent process
            "parent_process.name": "Initiating Process File Name", # Alias
            "parent_process.executable": "Initiating Process File Name", # Alias
            "ParentCommandLine": "Initiating Process Command Line", # Command line of the parent
            "parent_process.command_line": "Initiating Process Command Line", # Alias
            "User": "Account Name",  # User context of the created process
            "user.name": "Account Name", # Alias
            # For parent user context, a rule might need to specify, or we might infer
            # "ParentUser": "Initiating Process Account Name", # Example if needed
            "ProcessId": "Process Id", # PID of the created process
            "process.pid": "Process Id", # Alias
            "ParentProcessId": "Initiating Process Id", # PID of the parent process
            "parent_process.pid": "Initiating Process Id", # Alias
            "OriginalFileName": "File Name", # Often the same as Image
            "Hashes.SHA1": "Sha1", # SHA1 of the created process
            "process.hash.sha1": "Sha1",
            "Hashes.SHA256": "Sha256", # SHA256 of the created process
            "process.hash.sha256": "Sha256",
            "Hashes.MD5": "MD5", # MD5 of the created process
            "process.hash.md5": "MD5",
            # Hashes for parent process
            "ParentHashes.SHA1": "Initiating Process SHA1",
            "parent_process.hash.sha1": "Initiating Process SHA1",
            "ParentHashes.SHA256": "Initiating Process SHA256",
            "parent_process.hash.sha256": "Initiating Process SHA256",
            "ParentHashes.MD5": "Initiating Process MD5",
            "parent_process.hash.md5": "Initiating Process MD5",
            "IntegrityLevel": "Process Integrity Level", # Integrity level of the created process
            "process.integrity_level": "Process Integrity Level",
            "ParentIntegrityLevel": "Initiating Process Integrity Level", # Integrity level of the parent
            "parent_process.integrity_level": "Initiating Process Integrity Level",
            "LogonId": "Logon Id", # Logon ID of the created process
            "user.id": "Account Sid", # More specific for user SID
            "process.owner": "Account Name", # User who owns the process
            "ComputerName": "Computer Name", # Machine name
            "host.name": "Computer Name",
            "EventTime": "Event Time", # Timestamp of the event
            "@timestamp": "Event Time",
            "ProcessCreationTime": "Process Creation Time",
            "process.creation_time": "Process Creation Time",
            "ParentProcessCreationTime": "Initiating Process Creation Time",
            "parent_process.creation_time": "Initiating Process Creation Time",
            "FolderPath": "Folder Path", # Path for the created process image
            "process.path": "Folder Path", # Often combined with File Name for full path
            "InitiatingProcessFolderPath": "Initiating Process Folder Path", # Path for the parent process
            "parent_process.path": "Initiating Process Folder Path",
            "TokenElevation": "Process Token Elevation", # For created process
            "ParentTokenElevation": "Initiating Process Token Elevation", # For parent process
            # Fields that might not have a direct 1:1 mapping yet or are less common:
            "Product": None, # Product name of the executable - often from PE metadata, no direct CSV field.
            # "Description": None, # Description of the executable
            # "CurrentDirectory": None, # CWD of the new process
        },
        "registry_event": { # Placeholder for registry events
            # Based on smallerfile.csv Action Types: RegistryKeyCreated, RegistryValueSet, RegistryKeyDeleted, RegistryValueDeleted
            "TargetObject": "Registry Key", # Sigma's common field for registry path
            "registry.path": "Registry Key",
            "Details": "Registry Value Data", # Sigma's common field for value data
            "registry.value": "Registry Value Data", # Often used for the data itself
            "registry.key": "Registry Key", # Can also be more specific
            "registry.value_name": "Registry Value Name",
            "Image": "Initiating Process File Name", # Process that made the registry change
            "process.executable": "Initiating Process File Name",
            "process.name": "Initiating Process File Name",
            "CommandLine": "Initiating Process Command Line",
            "process.command_line": "Initiating Process Command Line",
            "User": "Initiating Process Account Name",
            "user.name": "Initiating Process Account Name",
            # For RegistryKeyCreated/Deleted, the 'Registry Value Name' and 'Registry Value Data' might be empty in CSV
            # For RegistryValueSet, 'Previous Registry Value Name', 'Previous Registry Value Data' are available
            "OldValue": "Previous Registry Value Data",
            "registry.old_value": "Previous Registry Value Data",
            "NewValue": "Registry Value Data", # For changes
            "registry.new_value": "Registry Value Data",
        },
        "network_connection": {
            # Primarily based on Action Types: ConnectionSuccess, InboundConnectionAccepted, ConnectionFailed, SslConnectionInspected
            "DestinationIp": "Remote IP",
            "destination.ip": "Remote IP",
            "DestinationPort": "Remote Port",
            "destination.port": "Remote Port",
            "DestinationHostname": "Remote Computer Name", # Also check Remote Url
            "destination.domain": "Remote Computer Name",
            "Url": "Remote Url", # For HTTP/S
            "url.full": "Remote Url",
            "SourceIp": "Local IP",
            "source.ip": "Local IP",
            "SourcePort": "Local Port",
            "source.port": "Local Port",
            "Protocol": "Protocol", # e.g., Tcp, Udp
            "network.protocol": "Protocol",
            "network.transport": "Protocol",
            "Image": "Initiating Process File Name", # Process initiating the connection
            "process.executable": "Initiating Process File Name",
            "process.name": "Initiating Process File Name",
            "User": "Initiating Process Account Name", # User context of the initiating process
            "user.name": "Initiating Process Account Name",
            "CommandLine": "Initiating Process Command Line",
            "process.command_line": "Initiating Process Command Line",
            "ProcessId": "Initiating Process Id",
            "process.pid": "Initiating Process Id",
            # For DNS specific (if ActionType indicates DNS query)
            # "QueryName": "Remote Computer Name", # This is an assumption for DNS, might need specific DNS ActionType
            # "dns.question.name": "Remote Computer Name",
        },
        "dns_query": { # Often a sub-category or distinct log source for Sigma
            "QueryName": "Remote Computer Name", # Assuming this field might hold the DNS query if ActionType is DNS-specific
            "dns.question.name": "Remote Computer Name",
            "DestinationIp": "Remote IP", # DNS Server IP
            "destination.ip": "Remote IP",
            "DestinationPort": "Remote Port", # Usually 53
            "destination.port": "Remote Port",
            "SourceIp": "Local IP",
            "source.ip": "Local IP",
            "Image": "Initiating Process File Name",
            "process.executable": "Initiating Process File Name",
            "User": "Initiating Process Account Name",
            "user.name": "Initiating Process Account Name",
            "Protocol": "Protocol", # UDP or TCP for DNS
            "network.protocol": "Protocol",
        },
        "registry_set": { # Added to handle specific Sigma category, maps like registry_event for now
            "TargetObject": "Registry Key",
            "registry.path": "Registry Key",
            "Details": "Registry Value Data",
            "registry.value": "Registry Value Data",
            "registry.key": "Registry Key",
            "registry.value_name": "Registry Value Name",
            "Image": "Initiating Process File Name",
            "process.executable": "Initiating Process File Name",
            "process.name": "Initiating Process File Name",
            "CommandLine": "Initiating Process Command Line",
            "process.command_line": "Initiating Process Command Line",
            "User": "Initiating Process Account Name",
            "user.name": "Initiating Process Account Name",
            "OldValue": "Previous Registry Value Data",
            "registry.old_value": "Previous Registry Value Data",
            "NewValue": "Registry Value Data",
            "registry.new_value": "Registry Value Data",
        }
        # Additional categories based on analysis
        ,
        "file_event": {
            "TargetFilename": "Folder Path",
            "Image": "Initiating Process File Name",
            "User": "Initiating Process Account Name",
            "CommandLine": "Initiating Process Command Line",
            "ParentImage": "Initiating Process Parent File Name",
            "ParentCommandLine": "Initiating Process Parent Command Line",
            "CreationUtcTime": "Event Time",
            "FileName": "File Name",
            "FileMagicBytes": "Additional Fields",
            "IntegrityLevel": "Process Integrity Level",
            "process.executable": "Initiating Process File Name",
            "process.command_line": "Initiating Process Command Line",
            "file.path": "Folder Path",
            "file.name": "File Name",
            "user.name": "Initiating Process Account Name"
        },
        "ps_script": {
            "ScriptBlockText": "Process Command Line",
            "Path": "Folder Path",
            "CommandLine": "Process Command Line",
            "User": "Account Name",
            "process.command_line": "Process Command Line",
            "process.executable": "File Name",
            "powershell.script_block_text": "Process Command Line",
            "user.name": "Account Name"
        },
        "image_load": {
            "Description": "Additional Fields",
            "ImageLoaded": "File Name",
            "Image": "Initiating Process File Name",
            "Hashes": "Sha256",
            "OriginalFileName": "Additional Fields",
            "Signed": "Additional Fields",
            "CommandLine": "Initiating Process Command Line",
            "Signature": "Additional Fields",
            "SignatureStatus": "Additional Fields",
            "Product": "Additional Fields",
            "Company": "Additional Fields",
            "process.executable": "Initiating Process File Name",
            "process.command_line": "Initiating Process Command Line",
            "file.path": "Folder Path",
            "file.name": "File Name",
            "file.hash.sha256": "Sha256"
        },
        "webserver": {
            "cs-method": "Additional Fields",
            "cs-uri-query": "Remote Url",
            "sc-status": "Additional Fields",
            "cs-user-agent": "Additional Fields",
            "cs-referer": "Additional Fields",
            "cs-username": "Account Name",
            "cs-uri-stem": "Remote Url",
            "cs-host": "Remote Computer Name",
            "http.request.method": "Additional Fields",
            "url.query": "Remote Url",
            "http.response.status_code": "Additional Fields",
            "user_agent.original": "Additional Fields",
            "http.request.referrer": "Additional Fields",
            "user.name": "Account Name",
            "url.path": "Remote Url",
            "url.domain": "Remote Computer Name"
        },
        "proxy": {
            "c-uri": "Remote Url",
            "c-useragent": "Additional Fields",
            "cs-method": "Additional Fields",
            "cs-host": "Remote Computer Name",
            "cs-cookie": "Additional Fields",
            "dst_ip": "Remote IP",
            "c-uri-extension": "Additional Fields",
            "cs-uri": "Remote Url",
            "c-uri-query": "Remote Url",
            "sc-status": "Additional Fields",
            "url.full": "Remote Url",
            "user_agent.original": "Additional Fields",
            "http.request.method": "Additional Fields",
            "url.domain": "Remote Computer Name",
            "http.cookie": "Additional Fields",
            "destination.ip": "Remote IP",
            "file.extension": "Additional Fields",
            "url.query": "Remote Url",
            "http.response.status_code": "Additional Fields"
        },
        "application": {
            "EventLog": "Additional Fields",
            "EventID": "Additional Fields",
            "InterfaceUuid": "Additional Fields",
            "OpNum": "Additional Fields",
            "verb": "Additional Fields",
            "objectRef.resource": "Additional Fields",
            "objectRef.subresource": "Additional Fields",
            "hostPath": "Folder Path",
            "objectRef.namespace": "Additional Fields",
            "capabilities": "Additional Fields",
            "apiGroup": "Additional Fields",
            "logtype": "Additional Fields",
            "application.name": "File Name",
            "event.code": "Additional Fields",
            "rpc.interface_uuid": "Additional Fields",
            "rpc.operation": "Additional Fields",
            "kubernetes.verb": "Additional Fields",
            "kubernetes.resource": "Additional Fields",
            "kubernetes.namespace": "Additional Fields",
            "host.hostname": "Computer Name"
        },
        "pipe_created": {
            "PipeName": "Additional Fields",
            "Image": "Initiating Process File Name",
            "process.executable": "Initiating Process File Name",
            "named_pipe.name": "Additional Fields"
        },
        "create_remote_thread": {
            "TargetImage": "File Name",
            "SourceImage": "Initiating Process File Name",
            "StartFunction": "Additional Fields",
            "StartModule": "Additional Fields",
            "StartAddress": "Additional Fields",
            "TargetParentProcessId": "Process Id",
            "SourceCommandLine": "Initiating Process Command Line",
            "SourceParentImage": "Initiating Process Parent File Name",
            "process.executable": "Initiating Process File Name",
            "target.process.executable": "File Name",
            "thread.start_function": "Additional Fields",
            "thread.start_module": "Additional Fields",
            "thread.start_address": "Additional Fields",
            "target.process.parent.pid": "Process Id",
            "process.command_line": "Initiating Process Command Line",
            "process.parent.executable": "Initiating Process Parent File Name"
        },
        "process_access": { # Category for process access events (e.g., Sysmon Event ID 10)
            "SourceImage": "Initiating Process File Name", # Process requesting access
            "TargetImage": "File Name", # Process being accessed
            "GrantedAccess": "Additional Fields", # Placeholder, as AccessMask is often in detailed fields
            "AccessMask": None, # Explicitly setting to null as per user request
            "CallTrace": "Additional Fields" # Call stack
        },
        "_NO_CATEGORY_": { # For general Windows fields or when category isn't specified
            "AccessMask": None # Explicitly setting to null
            # Add other common cross-category windows fields here if needed
        },
        "_logsource_category_to_action_type_": {
            "process_creation": "ProcessCreated",
            "network_connection": ["ConnectionSuccess", "InboundConnectionAccepted", "ConnectionFailed", "SslConnectionInspected"], # Can be a list if multiple Action Types apply
            "dns_query": "DnsQuery", # Assuming a specific Action Type for DNS, might need to be confirmed from full timeline.csv
            "file_event": ["FileCreated", "FileDeleted", "FileModified", "FileRenamed"], # Example, needs confirmation
            "registry_event": ["RegistryKeyCreated", "RegistryValueSet", "RegistryKeyDeleted", "RegistryValueDeleted"],
            "registry_set": "RegistryValueSet", # Often a more specific form of registry_event
            "image_load": "ImageLoaded", # Or similar, e.g., ModuleLoaded
            "pipe_created": "NamedPipeEvent", # Example, needs confirmation
            "create_remote_thread": "CreateRemoteThread", # Example, needs confirmation
            "process_access": "ProcessAccessed", # Example, needs confirmation
            "ps_script": "ScriptExecution", # Example, needs confirmation
            "ps_module": "ModuleLoaded", # Example, needs confirmation
            # Add other categories as identified
        }
    }
    return mapping

def main():
    field_map = get_initial_field_mapping()
    output_file_path = 'field_mapping.json'

    with open(output_file_path, 'w', encoding='utf-8') as f:
        json.dump(field_map, f, indent=4, sort_keys=True)

    print(f"Field mapping definition saved to {output_file_path}")
    print(f"Mapped {len(field_map.get('process_creation', {}))} fields for 'process_creation'.")
    print(f"Mapped {len(field_map.get('registry_event', {}))} fields for 'registry_event'.")
    print(f"Mapped {len(field_map.get('registry_set', {}))} fields for 'registry_set'.")
    print(f"Mapped {len(field_map.get('network_connection', {}))} fields for 'network_connection'.")
    print(f"Mapped {len(field_map.get('dns_query', {}))} fields for 'dns_query'.")
    print(f"Mapped {len(field_map.get('file_event', {}))} fields for 'file_event'.")
    print(f"Mapped {len(field_map.get('ps_script', {}))} fields for 'ps_script'.")
    print(f"Mapped {len(field_map.get('image_load', {}))} fields for 'image_load'.")
    print(f"Mapped {len(field_map.get('webserver', {}))} fields for 'webserver'.")
    print(f"Mapped {len(field_map.get('proxy', {}))} fields for 'proxy'.")
    print(f"Mapped {len(field_map.get('application', {}))} fields for 'application'.")
    print(f"Mapped {len(field_map.get('pipe_created', {}))} fields for 'pipe_created'.")
    print(f"Mapped {len(field_map.get('create_remote_thread', {}))} fields for 'create_remote_thread'.")
    print(f"Mapped {len(field_map.get('process_access', {}))} fields for 'process_access'.")
    print(f"Mapped {len(field_map.get('_NO_CATEGORY_', {}))} fields for '_NO_CATEGORY_'.")

if __name__ == '__main__':
    main()