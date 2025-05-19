import json
import os

def update_field_mapping(mapping_file="field_mapping.json"):
    """
    Update the field mapping file with additional logsource categories.
    
    Args:
        mapping_file: Path to the field mapping JSON file
    """
    # Load existing mapping
    if os.path.exists(mapping_file):
        with open(mapping_file, 'r', encoding='utf-8') as f:
            mapping = json.load(f)
    else:
        mapping = {}
    
    # Add mapping for file_event
    if "file_event" not in mapping:
        mapping["file_event"] = {
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
        }
    
    # Add mapping for ps_script
    if "ps_script" not in mapping:
        mapping["ps_script"] = {
            "ScriptBlockText": "Process Command Line",
            "Path": "Folder Path",
            "CommandLine": "Process Command Line",
            "User": "Account Name",
            "process.command_line": "Process Command Line",
            "process.executable": "File Name",
            "powershell.script_block_text": "Process Command Line",
            "user.name": "Account Name"
        }
    
    # Add mapping for image_load
    if "image_load" not in mapping:
        mapping["image_load"] = {
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
        }
    
    # Add mapping for webserver
    if "webserver" not in mapping:
        mapping["webserver"] = {
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
        }
    
    # Add mapping for proxy
    if "proxy" not in mapping:
        mapping["proxy"] = {
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
        }
    
    # Add mapping for application
    if "application" not in mapping:
        mapping["application"] = {
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
        }
    
    # Add mapping for pipe_created
    if "pipe_created" not in mapping:
        mapping["pipe_created"] = {
            "PipeName": "Additional Fields",
            "Image": "Initiating Process File Name",
            "process.executable": "Initiating Process File Name",
            "named_pipe.name": "Additional Fields"
        }
    
    # Add mapping for create_remote_thread
    if "create_remote_thread" not in mapping:
        mapping["create_remote_thread"] = {
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
        }
    
    # Save updated mapping
    with open(mapping_file, 'w', encoding='utf-8') as f:
        json.dump(mapping, f, indent=4)
    
    print(f"Updated {mapping_file} with additional logsource categories.")

if __name__ == "__main__":
    update_field_mapping()