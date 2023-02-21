import boto3
import botocore
# import jsonschema
import json
import traceback

from extutil import remove_none_attributes, account_context, ExtensionHandler, ext, \
    current_epoch_time_usec_num, component_safe_name, random_id, handle_common_errors

eh = ExtensionHandler()

cloudfront = boto3.client("cloudfront")

def lambda_handler(event, context):
    try:
        print(f"event = {event}")
        # account_number = account_context(context)['number']
        region = account_context(context)['region']
        eh.capture_event(event)
        prev_state = event.get("prev_state") or {}
        project_code = event.get("project_code")
        repo_id = event.get("repo_id")
        cdef = event.get("component_def")
        cname = event.get("component_name")

        #How long can these names be? Untested
        caller_reference = random_id()
        caller_reference = component_safe_name(project_code, repo_id, cname, max_chars=64)
        comment = cdef.get("comment") or f"Created by CK"
        oai_id = prev_state.get("props", {}).get("id") or cdef.get("existing_id")
        # region = cdef.get("region")
        prev_state = event.get("prev_state") or {}
    
        pass_back_data = event.get("pass_back_data", {})
        if pass_back_data:
            pass
        elif event.get("op") == "upsert":
            if oai_id:
                eh.add_op("get_oai", oai_id)
            else:
                eh.add_op("create_oai")

        elif event.get("op") == "delete":
            eh.add_op("delete_oai", prev_state.get("props").get("id"))

        get_oai(region)
        create_oai(caller_reference, comment, region)
        delete_oai()
            
        return eh.finish()

    except Exception as e:
        msg = traceback.format_exc()
        print(msg)
        eh.add_log("Unexpected Error", {"error": str(e)}, is_error=True)
        eh.declare_return(200, 0, error_code=str(e))
        return eh.finish()


@ext(handler=eh, op="get_oai")
def get_oai(region):
    oai_id = eh.ops["get_oai"]
    
    try:
        cloudfront_data = cloudfront.get_cloud_front_origin_access_identity(Id=oai_id)
        eh.add_log("Got Existing OAI, Exiting", cloudfront_data)
        
        eh.add_props({
            "id": oai_id,
            "arn": f"arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity {oai_id}",
            "s3_id": cloudfront_data["CloudFrontOriginAccessIdentity"]["S3CanonicalUserId"],
            "etag": cloudfront_data["ETag"]
        })

        eh.add_links({
            "OAI": f"https://us-east-1.console.aws.amazon.com/cloudfront/v3/home?region={region}#/distributions/{oai_id}"
        })

    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == "NoSuchCloudFrontOriginAccessIdentity":
            eh.add_log("OAI does not exist", {"id": oai_id})
            eh.add_op("create_oai")
            
        else:
            eh.add_log("Failed to get OAI", {"error": str(e)}, is_error=True)
            eh.retry_error("Failed to Get OAI", {"Exception": str(e)})

@ext(handler=eh, op="create_oai")
def create_oai(caller_reference, comment, region):

    try:
        cloudfront_data = cloudfront.create_cloud_front_origin_access_identity(
            CloudFrontOriginAccessIdentityConfig={
                "CallerReference": caller_reference,
                "Comment": comment
            }
        )
        eh.add_log("Created OAI", cloudfront_data)

        oai_id = cloudfront_data["CloudFrontOriginAccessIdentity"]["Id"]

        eh.add_props({
            "id": oai_id,
            "arn": f"arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity {oai_id}",
            "s3_id": cloudfront_data["CloudFrontOriginAccessIdentity"]["S3CanonicalUserId"],
            "etag": cloudfront_data["ETag"]
        })

        eh.add_links({
            "OAI": f"https://us-east-1.console.aws.amazon.com/cloudfront/v3/home?region={region}#/distributions/{oai_id}"
        })

    except botocore.exceptions.ClientError as e:
        handle_common_errors(e, eh, "Create OAI Failure", 0, ["TooManyCloudFrontOriginAccessIdentities"])

@ext(handler=eh, op="delete_oai")
def delete_oai():
    oai_id = eh.ops["delete_oai"]

    try:
        cloudfront.delete_cloud_front_origin_access_identity(
            Id=oai_id
        )
        eh.add_log(f"Removed OAI", {"oai_id": oai_id})
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == "ResourceNotFoundException":
            eh.add_log("OAI does not exist, exiting", {"oai_id": oai_id})
        else:
            handle_common_errors(e, eh, "Delete OAI Failure", 0)
