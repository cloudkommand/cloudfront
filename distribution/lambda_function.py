import boto3
import botocore
# import jsonschema
import json
import traceback
import zipfile
import os

from botocore.exceptions import ClientError

from extutil import remove_none_attributes, account_context, ExtensionHandler, ext, \
    current_epoch_time_usec_num, component_safe_name, lambda_env, random_id, \
    handle_common_errors

eh = ExtensionHandler()

"""
Progress only needs to be explicitly reported on 1) a retry 2) an error. Finishing auto-sets progress to 100. 

How to wait and check again
    eh.retry_error(a_unique_id_for_the_error(if you don't want it to fail out after 6 tries), progress=65, callback_sec=8)
        Only set callback seconds for a wait, not an error

There are three elements of state preserved across retries:
    - eh.props 
        - eh.add_props, takes a dictionary, merges existing with new
    - eh.links 
        - eh.add_links, takes a dictionary, merges existing with new
    - eh.state 
        - eh.add_state, takes a dictionary, merges existing with new
        - This is specifically if CloudKommand doesn't need to store it for later. Thrown away at the end of the deployment.

Wrap all operations you want to run with the following:
    @ext(handler=eh, op="your_operation_name")
"""

def lambda_handler(event, context):
    try:
        """
        region = account_context(context)['region']
        eh.capture_event(event)

        prev_state = event.get("prev_state") or {}
        project_code = event.get("project_code")
        repo_id = event.get("repo_id")
        cdef = event.get("component_def")
        cname = event.get("component_name")
        """
        print(f"event = {event}")
        # account_number = account_context(context)['number']
        region = account_context(context)['region']
        eh.capture_event(event)

        prev_state = event.get("prev_state") or {}
        project_code = event.get("project_code")
        repo_id = event.get("repo_id")
        cdef = event.get("component_def")
        cname = event.get("component_name")

        # Generate the identifier (if allowed) / name of the component here 
        
        # if there is no identifier beforehand, and you don't have config, just create

        # you pull in whatever arguments you care about
        s3_url_path = cdef.get("s3_url_path") or "/"
        base_domain_length = len(cdef.get("base_domain")) if cdef.get("base_domain") else 0
        domain = cdef.get("domain") or (form_domain(component_safe_name(project_code, repo_id, cname, no_underscores=True, max_chars=62-base_domain_length), cdef.get("base_domain")) if cdef.get("base_domain") else None)

        index_document = cdef.get("index_document") or "index.html"
        error_document = cdef.get("error_document") or "index.html"

        # If I've been run before, just run the functions, don't set any operations
        if event.get("pass_back_data"):
            print(f"pass_back_data found")
        elif event.get("op") == "upsert":
            # Declare two operations
            # First operation: what is the current state (get current state, compare it to whatever configuration I want to see if there is a difference)
            # Second operation: if no changes, ignore, else deploy changes (should be idempotent)
            eh.add_op("get_state")
            eh.add_op("setup_s3")
            eh.add_op("setup_status_objects")
            eh.add_op("put_object")
            if cdef.get("config"):
                eh.add_op("add_config")
            if domain:
                eh.add_op("setup_route53")

        elif event.get("op") == "delete":
            eh.add_op("setup_s3")
            eh.add_op("remove_codebuild_project", {"create_and_remove": False, "name": codebuild_project_name})
            print(prev_state)
            print(prev_state.get("props"))
            print(prev_state.get("rendef"))
            eh.add_props(prev_state.get("props", {}))
            print(eh.props)
            if domain:
                eh.add_op("setup_route53")


        """
        get_state()
        create_x() (sometimes multiple)
        update_x() (sometimes multiple, because updating only one part of state, want to retry to the exact update you want to do)
        delete_x()
        generate_props()
        
        """

        get_state(cname, cdef, codebuild_project_name, prev_state)
        setup_status_objects(bucket)
        add_config(bucket, object_name, cdef.get("config"))
        # put_object(bucket, object_name, s3_build_object_name)
        setup_s3(cname, cdef, domain, index_document, error_document)
        setup_codebuild_project(codebuild_project_name, bucket, object_name, s3_url_path, build_container_size, role_arn, prev_state, cname, repo_id, codebuild_runtime_versions, install_commands)
        start_build(codebuild_project_name)
        check_build_complete(bucket)
        set_object_metadata(cdef, s3_url_path, index_document, error_document, region, domain)
        setup_route53(cname, cdef, prev_state)
        remove_codebuild_project()
            
        return eh.finish()

    except Exception as e:
        msg = traceback.format_exc()
        print(msg)
        eh.add_log("Uncovered Error", {"error": msg}, is_error=True)
        eh.declare_return(200, 0, error_code=str(e))
        return eh.finish()







@ext(handler=eh, op="upsert_distribution")
def upsert_distribution(cname, cdef, codebuild_project_name, prev_state):


    pass






def merge_distribution_config(
    deployment_id, cert_base_domain, aliases, 
    oai_id, origin_bucket_name, origin_path, 
    extra_origins, cache_behaviours,
    distribution_config=None
):
    if not aliases:
        raise PermanentFailureException("Require aliases to be non-empty")

    acm_certificate_arn = get_acm_certificate_arn(cert_base_domain)

    desired_distribution_config = {
        'CallerReference': deployment_id,
        'Aliases': {
            'Quantity': len(aliases),
            'Items': aliases
        },
        'DefaultRootObject': 'index.html',
        'Origins': {
            'Quantity': 1 + len(extra_origins or []),
            'Items': [
                {
                    'Id': f'{aliases[0]}',
                    'DomainName': f'{origin_bucket_name}.s3.amazonaws.com',
                    'OriginPath': f'/{origin_path}',
                    'OriginShield': {
                        "Enabled": False
                    },
                    'CustomHeaders': {
                        'Quantity': 0
                    },
                    'S3OriginConfig': {
                        'OriginAccessIdentity': f'origin-access-identity/cloudfront/{oai_id}'
                    },
                    'ConnectionAttempts': 3,
                    'ConnectionTimeout': 10
                },
            ]
        },
        'DefaultCacheBehavior': {
            'TargetOriginId': f'{aliases[0]}',
            'ForwardedValues': {
                "Cookies": {
                    "Forward": "none"
                },
                "Headers": {
                    "Quantity": 0
                },
                "QueryString": False,
                "QueryStringCacheKeys": {
                    "Quantity": 0
                }
            },
            'TrustedKeyGroups': {
                'Enabled': False,
                'Quantity': 0
            },
            'TrustedSigners': {
                'Enabled': False,
                'Quantity': 0
            },
            'ViewerProtocolPolicy': 'redirect-to-https',
            'MinTTL': 0,
            "LambdaFunctionAssociations": {
                "Quantity": 0
            },
            'AllowedMethods': {
                'Quantity': 2,
                'Items': [
                    'HEAD', 'GET'
                ],
                'CachedMethods': {
                    'Quantity': 2,
                    'Items': [
                        'HEAD', 'GET'
                    ]
                }
            },
            "Compress": False,
            "DefaultTTL": 3600,
            "FieldLevelEncryptionId": "",
            'MaxTTL': 86400,
            "SmoothStreaming": False

        },
        'CacheBehaviors':{
            'Quantity': len(cache_behaviours or [])
        },
        'CustomErrorResponses': {
            'Quantity': 2,
            'Items': [
                {
                    "ErrorCachingMinTTL": 300,
                    'ErrorCode': 403,
                    'ResponsePagePath': '/index.html',
                    'ResponseCode': '200'
                },
                {
                    "ErrorCachingMinTTL": 300,
                    'ErrorCode': 404,
                    'ResponsePagePath': '/index.html',
                    'ResponseCode': '200'
                }
            ]
        },
        'Comment': f'{aliases[0]}',
        'Logging': {
            "Bucket": "",
            "Enabled": False,
            "IncludeCookies": False,
            "Prefix": ""
        },
        'PriceClass': 'PriceClass_All',
        'Enabled': True,
        'ViewerCertificate': {
            'ACMCertificateArn': f'{acm_certificate_arn}',
            "Certificate": f'{acm_certificate_arn}',
            "CertificateSource": "acm",
            "MinimumProtocolVersion": "TLSv1.1_2016",
            'SSLSupportMethod': 'sni-only'
        },
        'Restrictions': {
            'GeoRestriction': {
                'RestrictionType': 'none',
                'Quantity': 0
            }
        },
        'WebACLId': "",
        'HttpVersion': 'http2',
        'IsIPV6Enabled': True
    }

    if extra_origins:
        desired_distribution_config["Origins"]["Items"].extend(extra_origins)
        
    if cache_behaviours:
        desired_distribution_config["CacheBehaviors"]["Items"] = cache_behaviours
    
    result_distribution_config = dict(distribution_config) if distribution_config else {}
    result_distribution_config.update(desired_distribution_config)

    return result_distribution_config



def get_acm_certificate_arn(base_domain):

    acm = boto3.client('acm')
    try:
        response = acm.list_certificates(
            CertificateStatuses=[
                'PENDING_VALIDATION'|'ISSUED'|'INACTIVE'|'EXPIRED'|'VALIDATION_TIMED_OUT'|'REVOKED'|'FAILED',
            ],
            NextToken='string'
        )
    # except acm.exceptions.InvalidArgsException as e:
    #     eh.add_log("Error setting Object Metadata", {"error": str(e)}, True)
    #     print(e.response)

    except ClientError as e:
        handle_common_errors(e, eh, "Error listing ACM Certificates", 5)
    

    if len(response.get('CertificateSummaryList', [])) == 0 :

    

    """
    Response:
    {
        'NextToken': 'string',
        'CertificateSummaryList': [
            {
                'CertificateArn': 'string',
                'DomainName': 'string'
            },
        ]
    }
    """
    pass










# def format_tags(tags_dict):
#     return [{"Key": k, "Value": v} for k,v in tags_dict]
@ext(handler=eh, op="get_state")
def get_state(cname, cdef, codebuild_project_name, prev_state):
    # Know whether to create / update / or delete your component (distribution here)
    # There should be a separate function for each of those actions. Add those with eh.add_op()
    eh.add_op("setup_codebuild_project")
    
    if prev_state and prev_state.get("props") and prev_state.get("props").get("codebuild_project_name"):
        prev_codebuild_project_name = prev_state.get("props").get("codebuild_project_name")
        if codebuild_project_name != prev_codebuild_project_name:
            eh.add_op("remove_codebuild_project", {"create_and_remove": True, "name": prev_codebuild_project_name})


@ext(handler=eh, op="setup_route53")
def setup_route53(cname, cdef, prev_state):
    print(f"props = {eh.props}")
    if cdef.get("cloudfront"):
        # component_def = {
        #     "domain": c
        # }
        pass
    else:
        #  or prev_state.get("rendef", {}).get("S3", {})
        S3 = eh.props.get("S3", {})
        component_def = {
            "target_s3_region": S3.get("region"),
            "target_s3_bucket": S3.get("name")
        }

    function_arn = lambda_env('route53_extension_arn')

    proceed = eh.invoke_extension(
        arn=function_arn, component_def=component_def, 
        child_key="Route53", progress_start=85, progress_end=100,
        merge_props=False)

    if proceed:
        eh.add_links({"Website URL": f'http://{eh.props["Route53"].get("domain")}'})
    print(f"proceed = {proceed}")        

@ext(handler=eh, op="setup_s3")
def setup_s3(cname, cdef, domain, index_document, error_document):
    # l_client = boto3.client('lambda')

    website_configuration = None
    block_public_access = True
    # public_access_block = None
    acl = None
    if cdef.get("cloudfront"):
        bucket_policy = {
            "Version": "2012-10-17",
            "Id": "BucketPolicyCloudfront",
            "Statement": [
                {
                    "Sid": "AllowCloudfront",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": eh.ops['cloudfront_id']
                    },
                    "Action": "s3:GetObject",
                    "Resource": "$SELF$/*"
                }
            ]
        }
    # elif cdef.get("base_domain"):
    #     bucket_policy = "TBD"
    else: #No Cloudfront
        bucket_policy = {
            "Version": "2012-10-17",
            "Id": "BucketPolicy",
            "Statement": [
                {
                    "Sid": "PublicReadForGetBucketObjects",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "$SELF$/*"
                }
            ]
        }
        website_configuration = {
            "error_document": error_document,
            "index_document": index_document
        }
        block_public_access = False
        acl = {
            "GrantRead": "uri=http://acs.amazonaws.com/groups/global/AllUsers"
        }

    function_arn = lambda_env('s3_extension_arn')
    component_def = remove_none_attributes({
        # "CORS": True,
        "name": domain,
        "website_configuration": website_configuration,
        "bucket_policy": bucket_policy,
        "block_public_access": block_public_access,
        "acl": acl,
        "tags": cdef.get("s3_tags")
    })

    proceed = eh.invoke_extension(
        arn=function_arn, component_def=component_def, 
        child_key="S3", progress_start=20, progress_end=50,
        merge_props=False)
    print(f"proceed = {proceed}")


@ext(handler=eh, op="add_config")
def add_config(bucket, object_name, config):
    s3 = boto3.client("s3")
    print(f"add_config")

    try:
        filename = f"/tmp/{random_id()}.zip"
        with open(filename, "wb") as f:
            s3.download_fileobj(bucket, object_name, f)
            # f.write(response['Body'])
    except ClientError as e:
        handle_common_errors(e, eh, "Downloading Zipfile Failed", 15)
        return 0

    directory = f"/tmp/{random_id()}"
    os.makedirs(directory)
    with zipfile.ZipFile(filename, 'r') as archive:
        archive.extractall(path=directory)

    filepath = config.get("filepath") or 'src/config/config.js'
    data = config['data']

    path_to_write = f"{directory}/{filepath}"
    os.makedirs(path_to_write.rsplit('/', 1)[0], exist_ok=True)

    with open(path_to_write, 'w') as g:
        content = f"""
            export function get_config() {{
                return {json.dumps(data, indent=2)}
            }};
        """
        g.write(content)

    filename2 = f"/tmp/{random_id()}.zip"
    create_zip(filename2, directory)

    try:
        response = s3.upload_file(filename2, bucket, object_name)
    except ClientError as e:
        handle_common_errors(e, eh, "Reuploading Zipfile Failed", 15)

    eh.add_log("Added Config", {"config": config, "filestr": content})


@ext(handler=eh, op="setup_status_objects")
def setup_status_objects(bucket):
    s3 = boto3.client("s3")
    print(f"setup_status_objects")

    try:
        response = s3.get_object(Bucket=bucket, Key=ERROR_FILE)
        eh.add_log("Status Objects Exist", {"bucket": bucket, "success": SUCCESS_FILE, "error": ERROR_FILE})
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == "NoSuchKey":
            try:
                success = {"value": "success"}
                s3.put_object(
                    Body=json.dumps(success),
                    Bucket=bucket,
                    Key=SUCCESS_FILE
                )

                error = {"value": "error"}
                s3.put_object(
                    Body=json.dumps(error),
                    Bucket=bucket,
                    Key=ERROR_FILE
                )
        
                eh.add_log("Status Objects Created", {"bucket": bucket, "success": SUCCESS_FILE, "error": ERROR_FILE})
            except:
                eh.add_log("Error Writing Status Objects", {"error": str(e)}, True)
                eh.retry_error(str(e), 10)

        else:
            eh.add_log("Error Getting Status Object", {"error": str(e)}, True)
            eh.retry_error(str(e), 10)


@ext(handler=eh, op="setup_codebuild_project")
def setup_codebuild_project(codebuild_project_name, bucket, object_name, s3_url_path, build_container_size, role_arn, prev_state, component_name, repo_id, codebuild_runtime_versions, install_commands):
    codebuild = boto3.client('codebuild')
    destination_bucket = eh.props['S3']['name']
    pre_build_commands = []

    # pre_build_commands = ["npm install -g react-scripts"]
    # if bundler_name == "webpack":
    #     pass
    # elif bundler_name:
    #     pre_build_commands.extend([f"npm install -g {bundler_name}"])
    # else:
    #     pre_build_commands.extend([
    #         "npm install -g webpack",
    #         "npm install -g vite",
    #         "npm install -g browserify",
    #         "npm install -g esbuild",
    #         "npm install -g rollup",
    #         "npm install -g parcel"
    #     ])

    if build_container_size:
        if (build_container_size.lower() == "small") or (build_container_size == 1):
            build_container_size = "BUILD_GENERAL1_SMALL"
        elif (build_container_size.lower() == "medium") or (build_container_size == 2):
            build_container_size = "BUILD_GENERAL1_MEDIUM"
        elif (build_container_size.lower() == "large") or (build_container_size == 3):
            build_container_size = "BUILD_GENERAL1_LARGE"
        elif (build_container_size.lower() == "2xlarge") or (build_container_size.lower() == "xxlarge") or (build_container_size == 4):
            build_container_size = "BUILD_GENERAL1_2XLARGE"
        elif build_container_size in ["BUILD_GENERAL1_SMALL", "BUILD_GENERAL1_MEDIUM", "BUILD_GENERAL1_LARGE", "BUILD_GENERAL1_2XLARGE"]:
            pass
        else:
            eh.add_log("Invalid build_container_size, using MEDIUM", {"build_container_size": build_container_size})
            build_container_size = "BUILD_GENERAL1_MEDIUM"
    else:
        build_container_size = "BUILD_GENERAL1_MEDIUM"

    try:
        params = {
            "name": codebuild_project_name,
            "description": f"Codebuild project for component {component_name} in app {repo_id}",
            "source": {
                "type": "S3",
                "location": f"{bucket}/{object_name}",
                "buildspec": json.dumps({
                    "version": 0.2,
                    "env": {
                        "variables": {
                            "THIS_BUILD_KEY": "whocares"
                        }
                    },
                    "phases": remove_none_attributes({
                        "install": remove_none_attributes({
                            "runtime-versions": codebuild_runtime_versions,
                            "commands": install_commands or None
                        }) or None,
                        "pre_build": remove_none_attributes({
                            "commands": pre_build_commands or None
                        }) or None,
                        "build": {
                            "commands": [
                                "mkdir -p build",
                                "npm install",
                                "npm run build"
                            ]
                        },
                        "post_build": {
                            "commands": [
                                f'bash -c "if [ \"$CODEBUILD_BUILD_SUCCEEDING\" == \"1\" ]; then aws s3 cp s3://{bucket}/{SUCCESS_FILE} s3://{bucket}/$THIS_BUILD_KEY; else aws s3 cp s3://{bucket}/{ERROR_FILE} s3://{bucket}/$THIS_BUILD_KEY; fi"'
                            ]
                        }
                    }), 
                    "artifacts": {
                        "files": [
                            "**/*"
                        ],
                        "base-directory": "build"
                    }
                }, sort_keys=True)
            },
            "artifacts": {
                "type": "S3",
                "location": destination_bucket,
                "path": s3_url_path,
                "namespaceType": "NONE",
                "name": "/",
                "packaging": "NONE",
                "encryptionDisabled": True
            },
            "environment": {
                "type": "LINUX_CONTAINER",
                "image": "aws/codebuild/amazonlinux2-x86_64-standard:3.0",
                "computeType": build_container_size,
                "imagePullCredentialsType": "CODEBUILD"
            },
            "serviceRole": role_arn
        }
        print(f"params = {params}")
        this_params_hash = json.dumps(params, sort_keys=True)

        response = codebuild.create_project(**params).get("project")
        eh.add_log("Created Codebuild Project", response)
        eh.add_props({
            "codebuild_project_arn": response['arn'],
            "codebuild_project_name": response['name'],
            "hash": this_params_hash
        })
        eh.add_op("start_build")
        eh.add_links({"Codebuild Project": gen_codebuild_link(codebuild_project_name)})
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == "ResourceAlreadyExistsException":
            try:
                # if this_params_hash != prev_state.get("props", {}).get("hash"):
                response = codebuild.update_project(**params).get("project")
                eh.add_log("Updated Codebuild Project", response)
                eh.add_props({
                    "codebuild_project_arn": response['arn'],
                    "codebuild_project_name": response['name'],
                    "hash": json.dumps(params, sort_keys=True)
                })
                eh.add_op("start_build")
                eh.add_links({"Codebuild Project": gen_codebuild_link(codebuild_project_name)})
                
                # else:
                #     eh.add_log("No Need to Update Project", {"name": codebuild_project_name})
                #     eh.add_props({
                #         "codebuild_project_arn": prev_state.get("props", {}).get("codebuild_project_arn"),
                #         "codebuild_project_name": prev_state.get("props", {}).get("codebuild_project_name"),
                #         "hash": json.dumps(params, sort_keys=True)
                #     })
                #     eh.add_op("start_build")
                #     eh.add_links({"Codebuild Project": gen_codebuild_link(codebuild_project_name)})

            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == "InvalidInputException":
                    eh.add_log("Invalid Codebuild Input", {"error": str(e)}, True)
                    eh.perm_error("Invalid Codebuild Input", 50)
                elif e.response['Error']['Code'] == "ResourceNotFoundException":
                    eh.add_log("Codebuild Project Gone", {"error": str(e)}, True)
                    eh.perm_error("Codebuild Project Gone", 50)
                else:
                    eh.add_log("Codebuild Error", {"error": str(e)}, True)
                    eh.retry_error(str(e), 50)

        elif e.response['Error']['Code'] == "InvalidInputException":
            eh.add_log("Invalid Codebuild Input", {"error": str(e)}, True)
            eh.perm_error("Invalid Codebuild Input", 50)
        elif e.response['Error']['Code'] == "AccountLimitExceededException":
            eh.add_log("Codebuild Limit Excceeded", {"error": str(e)}, True)
            eh.perm_error("Codebuild Limit Excceeded", 50)
        else:
            eh.add_log("Codebuild Error", {"error": str(e)}, True)
            eh.retry_error(str(e), 50)


@ext(handler=eh, op="remove_codebuild_project")
def remove_codebuild_project():
    codebuild = boto3.client('codebuild')

    codebuild_project_name = eh.ops['remove_codebuild_project'].get("name")
    car = eh.ops['remove_codebuild_project'].get("create_and_remove")

    try:
        _ = codebuild.delete_project(name=codebuild_project_name)
        eh.add_log("Deleted Project if it Existed", {"name": codebuild_project_name})
    except botocore.exceptions.ClientError as e:
        eh.add_log("Remove Codebuild Error", {"error": str(e)}, True)
        eh.retry_error(str(e), 60 if car else 15)

@ext(handler=eh, op="start_build")
def start_build(codebuild_project_name):
    codebuild = boto3.client('codebuild')
    this_build_key = f"reactspabuilds/{random_id()}.json"

    try:
        response = codebuild.start_build(
            projectName=codebuild_project_name,
            environmentVariablesOverride=[
                {
                    "name": "THIS_BUILD_KEY",
                    "value": this_build_key,
                    "type": "PLAINTEXT"
                }
            ]).get("build")
        # eh.add_state({"codebuild_id": response.get("id")})
        eh.add_log("Start Build", response)
        # eh.add_state({"this_build_key": this_build_key})
        eh.add_op("check_build_complete", this_build_key)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] in ['InvalidInputException', 'ResourceNotFoundException']:
            eh.add_log("Start Build Failed", {"error": str(e)}, True)
            eh.perm_error(str(e), progress=50)
        else:
            eh.add_log("Start Build Error", {"error": str(e)}, True)
            eh.retry_error(str(e), progress=50)

@ext(handler=eh, op="check_build_complete")
def check_build_complete(bucket):
    s3 = boto3.client("s3")

    build_key = eh.ops['check_build_complete']
    print(f'build_key = {build_key}')
    print(f"bucket = {bucket}")
    
    try:
        response = s3.get_object(Bucket=bucket, Key=build_key)['Body']
        value = json.loads(response.read()).get("value")
        if value == "success":
            eh.add_log("Build Succeeded", response)
            eh.add_op("set_object_metadata")
            return None
        else:
            eh.add_log(f"End Build: error", response)
            eh.perm_error(f"End Build: error", progress=65)

    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] in ['NoSuchKey']:
            eh.add_log("Build In Progress", {"error": None})
            eh.retry_error(str(current_epoch_time_usec_num()), progress=65, callback_sec=8)
            # eh.add_log("Check Build Failed", {"error": str(e)}, True)
            # eh.perm_error(str(e), progress=65)
        else:
            eh.add_log("Check Build Error", {"error": str(e)}, True)
            eh.retry_error(str(e), progress=65)

    
    
@ext(handler=eh, op="set_object_metadata")
def set_object_metadata(cdef, s3_url_path, index_document, error_document, region, domain):
    s3 = boto3.client('s3')

    bucket_name = eh.props['S3']['name']
    key = f"{s3_url_path}/{index_document}" if s3_url_path and not (s3_url_path == "/") else index_document
    print(f"bucket_name = {bucket_name}")
    print(f"key = {key}")
    print(f"s3_url_path = {s3_url_path}")

    try:
        response = s3.copy_object(
            Bucket=bucket_name,
            Key=key,
            CopySource=f"{bucket_name}/{key}",
            MetadataDirective="REPLACE",
            CacheControl="max-age=0",
            ContentType="text/html"
        )
        eh.add_log(f"Fixed {index_document}", response)

        if error_document != index_document:
            key = f"{s3_url_path}/{error_document}" if s3_url_path else error_document
            response = s3.copy_object(
                Bucket=bucket_name,
                Key=key,
                CopySource=f"{bucket_name}/{key}",
                MetadataDirective="REPLACE",
                CacheControl="max-age=0",
                ContentType="text/html"
            )
            eh.add_log(f"Fixed {error_document}", response)

        if (not cdef.get("cloudfront")) and (not domain):
            eh.add_links({"Website URL": gen_s3_url(bucket_name, s3_url_path, region)})
    except botocore.exceptions.ClientError as e:
        eh.add_log("Error setting Object Metadata", {"error": str(e)}, True)
        eh.retry_error(str(e), 95 if not domain else 85)

# http://ck-azra-web-bucket.s3-website-us-east-1.amazonaws.com/login 
def gen_s3_url(bucket_name, s3_url_path, region):
    return f'http://{bucket_name}.s3-website-{region}.amazonaws.com{s3_url_path if s3_url_path != "/" else ""}'

def gen_codebuild_link(codebuild_project_name):
    return f"https://console.aws.amazon.com/codesuite/codebuild/projects/{codebuild_project_name}"

def create_zip(file_name, path):
    ziph=zipfile.ZipFile(file_name, 'w', zipfile.ZIP_DEFLATED)
    # ziph is zipfile handle
    for root, dirs, files in os.walk(path):
        for file in files:
            ziph.write(os.path.join(root, file), 
                       os.path.relpath(os.path.join(root, file), 
                                       os.path.join(path, '')))
    ziph.close()

def form_domain(bucket, base_domain):
    if bucket and base_domain:
        return f"{bucket}.{base_domain}"
    else:
        return None


