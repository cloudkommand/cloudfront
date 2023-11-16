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

acm = boto3.client("acm")
cloudfront = boto3.client("cloudfront")
s3 = boto3.client("s3")

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
        op = event.get("op")
        # Generate the identifier (if allowed) / name of the component here 
        
        # if there is no identifier beforehand, and you don't have config, just create

        # you pull in whatever arguments you care about
        
        if not eh.state.get("reference_id"):
            eh.add_state({"reference_id": eh.props.get("caller_reference") or random_id()})
        
        #This handles the case where pass back data has already set the ID.
        if not eh.props.get("id"):
            distribution_id = prev_state.get("props", {}).get("id") or cdef.get("existing_id")
            if distribution_id:
                eh.add_props({
                    "id": distribution_id, 
                    "location": prev_state.get("props", {}).get("location")
                })

        aliases = cdef.get("aliases")
        if not aliases:
            eh.perm_error("No aliases defined for cloudfront distribution", 0)
            return eh.finish()
            
        default_root_object = cdef.get("default_root_object", "index.html")

        oai_id = cdef.get("oai_id")

        log_bucket = f'{cdef.get("logs_s3_bucket")}.s3.amazonaws.com' if cdef.get("logs_s3_bucket") else ""
        logs_include_cookies = cdef.get("logs_include_cookies") or False
        logs_prefix = cdef.get("logs_s3_prefix") or ""

        price_class = fix_price_class(cdef.get("price_class"))
        waf_acl_value = cdef.get("waf_web_acl_arn") or cdef.get("web_acl_id") or ""

        enable_ipv6 = cdef.get("enable_ipv6", True)

        origins = cdef.get("origins") or {} # {"YOUR_ID_FOR_ORIGIN": {"origin_path": ... , }}

        cache_behaviors = cdef.get("cache_behaviors") or []

        def set_cache_policy_id(eh, def_item):
            try:
                cache_policy_id = def_item.get("cache_policy_id") or cache_policy_name_to_id(def_item.get("cache_policy_name")) or "658327ea-f89d-4fab-a63d-7e88639e58f6"
                return cache_policy_id
            except KeyError as e:
                cache_policy_id = ""
                eh.add_log("Invalid Cache Policy Name", {"value": str(e)})
                eh.perm_error(str(e), 0)
                return cache_policy_id
                    
        def set_origin_request_policy_id(eh, def_item):
            try:
                origin_request_policy_id = def_item.get("origin_request_policy_id") or origin_request_policy_name_to_id(def_item.get("origin_request_policy_name")) or None
                return origin_request_policy_id
            except KeyError as e:
                origin_request_policy_id = ""
                eh.add_log("Invalid Origin Request Policy Name", {"value": str(e)})
                eh.perm_error(str(e), 0)
                return origin_request_policy_id
        
        def set_response_headers_policy_id(eh, def_item):
            try:
                response_headers_policy_id = def_item.get("response_headers_policy_id") or response_headers_policy_name_to_id(def_item.get("response_headers_policy_name")) or "eaab4381-ed33-4a86-88ca-d9558dc6cd63"
                return response_headers_policy_id
            except KeyError as e:
                response_headers_policy_id = ""
                eh.add_log("Invalid Response Header Policy Name", {"value": str(e)})
                eh.perm_error(str(e), 0)
                return response_headers_policy_id
    
        tags = cdef.get("tags") or {}

        error_responses = cdef.get("error_responses") or {
            'Quantity': 2,
            'Items': [
                {
                    "ErrorCachingMinTTL": 300,
                    'ErrorCode': 403,
                    'ResponsePagePath': f'/{default_root_object}',
                    'ResponseCode': '200'
                },
                {
                    "ErrorCachingMinTTL": 300,
                    'ErrorCode': 404,
                    'ResponsePagePath': f'/{default_root_object}',
                    'ResponseCode': '200'
                }
            ]
        }

        # Get all target_s3_bucket references
        list_of_target_s3_buckets = []
        if origins:
            for item in origins:
                if origins[item].get("target_s3_bucket"):
                    list_of_target_s3_buckets.append([item, origins[item].get("target_s3_bucket")])
        if cdef.get("target_s3_bucket"):
            list_of_target_s3_buckets.append(["default", target_s3_bucket])

        # If I've been run before, just run the functions, don't set any operations
        if event.get("pass_back_data"):
            print(f"pass_back_data found")
        elif op == "upsert":
            eh.add_op("get_acm_cert")
            if list_of_target_s3_buckets:
                eh.add_op("get_s3_website_config", list_of_target_s3_buckets)
            if distribution_id:
                eh.add_op("get_distribution", distribution_id)
            else:
                eh.add_op("create_distribution")
        elif op == "delete":
            # eh.add_op("get_acm_cert")
            eh.add_props({
                "certificate_arn": prev_state.get("props", {}).get("certificate_arn"),
                "domain_name": prev_state.get("props", {}).get("domain_name")
            })
            
            eh.add_op("get_distribution", distribution_id)
            eh.add_op("delete_distribution", distribution_id)


        """
        get_state()
        create_x() (sometimes multiple)
        update_x() (sometimes multiple, because updating only one part of state, want to retry to the exact update you want to do)
        delete_x()
        generate_props()
        
        """

        get_acm_cert(aliases, region)
        get_s3_website_config() # TODO: edit this to work with the origin keys

        ###
        # The S3 origin config bit for a website is only designed to work when the base level target_s3_bucket is a website. So if you have an S3 bucket website, you must set it as target_s3_bucket.
        ###
        
        def format_targets(target, target_type, origin_item_key=None, include_s3_origin_config=False):
            if (op == "upsert") and target_type == "s3":
                #Warning about S3 Regions, they are funny. At some point should test in us-east-2 or something
                if eh.state.get("s3_is_website").get(origin_item_key):
                    domain_name = f"{target}.s3-website.{region}.amazonaws.com"
                else:
                    domain_name = f"{target}.s3.{region}.amazonaws.com"
                    if not oai_id:
                        eh.add_log("WARN: No OAI", {"cdef": cdef}, is_error=True)
                    s3_origin_config = remove_none_attributes({
                        "OriginAccessIdentity": f'origin-access-identity/cloudfront/{oai_id}' if oai_id else None
                    }) or None
                    if include_s3_origin_config:
                        return s3_origin_config, domain_name
            elif target_type == "s3" and include_s3_origin_config:
                domain_name = eh.props['domain_name']
            
            elif target_type == "ec2":
                domain_name = f"{target}.compute-1.amazonaws.com"
            elif target_type == "load_balancer":
                domain_name = f"{target}.{region}.elb.amazonaws.com"
            elif target_type == "domain":
                domain_name = target
            
            return domain_name
        
        # Format origins now that S3 related config information has been retrieved
        formatted_origins = {}
        if origins:
            for origin_key in origins:
                item_s3_origin_config = None
                item_custom_origin_config = None

                origin_item = origins[origin_key]
                # Get a properly formatted domain name
                if origin_item.get("target_s3_bucket"): 
                    item_s3_origin_config, item_domain_name = format_targets(target=origin_item.get("target_s3_bucket"), target_type="s3", include_s3_origin_config=True)
                elif origin_item.get("target_domain_name"):
                    item_domain_name = format_targets(target=origin_item.get("target_domain_name"), target_type="domain")
                elif origin_item.get("target_load_balancer"):
                    item_domain_name = format_targets(target=origin_item.get("target_load_balancer"), target_type="load_balancer")
                elif origin_item.get("target_ec2_instance"):
                    item_domain_name = format_targets(target=origin_item.get("target_ec2_instance"), target_type="ec2")
                item_origin_path = origin_item.get("origin_path") or ""
                item_origin_shield = remove_none_attributes({
                    "Enabled": bool(origin_item.get("origin_shield")),
                    "OriginShieldRegion": region if origin_item.get("origin_shield") else None
                })
                item_custom_origin_headers = origin_item.get("custom_origin_headers") or {}
                item_custom_headers = remove_none_attributes({
                    "Quantity": len(item_custom_origin_headers.keys()), 
                    "Items": [{"HeaderName": k, "HeaderValue": v} for k,v in item_custom_origin_headers.items()] or None
                })
                print(f"item_custom_headers = {item_custom_headers}")
                item_allowed_ssl_protocols = origin_item.get("allowed_ssl_protocols") or ["TLSv1", "TLSv1.1", "TLSv1.2"]

                if not item_s3_origin_config:
                    item_custom_origin_config = {
                        "HTTPPort": 80,
                        "HTTPSPort": 443,
                        "OriginProtocolPolicy": "https-only" if origin_item.get("force_https") else "match-viewer",
                        "OriginSslProtocols": {
                            "Quantity": len(item_allowed_ssl_protocols),
                            "Items": item_allowed_ssl_protocols
                        },
                        "OriginReadTimeout": 30,
                        "OriginKeepaliveTimeout": 5,
                    }

                formatted_origin = remove_none_attributes({
                    'Id': f"{item_domain_name}{item_origin_path}",
                    'DomainName': item_domain_name,
                    'OriginPath': item_origin_path,
                    'OriginShield': item_origin_shield,
                    'CustomHeaders': item_custom_headers,
                    'S3OriginConfig': item_s3_origin_config,
                    'CustomOriginConfig': item_custom_origin_config,
                    'ConnectionAttempts': 3,
                    'ConnectionTimeout': 10
                })
                formatted_origins[origin_key] = formatted_origin
        else: # DEPRECATED: this path will no longer be supported in the future to minimize confusion in usage.

            s3_origin_config = None
            custom_origin_config = None

            # Origin-related values
            target_s3_bucket = cdef.get("target_s3_bucket")
            target_ec2_instance = cdef.get("target_ec2_instance")
            target_load_balancer = cdef.get("target_load_balancer")
            target_domain_name = cdef.get("target_domain_name")
            origin_path = cdef.get("origin_path") or ""
            if origin_path.endswith("/"):
                origin_path = origin_path[:-1]
            custom_origin_headers = cdef.get("custom_origin_headers") or {}
            custom_headers = remove_none_attributes({
                "Quantity": len(custom_origin_headers.keys()), 
                "Items": [{"HeaderName": k, "HeaderValue": v} for k,v in custom_origin_headers.items()] or None
            })
            print(f"custom_headers = {custom_headers}")
            origin_shield = remove_none_attributes({
                "Enabled": bool(cdef.get("origin_shield")),
                "OriginShieldRegion": region if cdef.get("origin_shield") else None
            })
            allowed_ssl_protocols = cdef.get("allowed_ssl_protocols") or ["TLSv1", "TLSv1.1", "TLSv1.2"]

            origin_key = "default"
            # Properly format the urls and set the s3_origin_config where necessary
            if target_s3_bucket: 
                s3_origin_config, domain_name = format_targets(target=target_s3_bucket, target_type="s3", include_s3_origin_config=True)
            elif target_domain_name:
                domain_name = format_targets(target=target_domain_name, target_type="domain")
            elif target_load_balancer:
                domain_name = format_targets(target=target_load_balancer, target_type="load_balancer")
            elif target_ec2_instance:
                domain_name = format_targets(target=target_ec2_instance, target_type="ec2")
            if not s3_origin_config:
                custom_origin_config = {
                    "HTTPPort": 80,
                    "HTTPSPort": 443,
                    "OriginProtocolPolicy": "https-only" if cdef.get("force_https") else "match-viewer",
                    "OriginSslProtocols": {
                        "Quantity": len(allowed_ssl_protocols),
                        "Items": allowed_ssl_protocols
                    },
                    "OriginReadTimeout": 30,
                    "OriginKeepaliveTimeout": 5,
                }
            formatted_origin = remove_none_attributes({
                'Id': f"{domain_name}{origin_path}",
                'DomainName': domain_name,
                'OriginPath': origin_path,
                'OriginShield': origin_shield,
                'CustomHeaders': custom_headers,
                'S3OriginConfig': s3_origin_config,
                'CustomOriginConfig': custom_origin_config,
                'ConnectionAttempts': 3,
                'ConnectionTimeout': 10
            })
            formatted_origins[origin_key] = formatted_origin
        
        # Format cache behaviors and select the default
        default_cache_behavior = {}
        formatted_cache_behaviors = []
        if cache_behaviors:
            default_ix = 0
            for ix, item in enumerate(cache_behaviors):
                if item.get("default"):
                    default_ix = ix
                    break
            for ix, behavior in enumerate(cache_behaviors):
                formatted_cache_item = remove_none_attributes({
                    'TargetOriginId': formatted_origins.get(behavior.get("target_origin")) or "",
                    'TrustedKeyGroups': remove_none_attributes({
                        'Enabled': bool(behavior.get("key_group_ids", [])),
                        'Quantity': len(behavior.get("key_group_ids", [])),
                        'Items': behavior.get("key_group_ids", []) or None
                    }),
                    'TrustedSigners': {
                        'Enabled': False,
                        'Quantity': 0
                    },
                    'ViewerProtocolPolicy': 'redirect-to-https' if behavior.get("force_https") else "allow-all",
                    "LambdaFunctionAssociations": {
                        "Quantity": 0
                    },
                    'AllowedMethods': {
                        'Quantity': len(behavior.get("allowed_methods", ["HEAD", "GET"])),
                        'Items': behavior.get("allowed_methods", ["HEAD", "GET"]),
                        'CachedMethods': {
                            'Quantity': len(behavior.get("cached_methods", ["HEAD", "GET"])),
                            'Items': behavior.get("cached_methods", ["HEAD", "GET"])
                        }
                    },
                    "ResponseHeadersPolicyId": set_response_headers_policy_id(eh, behavior),
                    "CachePolicyId": set_cache_policy_id(eh, behavior),
                    "OriginRequestPolicyId": set_origin_request_policy_id(eh, behavior),
                    "Compress": False if set_cache_policy_id(eh, behavior) in [
                            "4135ea2d-6df8-44a3-9df3-4b5a84be39ad", "b2884449-e4de-46a7-ac36-70bc7f1ddd6d"
                        ] else True,
                    "FieldLevelEncryptionId": "",
                    "SmoothStreaming": False
                })
                if default_ix == ix:
                    default_cache_behavior = formatted_cache_item
                else:
                    formatted_cache_item['PathPattern'] = behavior.get("path_pattern")
                    formatted_cache_behaviors.append(formatted_cache_item)
        else: # DEPRECATED: this path will no longer be supported in the future to minimize confusion in usage.
            # The deprecated path only supports the default and nothing else
            # In the future, this else statement will be converted to provide a default cache behavior when nothing is set.

            key_group_ids = cdef.get("key_group_ids") or []
            cached_methods = cdef.get("cached_methods") or ["HEAD", "GET"]
            allowed_methods = cdef.get("allowed_methods") or ["HEAD", "GET"]
            cache_policy_id = set_cache_policy_id(eh, cdef)
            origin_request_policy_id = set_origin_request_policy_id(eh, cdef)
            response_headers_policy_id = set_response_headers_policy_id(eh, cdef)

            formatted_cache_behaviors = []
            default_cache_behavior = remove_none_attributes({
                'TargetOriginId': formatted_origins.get("default").get("Id"),
                # 'ForwardedValues': {
                #     "Cookies": {
                #         "Forward": "none"
                #     },
                #     "Headers": {
                #         "Quantity": 0
                #     },
                #     "QueryString": False,
                #     "QueryStringCacheKeys": {
                #         "Quantity": 0
                #     }
                # },
                'TrustedKeyGroups': remove_none_attributes({
                    'Enabled': bool(key_group_ids),
                    'Quantity': len(key_group_ids),
                    'Items': key_group_ids or None
                }),
                'TrustedSigners': {
                    'Enabled': False,
                    'Quantity': 0
                },
                'ViewerProtocolPolicy': 'redirect-to-https' if cdef.get("force_https") else "allow-all",
                "LambdaFunctionAssociations": {
                    "Quantity": 0
                },
                'AllowedMethods': {
                    'Quantity': len(allowed_methods),
                    'Items': allowed_methods,
                    'CachedMethods': {
                        'Quantity': len(cached_methods),
                        'Items': cached_methods
                    }
                },
                "ResponseHeadersPolicyId": response_headers_policy_id,
                "CachePolicyId": cache_policy_id,
                "OriginRequestPolicyId": origin_request_policy_id,
                "Compress": False if cache_policy_id in [
                        "4135ea2d-6df8-44a3-9df3-4b5a84be39ad", "b2884449-e4de-46a7-ac36-70bc7f1ddd6d"
                    ] else True,
                "FieldLevelEncryptionId": "",
                "SmoothStreaming": False
            })

        converted_formatted_origins = [formatted_origin[origin_key] for origin_key in formatted_origins]

        desired_config = remove_none_attributes({
            'CallerReference': eh.state["reference_id"],
            'Aliases': {
                'Quantity': len(aliases),
                'Items': aliases
            },
            'DefaultRootObject': default_root_object or "",
            'Origins': {
                'Quantity': len(converted_formatted_origins),
                'Items': converted_formatted_origins
            },
            'DefaultCacheBehavior': default_cache_behavior,
            'CacheBehaviors': remove_none_attributes({
                'Quantity': len(formatted_cache_behaviors) or 0,
                'Items': formatted_cache_behaviors if formatted_cache_behaviors else None
            }),
            'CustomErrorResponses': error_responses,
            'Comment': f'{aliases[0]}',
            'Logging': {
                "Bucket": log_bucket,
                "Enabled": bool(log_bucket),
                "IncludeCookies": logs_include_cookies,
                "Prefix": logs_prefix
            },
            'PriceClass': price_class,
            'Enabled': True if op == "upsert" else False,
            'ViewerCertificate': remove_none_attributes({
                'ACMCertificateArn': eh.props.get("certificate_arn"),
                "CloudFrontDefaultCertificate": False,
                # "Certificate": eh.props["certificate_arn"],
                # "CertificateSource": "acm",
                "MinimumProtocolVersion": "TLSv1.2_2021" if eh.props.get("certificate_arn") else None,
                'SSLSupportMethod': 'sni-only'  if eh.props.get("certificate_arn") else None
            }) or None,
            'Restrictions': {
                'GeoRestriction': {
                    'RestrictionType': 'none',
                    'Quantity': 0
                }
            },
            'WebACLId': waf_acl_value or "",
            'HttpVersion': 'http2',
            'IsIPV6Enabled': enable_ipv6
        })
        
        print(f"desired_config = {desired_config}")

        get_distribution(desired_config, op)
        create_distribution(desired_config, tags)
        update_distribution(desired_config)
        remove_tags()
        add_tags()
        check_distribution_deployed()
        delete_distribution()
            
        return eh.finish()

    except Exception as e:
        msg = traceback.format_exc()
        print(msg)
        eh.add_log("Unexpected Error", {"error": msg}, is_error=True)
        eh.declare_return(200, 0, error_code=str(e))
        return eh.finish()

@ext(handler=eh, op="get_acm_cert")
def get_acm_cert(domain_names, region):
    cursor = 'none'
    certs = []
    while cursor:
        try:
            payload = remove_none_attributes({
                "CertificateStatuses": ["ISSUED"],
                "NextToken": cursor if cursor != 'none' else None
            })
            cert_response = acm.list_certificates(**payload)
            print(f"cert_response = {cert_response}")
            for cert in cert_response.get("CertificateSummaryList", []):
                cert_detail = acm.describe_certificate(CertificateArn=cert["CertificateArn"])
                print(f"cert_detail = {cert_detail}")
                certs.append(cert_detail["Certificate"])
            
            cursor = cert_response.get("nextToken")
        except ClientError as e:
            handle_common_errors(e, eh, "List Certificates Failed", 0)
    

    #Check that all domain names are in the cert and all of them have one domain name that matches
    #the number of periods in the domain name
    sorted_matching_certs = []
    for cert in certs:
        add = True
        for domain_name in domain_names:
            matching_sans = list(filter(lambda x: domain_name.endswith(x.replace("*", "")), cert["SubjectAlternativeNames"]))
            print(matching_sans)
            if not matching_sans:
                add = False
                break
            elif (not domain_name in matching_sans
                ) and not any(
                [san.startswith("*") and (domain_name.count(".") == san.count(".")) 
                for san in matching_sans]):
                
                add = False
                break
        print(f"cert = {cert}, add = {add}")
        if add:
            sorted_matching_certs.append(cert)

    sorted_matching_certs.sort(key=lambda x:-len(x['DomainName']))
    print(f"sorted_matching_certs = {sorted_matching_certs}")

    if not sorted_matching_certs:
        eh.perm_error("No Matching ACM Certificate Found, Cannot Create Distribution", 0)
        eh.add_log("No Matching ACM Certificates", {"all_certs": certs}, is_error=True)
        return 0

    # eh.add_op("get_domain_name")
    certificate_arn = sorted_matching_certs[0]['CertificateArn']
    certificate_domain_name = sorted_matching_certs[0]['DomainName']
    eh.add_log("Found ACM Certificate", {"certificate_arn": certificate_arn, "certificate_domain_name": certificate_domain_name})
    eh.add_props({
        "certificate_arn": certificate_arn,
        "certificate_domain_name": certificate_domain_name
    })
    eh.add_links({"ACM Certificate": gen_certificate_link(certificate_arn, region)})


@ext(handler=eh, op="get_s3_website_config")
def get_s3_website_config():
    """
    Get the S3 website configuration for a bucket
    """
    bucket_name_lists = eh.ops.get("get_s3_website_config")

    s3_is_website = {}
    for item in bucket_name_lists:
        try:
            s3 = boto3.client('s3')
            config = s3.get_bucket_website(Bucket=item[1])
            s3_is_website[item[0]] = True
            eh.add_log("Got S3 Website Config", {"config": config})
            # eh.add_state({"s3_is_website": True})
            # eh.add_state({"s3_root_document": config.get("IndexDocument", {}).get("Suffix")})
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchWebsiteConfiguration':
                # eh.add_state({"s3_is_website": False})
                s3_is_website[item[0]] = False
                config = None
            else:
                handle_common_errors(e, eh, "Failed to get S3 Website Config", 4)
                # return 0
    eh.add_state({"s3_is_website": s3_is_website})
    return 0

@ext(handler=eh, op="get_distribution")
def get_distribution(desired_config, op):
    distribution_id = eh.ops["get_distribution"]

    try:
        result = cloudfront.get_distribution(Id=distribution_id)
        distribution = result["Distribution"]
        eh.add_log("Got Distribution", {"distribution": distribution})
        print(distribution)
        print(desired_config)

        update_distribution = get_distribution_needs_update(desired_config, distribution)

        eh.add_props({
            "id": distribution["Id"],
            "arn": distribution["ARN"],
            "domain_name": distribution["DomainName"],
            "caller_reference": distribution["DistributionConfig"]["CallerReference"],
            "etag": result.get("ETag")
        })
        eh.add_links({"CloudFront Distribution": gen_distribution_link(distribution["Id"])})
        if update_distribution:
            eh.add_op("update_distribution")
            
        else:
            eh.add_log("No Update Necessary. Exiting", {"distribution": distribution})

    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchDistribution":
            eh.add_log("Distribution Does Not Exist", {"distribution_id": distribution_id})
            if op == "upsert":
                eh.add_op("create_distribution")
            else:
                eh.add_log("Distribution Does Not Exist. Exiting", {"distribution_id": distribution_id})
                eh.complete_op("delete_distribution")
        else:
            handle_common_errors(e, eh, "Get Distribution Failed", 7)
        
@ext(handler=eh, op="create_distribution")
def create_distribution(desired_config, tags):
    try:
        if tags:
            distribution = cloudfront.create_distribution_with_tags(
                DistributionConfigWithTags={
                    "Tags": {
                        "Items": format_tags(tags)
                    },
                    "DistributionConfig": desired_config
                }
            )
        else:
            distribution = cloudfront.create_distribution(
                DistributionConfig= desired_config
            )
            
        eh.add_log("Created Distribution", {"distribution": distribution})
        print(distribution)
        eh.add_props({
            "id": distribution["Distribution"]["Id"],
            "arn": distribution["Distribution"]["ARN"],
            "domain_name": distribution["Distribution"]["DomainName"],
            "caller_reference": distribution["Distribution"]["DistributionConfig"]["CallerReference"],
            "location": distribution.get("Location"),
            "etag": distribution.get("ETag")
        })
        eh.add_links({"CloudFront Distribution": gen_distribution_link(distribution["Distribution"]["Id"])})
        eh.add_op("check_distribution_deployed")

    except ClientError as e:
        handle_common_errors(e, eh, "Create Distribution Failed", 12, CLOUDFRONT_ERRORS)


@ext(handler=eh, op="update_distribution")
def update_distribution(desired_config):
    cloudfront_id = eh.props.get("id")

    try:
        desired_config["CallerReference"] = eh.props.get("caller_reference")
        # _ = desired_config.pop("CallerReference")
        distribution = cloudfront.update_distribution(
            DistributionConfig=desired_config,
            Id=cloudfront_id,
            IfMatch=eh.props.get("etag")
        )

        eh.add_log("Updated Distribution", {"distribution": distribution})
        eh.add_props({
            "id": distribution["Distribution"]["Id"],
            "arn": distribution["Distribution"]["ARN"],
            "domain_name": distribution["Distribution"]["DomainName"],
            "caller_reference": distribution["Distribution"]["DistributionConfig"]["CallerReference"],
            "location": distribution.get("Location") or eh.props.get("location"),
            "etag": distribution.get("ETag")
        })
        eh.add_op("check_distribution_deployed")
    except ClientError as e:
        if (desired_config.get("Enabled") == False) and (e.response["Error"]["Code"] == "NoSuchDistribution"):
            eh.add_log("Distribution Does Not Exist", {"distribution_id": cloudfront_id})
            eh.complete_op("delete_distribution")
        else:
            handle_common_errors(e, eh, "Update Distribution Failed", 12, CLOUDFRONT_ERRORS)

@ext(handler=eh, op="delete_distribution")
def delete_distribution():
    cloudfront_id = eh.ops["delete_distribution"]

    try:
        cloudfront.delete_distribution(
            Id=cloudfront_id,
            IfMatch=eh.props.get("etag")
        )
        eh.add_log("Deleted Distribution", {"distribution_id": cloudfront_id})
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchDistribution":
            eh.add_log("Distribution Does Not Exist", {"distribution_id": cloudfront_id})
        #Test this
        elif e.response["Error"]["Code"] == "DistributionNotDisabled":
            eh.add_log("Distribution Not Fully Disabled", {"distribution_id": cloudfront_id})
            eh.retry_error(random_id(), 60, callback_sec=8)
        else:
            handle_common_errors(e, eh, "Delete Distribution Failed", 60, CLOUDFRONT_ERRORS)

@ext(handler=eh, op="check_distribution_deployed")
def check_distribution_deployed():
    try:
        response = cloudfront.get_distribution(
            Id=eh.props.get("id")
        )

        if response["Distribution"]["Status"] != "Deployed":
            eh.add_log("Distribution Deploying", {"id": eh.props.get("id"), "status": response["Distribution"]["Status"]})
            eh.retry_error(random_id(), 65, callback_sec=8)
        else:
            eh.add_log("Distribution Fully Deployed")

    except ClientError as e:
        handle_common_errors(e, eh, "Get Distribution Failed", 65, CLOUDFRONT_ERRORS)

@ext(handler=eh, op="add_tags")
def add_tags():
    formatted_tags = format_tags(eh.ops['add_tags'])

    try:
        cloudfront.tag_resource(
            ResourceArn=eh.props['arn'],
            Tags={"Items": formatted_tags}
        )
        eh.add_log("Tags Added", {"tags": formatted_tags})

    except botocore.exceptions.ClientError as e:
        handle_common_errors(e, eh, "Add Tags Failed", 92, ["InvalidArgument", "InvalidTagging"])
        

@ext(handler=eh, op="remove_tags")
def remove_tags():
    try:
        cloudfront.untag_resource(
            ResourceArn=eh.props['arn'],
            TagKeys={"Items": eh.ops['remove_tags']}
        )
        eh.add_log("Tags Removed", {"tags": eh.ops['remove_tags']})

    except botocore.exceptions.ClientError as e:
        handle_common_errors(e, eh, "Remove Tags Failed", 85, ["InvalidArgument", "InvalidTagging"])

def gen_certificate_link(certificate_arn, region):
    return f"https://console.aws.amazon.com/acm/home?region={region}#/certificate/{certificate_arn.rsplit('/')[0]}"

def gen_distribution_link(distribution_id):
    return f"https://console.aws.amazon.com/cloudfront/home?region=us-east-1#/distributions/{distribution_id}"

def format_tags(tags_dict):
    return [{"Key": k, "Value": v} for k,v in tags_dict.items()]

def compare_items(a, b, key="Id"):
    a_dict, b_dict = {}, {}
    if a.get("Quantity", 0) != 0:
        if key == "SET":
            a_dict = set(a["Items"])
        else:
            a_dict = {x[key]:x for x in a["Items"]}
    if b.get("Quantity", 0) != 0:
        if key == "SET":
            b_dict = set(b["Items"])
        else:
            b_dict = {x[key]:x for x in b["Items"]}
    return a_dict == b_dict

def get_distribution_needs_update(desired_config, distribution):
    for k,v in desired_config.items():
        if k in ["CallerReference"]:
            continue
        elif k in ["Origins"]:
            if v.get("Quantity") == distribution["DistributionConfig"].get("Origins", {}).get("Quantity"):
                origin_dict = {x["DomainName"]:x for x in v.get("Items", [])}
                existing_dict = {x["DomainName"]:x for x in distribution["DistributionConfig"].get("Origins", {}).get("Items", [])}
                if set(origin_dict.keys()) != set(existing_dict.keys()):
                    print("Different origins")
                    print(set(origin_dict.keys()))
                    print(set(existing_dict.keys()))
                    return True

                for k2, v2 in origin_dict.items():
                    for k3, v3 in v2.items():
                        if k3 == "CustomHeaders":
                            if not compare_items(v2, existing_dict.get(k2, {}), "HeaderName"):
                                print(v2)
                                print(existing_dict)
                                return True
                        elif k3 == "CustomOriginConfig":
                            if existing_dict[k2].get(k3):
                                for k4, v4 in v3.items():
                                    if k4 == "OriginSslProtocols":
                                        if not compare_items(v4, existing_dict.get(k2, {}).get(k3, {}).get(k4, {}), key="SET"):
                                            print(v4)
                                            print(existing_dict)
                                            return True
                                    elif v4 != existing_dict.get(k2, {}).get(k3, {}).get(k4):
                                        print(v3)
                                        print(existing_dict)
                                        return True
                        elif (v3 or existing_dict[k2].get(k3)) and v3 != existing_dict[k2].get(k3):
                            print(k3)
                            print(v3)
                            print(existing_dict[k2].get(k3))
                            return True
            else:
                print(f"Different number of origins")
                print(v)
                print(distribution.get("Origins", {}))
                return True
        elif k in ["CustomErrorResponses"]:
            if not compare_items(v, distribution["DistributionConfig"][k], key="ErrorCode"):
                print(k)
                print(v)
                print(distribution["DistributionConfig"][k])
                return True
        elif k == "DefaultCacheBehavior":
            for k2, v2 in v.items():
                if k2 == "TrustedKeyGroups":
                    if not compare_items(v2, distribution["DistributionConfig"][k][k2], "SET"):
                        print(k2)
                        print(v2)
                        print(distribution["DistributionConfig"][k][k2])
                        return True
                elif k2 in ["AllowedMethods"]:
                    if not compare_items(v2, distribution["DistributionConfig"][k][k2], key="SET"):
                        print(v2)
                        print(distribution["DistributionConfig"][k][k2])
                        return True
                    if not compare_items(v2["CachedMethods"], distribution["DistributionConfig"][k][k2]["CachedMethods"], key="SET"):
                        print(v2["CachedMethods"])
                        print(distribution["DistributionConfig"][k][k2])
                        return True
                elif v2 != distribution["DistributionConfig"][k][k2]:
                    print(k2)
                    print(v2)
                    print(distribution["DistributionConfig"][k][k2])
                    return True
        elif k == "CacheBehaviors":
            if v.get("Quantity") == distribution["DistributionConfig"].get("CacheBehaviors", {}).get("Quantity"):
                cache_behaviors_dict = {x["TargetOriginId"]:x for x in v.get("Items", [])}
                existing_cache_behaviors_dict = {x["TargetOriginId"]:x for x in distribution["DistributionConfig"].get("CacheBehaviors", {}).get("Items", [])}

                if set(cache_behaviors_dict.keys()) != set(existing_cache_behaviors_dict.keys()):
                    print("Different cache behaviors")
                    print(set(cache_behaviors_dict.keys()))
                    print(set(existing_cache_behaviors_dict.keys()))
                    return True
                
                for k2, v2 in cache_behaviors_dict.items():
                    for k3, v3 in v2.items():
                        if k3 == "TrustedKeyGroups":
                            if not compare_items(v3, existing_cache_behaviors_dict.get(k2, {}).get(k3, {}), "SET"):
                                print(v3)
                                print(existing_cache_behaviors_dict)
                                return True
                        elif k3 == "AllowedMethods":
                            if not compare_items(v3, existing_cache_behaviors_dict.get(k2, {}).get(k3, {}), "SET"):
                                print(v3)
                                print(existing_cache_behaviors_dict)
                                return True
                            if not compare_items(v3["CachedMethods"], existing_cache_behaviors_dict.get(k2, {}).get(k3, {}).get("CachedMethods", {}), key="SET"):
                                print(v3["CachedMethods"])
                                print(distribution["DistributionConfig"][k][k2])
                                return True
                        elif (v3 or existing_cache_behaviors_dict[k2].get(k3)) and v3 != existing_cache_behaviors_dict[k2].get(k3):
                            print(k3)
                            print(v3)
                            print(existing_cache_behaviors_dict[k2].get(k3))
                            return True
            else:
                print(f"Different number of CacheBehaviors")
                print(v)
                print(distribution.get("DistributionConfig", {}).get("CacheBehaviors", {}))
                return True
        elif k == "ViewerCertificate":
            for k2, v2 in v.items():
                if v2 != distribution["DistributionConfig"].get(k, {}).get(k2):
                    print(k2)
                    print(v2)
                    print(distribution["DistributionConfig"][k][k2])
                    return True
        elif v != distribution["DistributionConfig"][k]:
            print(v)
            print(distribution["DistributionConfig"][k])
            return True
        

def cache_policy_name_to_id(cache_policy_name):
    if not cache_policy_name:
        return None
    else:
        try:
            return CACHE_POLICIES[cache_policy_name]
        except:
            raise KeyError(f"{cache_policy_name} is not a valid cache policy name. Valid names are {list(CACHE_POLICIES.keys())}")

def origin_request_policy_name_to_id(origin_request_policy_name):
    if not origin_request_policy_name:
        return None
    else:
        try:
            return ORIGIN_REQUEST_POLICIES[origin_request_policy_name]
        except:
            raise KeyError(f"{origin_request_policy_name} is not a valid cache policy name. Valid names are {list(ORIGIN_REQUEST_POLICIES.keys())}")

def response_headers_policy_name_to_id(response_headers_policy_name):
    if not response_headers_policy_name:
        return None
    else:
        try:
            return RESPONSE_HEADERS_POLICIES[response_headers_policy_name]
        except:
            raise KeyError(f"{response_headers_policy_name} is not a valid cache policy name. Valid names are {list(RESPONSE_HEADERS_POLICIES.keys())}")

def fix_price_class(price_class):
    if price_class and price_class in ["All", "100", "200"]:
        return f"PriceClass_{price_class}"
    elif price_class:
        return price_class
    else:
        return "PriceClass_All"

RESPONSE_HEADERS_POLICIES = {
    "CORS-and-SecurityHeadersPolicy": "e61eb60c-9c35-4d20-a928-2b84e02af89c",
    "CORS-With-Preflight": "5cc3b908-e619-4b99-88e5-2cf7f45965bd",
    "CORS-with-preflight-and-SecurityHeadersPolicy": "eaab4381-ed33-4a86-88ca-d9558dc6cd63",
    "SecurityHeadersPolicy": "67f7725c-6f97-4210-82d7-5512b31e9d03",
    "SimpleCORS": "60669652-455b-4ae9-85a4-c4c02393f86c"
}  

CACHE_POLICIES = {
    "CachingOptimized": "658327ea-f89d-4fab-a63d-7e88639e58f6",
    "CachingOptimizedForUncompressedObjects": "b2884449-e4de-46a7-ac36-70bc7f1ddd6d",
    "CachingDisabled": "4135ea2d-6df8-44a3-9df3-4b5a84be39ad",
    "Elemental-MediaPackage": "08627262-05a9-4f76-9ded-b50ca2e3a84f",
    "Amplify": "2e54312d-136d-493c-8eb9-b001f22f67d2"
}

ORIGIN_REQUEST_POLICIES = {
    "AllViewer": "216adef6-5c7f-47e4-b989-5492eafa07d3",
    "AllViewerAndCloudFrontHeaders-2022-06": "33f36d7e-f396-46d9-90e0-52428a34d9dc",
    "AllViewerExceptHostHeader": "b689b0a8-53d0-40ab-baf2-68738e2966ac",
    "CORS-CustomOrigin": "59781a5b-3903-41f3-afcb-af62929ccde1",
    "CORS-S3Origin": "88a5eaf4-2fd4-4709-b370-b4c650ea3fcf",
    "Elemental-MediaTailor-PersonalizedManifests": "775133bc-15f2-49f9-abea-afb2e0bf67d2",
    "UserAgentRefererHeaders": "acba4595-bd28-49b8-b9fe-13317c0390fa"
}

CLOUDFRONT_ERRORS = [
    "CNAMEAlreadyExists", "InvalidOrigin", "InvalidOriginAccessIdentity",
    "AccessDenied", "InvalidViewerCertificate", "InvalidMinimumProtocolVersion",
    "TooManyDistributionCNAMEs", "TooManyDistributions", "InvalidDefaultRootObject",
    "InvalidRelativePath", "InvalidErrorCode", "InvalidResponseCode", "InvalidArgument",
    "NoSuchOrigin", "TooManyTrustedSigners", "InvalidRequiredProtocol", "InvalidProtocolSettings",
    "InvalidTTLOrder", "InvalidWebACLId", "TooManyOriginCustomHeaders", "TooManyQueryStringParameters",
    "InvalidQueryStringParameters", "InvalidHeadersForS3Origin", "InconsistentQuantities",
    "InvalidTagging", "TooManyDistributionsWithLambdaAssociations", "TooManyLambdaFunctionAssociations",
    "InvalidLambdaFunctionAssociation", "InvalidOriginReadTimeout", "InvalidOriginKeepaliveTimeout",
    "NoSuchFieldLevelEncryptionConfig", "TooManyFieldLevelEncryptionConfigs", "InvalidFieldLevelEncryptionId",
    "TooManyDistributionsAssociatedToFieldLevelEncryptionConfig", "FieldLevelEncryptionConfigInUseByDistribution",
    "FieldLevelEncryptionConfigAlreadyExists", "InvalidSigner",
    "NoSuchFieldLevelEncryptionProfile", "TooManyFieldLevelEncryptionProfiles", "FieldLevelEncryptionProfileInUse",
    "FieldLevelEncryptionProfileAlreadyExists", "InvalidFieldLevelEncryptionProfileConfig",
    "NoSuchCachePolicy", "TooManyCachePolicies",
    "NoSuchOriginRequestPolicy", "TooManyOriginRequestPolicies",
    "InvalidOriginRequestPolicyConfig", "TooManyOriginRequestPolicyConfigs", "OriginRequestPolicyInUse",
    "OriginRequestPolicyAlreadyExists", "NoSuchRealtimeLogConfig", "TooManyRealtimeLogConfigs",
    "InvalidRealtimeLogConfig", "RealtimeLogConfigInUse", "RealtimeLogConfigAlreadyExists",
    "NoSuchFieldLevelEncryptionEntity", "TooManyFieldLevelEncryptionEntities", "FieldLevelEncryptionEntityInUse",
    "FieldLevelEncryptionEntityAlreadyExists", "InvalidCloudFrontOriginAccessIdentity",
    "InvalidCloudFrontOriginAccessIdentityConfig", "InvalidIfMatchVersion",
    "NoSuchCloudFrontOriginAccessIdentity", "PreconditionFailed",
    "InvalidForwardCookies", "IllegalUpdate"
]
