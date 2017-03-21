############################################################
##           daddy88/shopify-serverless-aws-app
##      A generic serverless embedded Shopify web app      
##     utilizing the Shopify EASDK and OAuth. "Hosted"     
##   on AWS Lambda, Simple Storage Service and API Gateway.
############################################################

from __future__ import print_function
import boto3

import sys
import json
import hmac
import hashlib
import urlparse

print('Loading function')

bucket_name = 'S3_BUCKET_NAME'
file_name = 'app-ui.html'
app_key = 'APP_API_KEY'
app_secret = 'APP_SECRET_HASH'
app_url = 'THE_URL_OF_YOUR_API_GATEWAY_ENDPOINT_OF_THIS_FILE' # eg. https://d4w5a64d.execute-api.eu-east-1.amazonaws.com/stage
app_scope = 'read_products' # the API access scope of your app

def safe_list_get (l, idx, default):
    # checks a list, and returns the default param if idx is not defined
    try:
        return l[idx]
    except:
        return default

def get_s3(finame):
    #returns contents of a s3 file
    return boto3.resource('s3').Bucket(bucket_name).Object(finame).get()['Body'].read()

def hmac_signature(shop_secret, payload):
    # calculates the hmac signature of the payload param, salted with the shop_secret param
    return hmac.new(shop_secret, ''.join(['%s=%s&' % (key, value) for (key, value) in sorted(payload.items())])[:-1], hashlib.sha256).hexdigest()

def respond_html(statusCode, body):
    return {
                "statusCode": statusCode,
                "headers": { "Content-Type": "text/html" },
                "body": body
            }

def lambda_handler(event, context):
    sys.tracebacklimit = 0 # dont print details of exceptions

    uri_path_proxy = event['pathParameters']['proxy']
    uri_path_proxy = uri_path_proxy.split("/") #split the path of the request on / into a dict

    if event['requestContext']['httpMethod'] == 'GET': 
        #if its a GET request
        if uri_path_proxy[0] == 'initiate':
            install_url = 'http://'+safe_list_get(event['queryStringParameters'], 'shop', '')+'/admin/oauth/authorize?client_id='+app_key+'&scope='+app_scope+'&redirect_uri='+app_url+'/auth'
            return respond_html(200, '<script>window.top.location.href = "'+install_url+'";</script>') #redirect the user to Shopify for acceptence of the App's access scope

        elif uri_path_proxy[0] == 'auth': 
            # when the user accepts the app's scope, shopify redirects to /auth
            payload = event['queryStringParameters'].copy()
            del payload['hmac'] # remove the hmac signature from the payload before calculating the digest
            digest = hmac_signature(app_secret, payload) # calculate the digest

            if digest == event['queryStringParameters']['hmac']: 
                # if the digest equals the hmac recived from Shopify = valid request
                return respond_html(200, get_s3(file_name).replace('{{APIKEY}}', app_key).replace('{{SHOP}}', 'https://'+event['queryStringParameters']['shop']))
            else: 
                # the request has been spoofed
                return respond_html(500, 'Sorry your not authenticated.')

    return respond_html(500, 'Sorry something went wrong.') # a catch all response
